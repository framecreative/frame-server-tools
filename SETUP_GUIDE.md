# fail2ban + nginx IP Banning Behind Cloudflare

## The Problem

When using Cloudflare as a reverse proxy, nginx sees Cloudflare's IP addresses instead of real visitor IPs. This means:

- **iptables bans are useless** - they ban Cloudflare's IP, not the attacker's
- **Banning a Cloudflare IP blocks ALL traffic** through that edge server
- Attackers continue to access the site because their real IP is never banned

## The Solution

Ban at the **nginx level** instead of iptables, using three components:

1. **nginx realip module** - Extracts the real visitor IP from the `CF-Connecting-IP` header
2. **Custom fail2ban action** - Writes banned IPs to an nginx deny file instead of iptables
3. **nginx include** - Each site's server block includes the deny file to enforce bans

### How the request flow works

```
Client (203.0.113.45)
  -> Cloudflare (adds CF-Connecting-IP: 203.0.113.45)
    -> nginx receives connection from 104.16.0.1
      -> realip module checks: is 104.16.0.1 in set_real_ip_from list?
        -> YES: replaces $remote_addr with CF-Connecting-IP value
          -> $remote_addr is now 203.0.113.45 everywhere (logs, deny rules, rate limits)
```

---

## Setup Steps

### Part 1: Configure nginx to See Real IPs

#### Step 1: Verify the realip module is available

```bash
nginx -V 2>&1 | grep -o 'http_realip_module'
```

Most distro packages include it by default. If missing, recompile nginx with `--with-http_realip_module`.

#### Step 2: Create the Cloudflare real IP config

Create `/etc/nginx/conf.d/cloudflare-realip.conf` containing `set_real_ip_from` directives for all Cloudflare IP ranges, plus `real_ip_header CF-Connecting-IP;`.

The `set_real_ip_from` directives tell nginx to **only trust the header when the request comes from a Cloudflare IP**. This prevents IP spoofing (see [Why Cloudflare IPs Are Required](#why-cloudflare-ips-are-required)).

The recipe fetches these ranges live from Cloudflare's published lists:
- https://www.cloudflare.com/ips-v4
- https://www.cloudflare.com/ips-v6

#### Step 3: Check for duplicate `real_ip_header` directives

If you already have a `cloudflare.conf` or similar file with `real_ip_header`, remove it from that file. The directive can only appear once in the `http {}` context. Duplicate entries cause nginx to fail with:

```
[emerg] "real_ip_header" directive is duplicate
```

#### Step 4: Test and reload nginx

```bash
nginx -t
systemctl reload nginx
```

#### Step 5: Verify real IPs appear in logs

```bash
tail -f /var/log/nginx/access.log
```

You should see real visitor IPs, not Cloudflare IPs like `104.16.x.x` or `162.158.x.x`.

---

### Part 2: Create the fail2ban nginx Deny Action

#### Step 1: Create the empty banned IPs file

```bash
touch /etc/nginx/conf.d/banned-ips.conf
chmod 644 /etc/nginx/conf.d/banned-ips.conf
```

#### Step 2: Include the banned IPs file in nginx server blocks

Add inside each `server {}` block, near the top:

```nginx
include /etc/nginx/conf.d/banned-ips.conf;
```

#### Step 3: Create the custom fail2ban action

Create `/etc/fail2ban/action.d/nginx-deny-file.conf`:

- **actionban**: Checks for duplicates with `grep`, appends `deny <ip>;` to the file, runs `nginx -t` to validate, then `nginx -s reload`
- **actionunban**: Removes the line with `sed`, validates, and reloads

#### Step 4: Update jail configs to use the new action

Add `action = nginx-deny-file` to each jail, or set it globally in `jail.local`:

```ini
[DEFAULT]
banaction = nginx-deny-file
```

#### Step 5: Check permissions

If fail2ban runs as a non-root user, it needs:
- Write access to `/etc/nginx/conf.d/banned-ips.conf`
- Sudo access for `nginx -t` and `nginx -s reload`

#### Step 6: Test and restart fail2ban

```bash
fail2ban-client -t
systemctl restart fail2ban
```

#### Step 7: Test a manual ban/unban

```bash
# Ban a test IP
fail2ban-client set <jail-name> banip 192.0.2.1

# Verify it was written
cat /etc/nginx/conf.d/banned-ips.conf
# Expected: deny 192.0.2.1;

# Unban
fail2ban-client set <jail-name> unbanip 192.0.2.1

# Verify removal
cat /etc/nginx/conf.d/banned-ips.conf
# Expected: (empty)
```

---

## The Forge Recipe

The `recipe.sh` script automates the entire setup. It is divided into 6 sections:

| Section | What it does |
|---------|-------------|
| 1 | Fetches Cloudflare IP ranges and writes the realip config. Creates the empty banned-ips.conf file. |
| 2 | Creates the `nginx-deny-file` fail2ban action that writes deny rules to the nginx file instead of iptables. |
| 3 | Loops through all sites in `/home/*/*`, creates per-site fail2ban filters and jails with `action = nginx-deny-file`. |
| 4 | Injects the `include banned-ips.conf;` line into each site's nginx config at `/etc/nginx/sites-available/{domain}`. Skips if already present. |
| 5 | Writes `jail.local` with the IP whitelist and `nginx-deny-file` as the global default ban action. |
| 6 | Tests nginx config before reloading (prevents downtime on bad config), then reloads both nginx and fail2ban. |

The recipe is safe to re-run. It checks for existing includes before injecting and checks for existing files before creating.

---

## Key Decisions & Recommendations

### Why Cloudflare IPs are required

The `CF-Connecting-IP` header is just a regular HTTP header. **Anyone can send it with any value.** If nginx blindly trusts it, an attacker connecting directly to your server can:

- **Evade bans** by sending a fake IP in the header
- **Frame other IPs** by spoofing a legitimate IP and triggering fail2ban on purpose
- **Be completely invisible** in your logs

The `set_real_ip_from` directives ensure nginx only trusts the header when the request actually came from a Cloudflare IP range. Direct connections have their header ignored and `$remote_addr` stays as the real TCP source.

### Why iptables doesn't work behind Cloudflare

iptables operates at the network/TCP level. The TCP connection to your server comes from Cloudflare, not the visitor. The realip module only changes `$remote_addr` inside nginx — it doesn't change the actual network-layer source IP. So iptables always sees Cloudflare's IP and can never match the real visitor.

### Global ban list vs per-site

We chose a **global ban list** (one `banned-ips.conf` for all sites). A ban triggered on one site blocks the IP across all sites. This is simpler and provides stronger protection. Per-site lists are possible but add complexity.

### Sites not behind Cloudflare

The realip config applies globally (it's in `/etc/nginx/conf.d/`), but this is safe for non-proxied sites. The module only rewrites `$remote_addr` when the request comes from an IP in the `set_real_ip_from` list. Direct visitors don't come from Cloudflare IPs, so the directive has no effect on them.

The `include banned-ips.conf;` works the same way for both proxied and non-proxied sites. By the time nginx evaluates the `deny` rules, `$remote_addr` is the real client IP either way:
- **Proxied sites**: realip module rewrites it from the header
- **Direct sites**: it was already the real IP

For servers with a mix of both, you can also use different ban actions per jail:

```ini
# For sites behind Cloudflare
[cloudflare-site]
action = nginx-deny-file

# For sites with direct traffic
[direct-site]
action = iptables-multiport[name=nginx, port="http,https", protocol=tcp]
```

However, using `nginx-deny-file` for everything works fine. The only advantage of iptables for direct sites is that it blocks at the kernel level before nginx processes the request.

### nginx reload performance

`nginx -s reload` is a graceful operation:
- New worker processes start with the updated config
- Old workers finish serving existing connections, then exit
- No connections are dropped (zero downtime)
- Reload takes <100ms even with thousands of deny rules

### Checking if a site is behind Cloudflare

```bash
# Check DNS - Cloudflare IPs mean it's proxied
dig +short example.com

# Check response headers
curl -sI https://example.com | grep -i "cf-ray\|server: cloudflare"

# Check multiple domains at once
for domain in example.com site2.com site3.com; do
    if curl -sI "https://$domain" | grep -qi "cf-ray"; then
        echo "$domain -> proxied"
    else
        echo "$domain -> direct"
    fi
done
```

Or check the Cloudflare dashboard: orange cloud = proxied, grey cloud = DNS only.

---

## Keeping Cloudflare IPs Up to Date

Cloudflare occasionally adds new IP ranges. If your list is outdated, traffic from new Cloudflare edge servers won't have the real IP extracted.

Create a cron job to update automatically. The recipe fetches live IPs each time it runs, but for ongoing maintenance, schedule a weekly update:

```bash
# /usr/local/bin/update-cloudflare-ips.sh
# Fetches latest Cloudflare IPs, updates nginx config, reloads if changed
# See recipe.sh Section 1 for the generation logic

# Crontab (Sundays at 3 AM):
0 3 * * 0 /usr/local/bin/update-cloudflare-ips.sh >> /var/log/cloudflare-ip-update.log 2>&1
```

---

## Troubleshooting

### nginx fails with "real_ip_header directive is duplicate"

```
[emerg] "real_ip_header" directive is duplicate in /etc/nginx/conf.d/cloudflare.conf:23
```

The `real_ip_header` directive can only appear once in the `http {}` context. Find all instances and remove the duplicate:

```bash
grep -r "real_ip_header" /etc/nginx/
```

Keep it in `cloudflare-realip.conf` and remove it from any other file (e.g. an existing `cloudflare.conf`).

### Logs still show Cloudflare IPs after enabling realip

- Verify `cloudflare-realip.conf` is being loaded. It must be included inside the `http {}` block. Check that `nginx.conf` has `include /etc/nginx/conf.d/*.conf;`
- Verify the Cloudflare IP ranges are up to date — a new range not in your list means those requests won't have the real IP extracted
- Verify you reloaded nginx after adding the config: `systemctl reload nginx`

### fail2ban is running but IPs aren't appearing in banned-ips.conf

- Check the jail is using the correct action: `fail2ban-client get <jail> action`
- Check fail2ban can write to the file: `ls -la /etc/nginx/conf.d/banned-ips.conf`
- Check the filter is matching log entries: `fail2ban-regex /var/log/nginx/<domain>-access.log /etc/fail2ban/filter.d/forge-<site>.conf`
- Check fail2ban logs for errors: `tail -50 /var/log/fail2ban.log`

### IPs are in banned-ips.conf but attacker isn't blocked

- Verify the `include /etc/nginx/conf.d/banned-ips.conf;` line is inside the correct `server {}` block — the recipe injects it after the first `server {` which may be the HTTP redirect block, not the HTTPS block
- Check nginx actually reloaded after the ban: `journalctl -u nginx | tail`
- Test manually: `curl -I http://your-server/` from the banned IP — should return 403

### nginx -t fails after a ban is written

The deny line is already in the file but nginx hasn't reloaded. Fix whatever caused the config test to fail, then reload:

```bash
nginx -t    # identify the error
# fix the issue
nginx -s reload   # now the pending ban takes effect too
```

### Attacker bypasses ban by connecting directly (not through Cloudflare)

Your server is accepting direct connections. Lock down your firewall to only allow HTTP/HTTPS from Cloudflare IPs:

```bash
# Check if direct access is possible
curl -sI http://your-server-ip/

# If it responds, configure your firewall (ufw example)
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    ufw allow from $ip to any port 80,443 proto tcp
done
ufw default deny incoming
ufw allow 22/tcp   # keep SSH access
ufw enable
```

---

## Useful Commands

```bash
# Check fail2ban status across all jails
fail2ban-client status

# Check a specific jail
fail2ban-client status forge-<site>

# View all currently banned IPs
cat /etc/nginx/conf.d/banned-ips.conf

# Manually ban an IP
fail2ban-client set forge-<site> banip <ip>

# Manually unban an IP
fail2ban-client set forge-<site> unbanip <ip>

# Test fail2ban filter against a log file
fail2ban-regex /var/log/nginx/example.com-access.log /etc/fail2ban/filter.d/forge-<site>.conf

# Test nginx config without reloading
nginx -t

# Check nginx reload history
journalctl -u nginx | grep reload

# Watch fail2ban activity
tail -f /var/log/fail2ban.log
```

---

## File Locations

| File | Purpose |
|------|---------|
| `/etc/nginx/conf.d/cloudflare-realip.conf` | Cloudflare IP ranges + realip header config |
| `/etc/nginx/conf.d/banned-ips.conf` | Global deny list (managed by fail2ban) |
| `/etc/fail2ban/action.d/nginx-deny-file.conf` | Custom action that writes to the nginx deny file |
| `/etc/fail2ban/jail.local` | Global fail2ban config (whitelist + default action) |
| `/etc/fail2ban/jail.d/forge-*.conf` | Per-site jail configs |
| `/etc/fail2ban/filter.d/forge-*.conf` | Per-site filter configs |
| `/etc/nginx/sites-available/{domain}` | Forge nginx site configs (include injected here) |
