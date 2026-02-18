# Project Context

This document contains environment-specific details and operational knowledge for working on this fail2ban + nginx recipe.

## Environment

- These are **Laravel Forge** managed servers
- nginx site configs are at the standard Forge path: `/etc/nginx/sites-available/{domain}`
- Site directories follow the Forge structure: `/home/{group}/{domain}/`
- Each site may have a `current/` directory (zero-downtime deployments) or just the site root

## Recipe Behaviour

### Per-repo fail2ban overrides

Each site can include its own `fail2ban.conf` in the repo to override the default filter rules. The recipe checks two locations in order:

1. `{site_path}/current/fail2ban.conf` (zero-downtime deploy structure)
2. `{site_path}/fail2ban.conf` (standard site root)

If found, it's included via `after = {path}` in the filter file, meaning repo-level regex rules are appended after the defaults. Sites without a `fail2ban.conf` are skipped entirely.

### SHORT_NAME truncation

Domain names are truncated to the first 18 characters for use in jail/filter filenames (e.g. `forge-myreallylongdoma.conf`). This was originally done to avoid hitting the iptables chain name character limit. It's still used for consistency in filenames even though we now use the nginx deny action instead of iptables.

An md5 hash (`SHORT_HASH`) of the domain is also generated but currently unused — it exists as a fallback if name collisions from truncation become a problem.

### nginx include injection

The recipe uses `sed` to inject the `include banned-ips.conf;` line after the first `server {` line in each site's nginx config. This means on Forge configs with multiple server blocks (e.g. HTTP redirect + HTTPS), the include is only added to the **first** server block. In practice this is usually the HTTP->HTTPS redirect block on Forge.

If a site needs the include in additional server blocks, it must be added manually.

The recipe checks with `grep` before injecting, so it is safe to re-run without creating duplicates.

## Banned IPs File Format

When populated by fail2ban, `/etc/nginx/conf.d/banned-ips.conf` looks like:

```
deny 203.0.113.45;
deny 198.51.100.23;
deny 192.0.2.67;
```

Each line is a standard nginx `deny` directive. nginx evaluates these against `$remote_addr` (which is the real client IP after the realip module processes it).

## Known Gotchas

### Duplicate `real_ip_header` directive

If a `cloudflare.conf` or similar file already exists with a `real_ip_header` line, nginx will fail with:

```
[emerg] "real_ip_header" directive is duplicate in /etc/nginx/conf.d/cloudflare.conf:23
nginx: configuration file /etc/nginx/nginx.conf test failed
```

**Fix:** Remove `real_ip_header` from the other file. It can only appear once in the `http {}` context. Find all instances with:

```bash
grep -r "real_ip_header" /etc/nginx/
```

### fail2ban action edge case on ban

In the `actionban` command, the `echo "deny <ip>;" >> deny_file` runs **before** `nginx -t`. If `nginx -t` fails for an unrelated reason (broken config elsewhere), the deny line is written to the file but nginx is not reloaded. The ban won't take effect until the config issue is fixed and nginx is reloaded. The line will still be in the file, so it will apply on the next successful reload.

### fail2ban action edge case on unban

The `sed` removal in `actionunban` runs before `nginx -t`. If nginx reload fails, the line is already removed from the file. The IP is effectively unbanned from the file but nginx is still serving the old config with the ban active until the next successful reload.

### Non-root fail2ban permissions

If fail2ban runs as a non-root user, it needs:

1. **Write access to the deny file:**

```bash
chown root:fail2ban /etc/nginx/conf.d/banned-ips.conf
chmod 664 /etc/nginx/conf.d/banned-ips.conf
```

2. **Sudo access for nginx commands:**

```bash
echo "fail2ban ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -s reload" > /etc/sudoers.d/fail2ban
chmod 440 /etc/sudoers.d/fail2ban
```

Then update the action file to prefix nginx commands with `sudo`.

Check what user fail2ban runs as with:

```bash
ps aux | grep fail2ban
```

On most Forge servers it runs as root, so this isn't needed.

## Verifying the Full Flow

After deployment, test end-to-end:

```bash
# 1. Check real IPs are in logs (not Cloudflare IPs)
tail -5 /var/log/nginx/access.log

# 2. Check fail2ban jails are running
fail2ban-client status

# 3. Manually ban a test IP
fail2ban-client set forge-<site> banip 192.0.2.1

# 4. Confirm it was written to the deny file
cat /etc/nginx/conf.d/banned-ips.conf
# Expected: deny 192.0.2.1;

# 5. Confirm nginx reloaded
journalctl -u nginx | tail -5

# 6. Test that the IP is actually blocked (from another machine or using curl)
curl -H "CF-Connecting-IP: 192.0.2.1" http://your-server/
# Expected: 403 Forbidden

# 7. Unban and confirm removal
fail2ban-client set forge-<site> unbanip 192.0.2.1
cat /etc/nginx/conf.d/banned-ips.conf
# Expected: line removed
```

## Forge Recipe Location

The recipe script is at `recipe.sh` in this directory. It is intended to be pasted into a Laravel Forge recipe and run on the server. See `SETUP_GUIDE.md` for the full walkthrough of what it does.
