#!/bin/bash

# ------ CONFIG ------
# Add URL paths you want to ban here (regex supported)

FORBIDDEN_PATHS=(
	"\/nyan.php"
	"\/super-secret-admin"
	"\/swagger"
)

IGNORED_IPS=(
	"27.33.91.54"
	"45.32.240.86"
)

FILTER_DIR="/etc/fail2ban/filter.d/"
JAIL_DIR="/etc/fail2ban/jail.d/"
JAIL_LOCAL_PATH="/etc/fail2ban/jail.local"
ACTION_DIR="/etc/fail2ban/action.d/"

# Path to the global nginx banned IPs file (shared across all sites)
NGINX_DENY_FILE="/etc/nginx/conf.d/banned-ips.conf"

# Path to the Cloudflare real IP config for nginx
CLOUDFLARE_REALIP_CONF="/etc/nginx/conf.d/cloudflare-realip.conf"

# -------------------------------------------------------
# SECTION 1: NGINX LAYER - Cloudflare Real IP + Deny File
# -------------------------------------------------------
# This section configures nginx to:
# - Extract real visitor IPs from Cloudflare's CF-Connecting-IP header
# - Only trust that header when the request comes from a known Cloudflare IP
# - Include a global deny file that fail2ban writes banned IPs into

echo "=== Setting up nginx ban layer ==="

# 1a. Create the Cloudflare real IP config
# This tells nginx to replace $remote_addr with the real client IP
# but ONLY when the request originates from a Cloudflare IP range.
# Without this, $remote_addr would be a Cloudflare IP and deny rules wouldn't match.
echo "Fetching current Cloudflare IP ranges..."

{
    echo "# Cloudflare real IP configuration"
    echo "# Auto-generated on $(date)"
    echo "# This file tells nginx to trust the CF-Connecting-IP header"
    echo "# ONLY from requests originating from Cloudflare's IP ranges."
    echo ""
    echo "# Cloudflare IPv4 ranges"
    for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
        echo "set_real_ip_from $ip;"
    done
    echo ""
    echo "# Cloudflare IPv6 ranges"
    for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
        echo "set_real_ip_from $ip;"
    done
    echo ""
    echo "# Use CF-Connecting-IP header to extract the real visitor IP"
    echo "real_ip_header CF-Connecting-IP;"
} > "$CLOUDFLARE_REALIP_CONF"

echo "  > Cloudflare real IP config written to $CLOUDFLARE_REALIP_CONF"

# 1b. Create the global banned IPs file if it doesn't exist
# fail2ban will append "deny <ip>;" lines to this file when banning
# and remove them when unbanning. All nginx server blocks include this file.
if [ ! -f "$NGINX_DENY_FILE" ]; then
    touch "$NGINX_DENY_FILE"
    chmod 644 "$NGINX_DENY_FILE"
    echo "  > Created empty banned IPs file at $NGINX_DENY_FILE"
else
    echo "  > Banned IPs file already exists at $NGINX_DENY_FILE"
fi

# -------------------------------------------------------
# SECTION 2: FAIL2BAN ACTION - nginx deny file writer
# -------------------------------------------------------
# This creates a custom fail2ban action that writes banned IPs
# to the nginx deny file instead of using iptables.
# iptables can't ban real IPs behind Cloudflare because the TCP
# connection comes from Cloudflare's IP, not the visitor's.

echo "=== Creating fail2ban nginx-deny-file action ==="

cat > "${ACTION_DIR}/nginx-deny-file.conf" <<'ACTIONEOF'
# Custom fail2ban action: writes deny rules to an nginx config file
# Used instead of iptables when sites are behind a Cloudflare proxy,
# because iptables only sees Cloudflare's IP, not the real visitor IP.

[Definition]

actionstart =

actionstop =

# Verify the deny file exists before attempting to write
actioncheck = test -f <deny_file>

# Ban: append a deny rule for the IP, then test and reload nginx
# The grep check prevents duplicate entries if fail2ban bans the same IP twice
actionban = if ! grep -q "deny <ip>;" <deny_file>; then
            echo "deny <ip>;" >> <deny_file> &&
            /usr/sbin/nginx -t > /dev/null 2>&1 &&
            /usr/sbin/nginx -s reload; fi

# Unban: remove the deny rule for the IP, then test and reload nginx
actionunban = sed -i "\|deny <ip>;|d" <deny_file> &&
              /usr/sbin/nginx -t > /dev/null 2>&1 &&
              /usr/sbin/nginx -s reload

[Init]

# Path to the nginx deny file (overridable per jail if needed)
deny_file = /etc/nginx/conf.d/banned-ips.conf
ACTIONEOF

echo "  > nginx-deny-file action written to ${ACTION_DIR}/nginx-deny-file.conf"

# -------------------------------------------------------
# SECTION 3: FAIL2BAN FILTERS + JAILS (per site)
# -------------------------------------------------------
# Loops through all sites on the server, looks for a fail2ban.conf
# in each site's repo, and creates a filter + jail for each one.
# Each jail now uses the nginx-deny-file action instead of iptables.

echo "=== Creating per-site fail2ban filters and jails ==="

# Build regex lines from FORBIDDEN_PATHS
DEFAULT_REGEX=""
for FORBIDDEN_PATH in "${FORBIDDEN_PATHS[@]}"; do
    DEFAULT_REGEX+=$'\n'"      ^<HOST> .* \"(GET|POST) ${FORBIDDEN_PATH}.*\""
done

# Build ignore IP list for jail.local
IP_LIST="127.0.0.1/8 ::1"
for ip in "${IGNORED_IPS[@]}"; do
    IP_LIST+=" $ip"
done

# Create a jail for each site found in /home/ groups
for GROUP_PATH in /home/*; do
	[ -d "$GROUP_PATH" ] || continue

	for SITE_PATH in "$GROUP_PATH"/*; do
	[ -d "$SITE_PATH" ] || continue

	# Set Domain name and site repo path to fail config
	DOMAIN=$(basename "$SITE_PATH")

	CONF_IN_CURRENT="$SITE_PATH/current/fail2ban.conf"
	CONF_IN_ROOT="$SITE_PATH/fail2ban.conf"
	REPO_CONFIG=""

	# Check if site has a fail2ban.conf in current/ or root
	if [ -f "$CONF_IN_CURRENT" ]; then
		echo "> Fail2ban conf found in current directory"
		REPO_CONFIG="$CONF_IN_CURRENT"
	elif [ -f "$CONF_IN_ROOT" ]; then
		echo "> Fail2ban conf found in site root."
		REPO_CONFIG="$CONF_IN_ROOT"
	else
		echo "> Skipping $DOMAIN (No fail2ban conf found in current or $SITE_PATH)"
		continue
	fi

	# Set include directive if there is a config within the repo
	INCLUDE_DIRECTIVE=""
	# If the domain name is too long, shorten it so it doesn't reach iptables Linux char limit
	SHORT_HASH=$(echo "$DOMAIN" | md5sum | cut -c1-6)
	SHORT_NAME="${DOMAIN:0:18}"

	if [ -f "$REPO_CONFIG" ]; then
		echo "  > Found repo config. Adding include link."
		# We use 'after' so the repo file can override the defaults below
		INCLUDE_DIRECTIVE="after = $REPO_CONFIG"
	else
		echo "  > No repo config. Using defaults only."
	fi

	echo "Creating filter file for site ${DOMAIN}"

	# Generate filter file (unchanged - defines what log patterns trigger a ban)
	FILTER_FILE="$FILTER_DIR/forge-$SHORT_NAME.conf"

	cat > "$FILTER_FILE" <<EOF
[INCLUDES]
$INCLUDE_DIRECTIVE

[Definition]
failregex = $DEFAULT_REGEX
ignoreregex =
EOF

	# Generate jail file
	JAIL_FILE="$JAIL_DIR/forge-$SHORT_NAME.conf"
	LOG_FILE="/var/log/nginx/${DOMAIN}-access.log"

	# If there is no log file, create it with standard Forge permissions
	if [ ! -f "$LOG_FILE" ]; then
        echo "  > Log file missing. Creating placeholder: $LOG_FILE"
        touch "$LOG_FILE"
        chmod 640 "$LOG_FILE"
        chown root:adm "$LOG_FILE" 2>/dev/null || chown root:root "$LOG_FILE"
    fi

	# Write the jail config
	# action = nginx-deny-file writes bans to the nginx deny file instead of iptables
	cat > "$JAIL_FILE" <<EOF
[INCLUDES]
$INCLUDE_DIRECTIVE

[forge-$SHORT_NAME]
enabled = true
port = http,https
filter = forge-$SHORT_NAME
logpath = $LOG_FILE
action = nginx-deny-file
maxretry = 3
findtime = 600
bantime = 86400
backend = auto
EOF

	# -------------------------------------------------------
	# SECTION 4: NGINX SITE CONFIG - Include banned IPs file
	# -------------------------------------------------------
	# Inject the banned-ips.conf include into the site's nginx config
	# so that nginx actually enforces the deny rules.
	# The include goes inside the server {} block.

	NGINX_SITE_CONF="/etc/nginx/sites-available/$DOMAIN"

	if [ -f "$NGINX_SITE_CONF" ]; then
		# Only add the include if it isn't already present
		if ! grep -q "include $NGINX_DENY_FILE;" "$NGINX_SITE_CONF"; then
			# Insert the include after the first 'server {' line
			sed -i "/server {/a\\    # fail2ban: block banned IPs at the nginx level\\n    include $NGINX_DENY_FILE;" "$NGINX_SITE_CONF"
			echo "  > Added banned-ips include to $NGINX_SITE_CONF"
		else
			echo "  > Banned-ips include already present in $NGINX_SITE_CONF"
		fi
	else
		echo "  > WARNING: nginx config not found at $NGINX_SITE_CONF - add include manually"
	fi

	done
done

# -------------------------------------------------------
# SECTION 5: GLOBAL FAIL2BAN CONFIG
# -------------------------------------------------------
# Write jail.local with the global whitelist and default ban action

echo "=== Updating global fail2ban config ==="

bash -c "cat > $JAIL_LOCAL_PATH" <<EOF
[DEFAULT]
ignoreip = $IP_LIST

# Use nginx deny file as the default ban action for all jails
# This writes banned IPs to an nginx config file instead of iptables,
# which is required when sites are behind a Cloudflare proxy
banaction = nginx-deny-file
EOF

echo "  > jail.local written with whitelist and nginx-deny-file as default action"

# -------------------------------------------------------
# SECTION 6: TEST AND RELOAD
# -------------------------------------------------------
# Validate nginx config before reloading to avoid downtime,
# then reload both nginx and fail2ban to apply all changes.

echo "=== Testing and reloading services ==="

# Test nginx config first - don't reload if it fails
if nginx -t > /dev/null 2>&1; then
    echo "  > nginx config test passed"
    nginx -s reload
    echo "  > nginx reloaded"
else
    echo "  > ERROR: nginx config test failed! Check with: nginx -t"
    echo "  > Skipping nginx reload - fix the config and reload manually"
fi

echo "Reloading fail2ban..."
fail2ban-client reload
echo "  > fail2ban reloaded"

echo ""
echo "=== Setup complete ==="
echo "  - Cloudflare real IP config: $CLOUDFLARE_REALIP_CONF"
echo "  - Banned IPs file: $NGINX_DENY_FILE"
echo "  - fail2ban action: ${ACTION_DIR}/nginx-deny-file.conf"
echo "  - Test a ban: fail2ban-client set forge-<site> banip 192.0.2.1"
echo "  - Check bans: cat $NGINX_DENY_FILE"
