# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A PHP CLI tool (`frmdv`) for managing fail2ban + nginx IP banning on Laravel Forge servers behind Cloudflare. It replaces iptables-based banning (which can't see real IPs behind Cloudflare) with nginx-level deny rules using the `CF-Connecting-IP` header via the realip module.

There is also a standalone bash script (`recipe.sh`) that does the same thing — it's designed to be pasted into a Laravel Forge recipe and run directly on servers. The PHP CLI is the primary tool for ongoing management.

## Commands

```bash
# Install dependencies
composer install

# Run the CLI
./frmdv <command>

# Available commands:
./frmdv firewall:init              # Full setup: cloudflare IPs, fail2ban action/filters/jails, nginx includes
./frmdv firewall:init --dry-run    # Preview what would be written without making changes
./frmdv firewall:ban <ip> [reason] # Manually ban an IP (writes to nginx deny file + reloads)
./frmdv firewall:unban <ip>        # Remove ban from nginx deny file and fail2ban
./frmdv firewall:ip-lookup <ip>    # Check if IP is banned in nginx deny file or any fail2ban jail
./frmdv firewall:status [site]     # Dashboard of all firewall components, or detailed status for one site
./frmdv firewall:update-cloudflare # Refresh Cloudflare IP ranges (for cron jobs)
./frmdv firewall:reload            # Reload fail2ban service
./frmdv firewall:reload-jail <jail|all> [--regenerate]  # Reload specific jail or all jails
./frmdv sites:list                 # List all discovered sites and their protection status
```

## Architecture

The CLI is a Symfony Console application. Entry point is `frmdv`.

**Config layer** (`src/Config/`):
- `FirewallConfig` — reads `config.json` (forbidden URL paths, ignored IPs) and holds all filesystem paths (fail2ban dirs, nginx deny file, etc.). All paths have sensible defaults for Forge servers.
- `SiteInfo` — value object representing a discovered site (domain, paths, short name, fail2ban config location).

**Service layer** (`src/Service/`):
- `Nginx` — manages the nginx deny file (ban/unban/lookup), Cloudflare realip config generation, and injecting `include banned-ips.conf` into site configs.
- `Fail2Ban` — generates and writes fail2ban action, filter, and jail configs. Handles service/jail reloads.
- `SiteDiscovery` — scans `/home/*/*` (Forge directory structure) for sites. `discoverAll()` returns all sites; `discoverProtected()` returns only those with a `fail2ban.conf` in their repo.

**Command layer** (`src/Command/`): Each command instantiates its own `FirewallConfig` and the services it needs. No dependency injection container.

## Key Domain Concepts

- **Sites live at** `/home/{group}/{domain}/` with optional `current/` subdirectory (zero-downtime deploys). Site discovery checks both `{site}/current/fail2ban.conf` and `{site}/fail2ban.conf`.
- **Domain short names** are truncated to 18 characters for jail/filter filenames (`forge-{shortName}.conf`), originally to avoid iptables chain name limits.
- **Global ban list**: one `banned-ips.conf` shared across all sites. A ban on any site blocks the IP everywhere.
- **nginx include injection** only targets the first `server {` block in each site config (usually the HTTP→HTTPS redirect on Forge).
- The `ban` command auto-rolls back if `nginx -t` fails after writing the deny line.
- The `unban` command removes from fail2ban first (to prevent re-banning), then from the nginx deny file.

## Config

`config.json` at the project root:
- `forbidden_paths` — URL path regexes that trigger fail2ban bans
- `ignored_ips` — IPs to whitelist in jail.local
