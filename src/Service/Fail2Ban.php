<?php

namespace App\Service;

use App\Config\FirewallConfig;
use App\Config\SiteInfo;

class Fail2Ban
{
    public function __construct(
        private readonly FirewallConfig $config,
    ) {}

    /**
     * Generates the nginx-deny-file action config content.
     */
    public function getActionContent(): string
    {
        $denyFile = $this->config->nginxDenyFile;

        return <<<CONF
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
deny_file = {$denyFile}
CONF;
    }

    /**
     * Writes the nginx-deny-file action to disk.
     */
    public function createAction(): void
    {
        $path = rtrim($this->config->actionDir, '/') . '/nginx-deny-file.conf';
        file_put_contents($path, $this->getActionContent() . "\n");
    }

    /**
     * Generates the filter config content for a site.
     */
    public function getFilterContent(SiteInfo $site): string
    {
        $includeDirective = '';
        if ($site->fail2banConf) {
            $includeDirective = 'after = ' . $site->fail2banConf;
        }

        $failRegex = $this->config->getDefaultFailRegex();

        return <<<CONF
[INCLUDES]
{$includeDirective}

[Definition]
failregex = {$failRegex}
ignoreregex =
CONF;
    }

    /**
     * Writes a per-site filter file.
     */
    public function createFilter(SiteInfo $site): void
    {
        $path = rtrim($this->config->filterDir, '/') . '/forge-' . $site->shortName . '.conf';
        file_put_contents($path, $this->getFilterContent($site) . "\n");
    }

    /**
     * Generates the jail config content for a site.
     */
    public function getJailContent(SiteInfo $site): string
    {
        $includeDirective = '';
        if ($site->fail2banConf) {
            $includeDirective = 'after = ' . $site->fail2banConf;
        }

        $jailName = 'forge-' . $site->shortName;

        return <<<CONF
[INCLUDES]
{$includeDirective}

[{$jailName}]
enabled = true
port = http,https
filter = {$jailName}
logpath = {$site->logPath}
action = nginx-deny-file
maxretry = 3
findtime = 600
bantime = 86400
backend = auto
CONF;
    }

    /**
     * Writes a per-site jail file and ensures the log file exists.
     */
    public function createJail(SiteInfo $site): void
    {
        $path = rtrim($this->config->jailDir, '/') . '/forge-' . $site->shortName . '.conf';
        file_put_contents($path, $this->getJailContent($site) . "\n");

        // Ensure the log file exists
        if (!file_exists($site->logPath)) {
            touch($site->logPath);
            chmod($site->logPath, 0640);
        }
    }

    /**
     * Generates the global jail.local content.
     */
    public function getJailLocalContent(): string
    {
        $ignoreIpList = $this->config->getIgnoreIpList();

        return <<<CONF
[DEFAULT]
ignoreip = {$ignoreIpList}

# Use nginx deny file as the default ban action for all jails
# This writes banned IPs to an nginx config file instead of iptables,
# which is required when sites are behind a Cloudflare proxy
banaction = nginx-deny-file
CONF;
    }

    /**
     * Writes the global jail.local file.
     */
    public function writeJailLocal(): void
    {
        file_put_contents($this->config->jailLocalPath, $this->getJailLocalContent() . "\n");
    }

    /**
     * Returns true if fail2ban is running and accessible.
     */
    public function isRunning(): bool
    {
        exec('fail2ban-client status 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }

    /**
     * Returns the list of active jail names.
     */
    public function getJails(): array
    {
        exec('fail2ban-client status 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return [];
        }

        foreach ($output as $line) {
            if (preg_match('/Jail list:\s*(.+)/', $line, $matches)) {
                return array_map('trim', explode(',', $matches[1]));
            }
        }

        return [];
    }

    /**
     * Returns true if a specific jail is active.
     */
    public function isJailActive(string $jail): bool
    {
        exec('fail2ban-client status ' . escapeshellarg($jail) . ' 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }

    /**
     * Returns the list of banned IPs in a jail.
     */
    public function getJailBannedIps(string $jail): array
    {
        exec('fail2ban-client status ' . escapeshellarg($jail) . ' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return [];
        }

        foreach ($output as $line) {
            if (preg_match('/Banned IP list:\s*(.+)/', $line, $matches)) {
                return array_filter(array_map('trim', explode(' ', $matches[1])));
            }
        }

        return [];
    }

    /**
     * Returns the number of currently banned IPs in a jail.
     */
    public function getJailBannedCount(string $jail): int
    {
        exec('fail2ban-client status ' . escapeshellarg($jail) . ' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return 0;
        }

        foreach ($output as $line) {
            if (preg_match('/Currently banned:\s*(\d+)/', $line, $matches)) {
                return (int) $matches[1];
            }
        }

        return 0;
    }

    /**
     * Returns true if an IP is banned in a specific jail.
     */
    public function isIpInJail(string $ip, string $jail): bool
    {
        return in_array($ip, $this->getJailBannedIps($jail), true);
    }

    /**
     * Returns the ignored (whitelisted) IPs for a jail as a comma-separated string.
     */
    public function getJailIgnoredIps(string $jail): string
    {
        exec('fail2ban-client get ' . escapeshellarg($jail) . ' ignoreip 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return '(error querying jail)';
        }

        $ips = [];
        foreach ($output as $line) {
            $line = trim($line);
            if (preg_match('/^[|\\\\]-\s+(.+)/', $line, $matches)) {
                $ips[] = $matches[1];
            }
        }

        return implode(', ', $ips);
    }

    /**
     * Unbans an IP from all fail2ban jails. Returns true on success.
     */
    public function unbanIp(string $ip): bool
    {
        exec('fail2ban-client unban ' . escapeshellarg($ip) . ' 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }

    /**
     * Bans an IP in a specific jail. Returns true on success.
     */
    public function banIp(string $ip, string $jailName): bool
    {
        exec('fail2ban-client set ' . escapeshellarg($jailName) . ' banip ' . escapeshellarg($ip) . ' 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }

    /**
     * Reloads the fail2ban service. Returns true on success.
     */
    public function reload(): bool
    {
        exec('fail2ban-client reload 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }

    /**
     * Reloads a specific fail2ban jail. Returns true on success.
     */
    public function reloadJail(string $jailName): bool
    {
        exec('fail2ban-client reload ' . escapeshellarg($jailName) . ' 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }
}
