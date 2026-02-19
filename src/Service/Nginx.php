<?php

namespace App\Service;

use App\Config\FirewallConfig;
use App\Config\SiteInfo;

class Nginx
{
    public function __construct(
        private readonly FirewallConfig $config,
    ) {}

    /**
     * Fetches Cloudflare IP ranges and writes the realip config.
     * Returns the generated config content.
     */
    public function createCloudflareRealipConfig(): string
    {
        $ipv4 = trim(@file_get_contents('https://www.cloudflare.com/ips-v4') ?: '');
        $ipv6 = trim(@file_get_contents('https://www.cloudflare.com/ips-v6') ?: '');

        $lines = [];
        $lines[] = '# Cloudflare real IP configuration';
        $lines[] = '# Auto-generated on ' . date('Y-m-d H:i:s');
        $lines[] = '# This file tells nginx to trust the CF-Connecting-IP header';
        $lines[] = '# ONLY from requests originating from Cloudflare\'s IP ranges.';
        $lines[] = '';
        $lines[] = '# Cloudflare IPv4 ranges';
        foreach (array_filter(explode("\n", $ipv4)) as $ip) {
            $lines[] = 'set_real_ip_from ' . trim($ip) . ';';
        }
        $lines[] = '';
        $lines[] = '# Cloudflare IPv6 ranges';
        foreach (array_filter(explode("\n", $ipv6)) as $ip) {
            $lines[] = 'set_real_ip_from ' . trim($ip) . ';';
        }
        $lines[] = '';
        $lines[] = '# Use CF-Connecting-IP header to extract the real visitor IP';
        $lines[] = 'real_ip_header CF-Connecting-IP;';

        $content = implode("\n", $lines) . "\n";

        return $content;
    }

    /**
     * Writes the Cloudflare realip config to disk.
     */
    public function writeCloudflareRealipConfig(string $content): void
    {
        file_put_contents($this->config->cloudflareRealipConf, $content);
    }

    /**
     * Creates the banned-ips.conf file if it doesn't exist.
     * Returns true if created, false if already existed.
     */
    public function ensureBannedIpsFile(): bool
    {
        if (file_exists($this->config->nginxDenyFile)) {
            return false;
        }

        touch($this->config->nginxDenyFile);
        chmod($this->config->nginxDenyFile, 0644);
        return true;
    }

    /**
     * Injects the banned-ips.conf include into a site's nginx config.
     * Returns true if injected, false if already present or config not found.
     */
    public function injectBannedIpsInclude(SiteInfo $site): bool
    {
        if (!file_exists($site->nginxSiteConf)) {
            return false;
        }

        $content = file_get_contents($site->nginxSiteConf);
        $includeDirective = 'include ' . $this->config->nginxDenyFile . ';';

        if (str_contains($content, $includeDirective)) {
            return false;
        }

        $content = preg_replace(
            '/server\s*\{/',
            "server {\n    # fail2ban: block banned IPs at the nginx level\n    $includeDirective",
            $content,
            1,
        );

        file_put_contents($site->nginxSiteConf, $content);
        return true;
    }

    /**
     * Bans an IP by appending a deny line to the deny file.
     * Returns false if the IP is already banned.
     */
    public function banIp(string $ip, ?string $reason = null): bool
    {
        if ($this->isIpBanned($ip)) {
            return false;
        }

        $line = "deny $ip;";
        $comments = [];
        if ($reason !== null) {
            $comments[] = $reason;
        }
        $comments[] = 'manual-ban ' . date('Y-m-d H:i:s');
        $line .= ' # ' . implode(' | ', $comments);

        file_put_contents($this->config->nginxDenyFile, $line . "\n", FILE_APPEND);
        return true;
    }

    /**
     * Unbans an IP by removing its deny line from the deny file.
     * Returns false if the IP was not found.
     */
    public function unbanIp(string $ip): bool
    {
        if (!file_exists($this->config->nginxDenyFile)) {
            return false;
        }

        $content = file_get_contents($this->config->nginxDenyFile);
        $lines = explode("\n", $content);
        $filtered = [];
        $found = false;

        foreach ($lines as $line) {
            if (preg_match('/^deny\s+' . preg_quote($ip, '/') . '\s*;/', $line)) {
                $found = true;
                continue;
            }
            $filtered[] = $line;
        }

        if (!$found) {
            return false;
        }

        file_put_contents($this->config->nginxDenyFile, implode("\n", $filtered));
        return true;
    }

    /**
     * Checks if an IP is currently banned in the deny file.
     */
    public function isIpBanned(string $ip): bool
    {
        if (!file_exists($this->config->nginxDenyFile)) {
            return false;
        }

        $content = file_get_contents($this->config->nginxDenyFile);
        return (bool) preg_match('/^deny\s+' . preg_quote($ip, '/') . '\s*;/m', $content);
    }

    /**
     * Returns the full deny line for a banned IP, or null if not found.
     */
    public function getBanLine(string $ip): ?string
    {
        if (!file_exists($this->config->nginxDenyFile)) {
            return null;
        }

        $content = file_get_contents($this->config->nginxDenyFile);
        if (preg_match('/^(deny\s+' . preg_quote($ip, '/') . '\s*;.*)$/m', $content, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Tests the nginx configuration. Returns true if valid.
     */
    public function test(): bool
    {
        exec('nginx -t 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }

    /**
     * Reloads nginx. Returns true on success.
     */
    public function reload(): bool
    {
        exec('nginx -s reload 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }
}
