<?php

namespace App\Config;

class FirewallConfig
{
    /** @var string[] */
    public readonly array $forbiddenPaths;

    /** @var string[] */
    public readonly array $ignoredIps;

    public readonly string $filterDir;
    public readonly string $jailDir;
    public readonly string $jailLocalPath;
    public readonly string $actionDir;
    public readonly string $nginxDenyFile;
    public readonly string $cloudflareRealipConf;
    public readonly string $nginxSitesAvailable;
    public readonly string $forgeConfPath;
    public readonly string $homePath;

    public function __construct(
        ?string $filterDir = null,
        ?string $jailDir = null,
        ?string $jailLocalPath = null,
        ?string $actionDir = null,
        ?string $nginxDenyFile = null,
        ?string $cloudflareRealipConf = null,
        ?string $nginxSitesAvailable = null,
        ?string $forgeConfPath = null,
        ?string $homePath = null,
    ) {
        $configPath = dirname(__DIR__, 2) . '/config.json';
        $config = json_decode(file_get_contents($configPath), true);

        $this->forbiddenPaths = $config['forbidden_paths'] ?? [];
        $this->ignoredIps = $config['ignored_ips'] ?? [];

        $this->filterDir = $filterDir ?? '/etc/fail2ban/filter.d/';
        $this->jailDir = $jailDir ?? '/etc/fail2ban/jail.d/';
        $this->jailLocalPath = $jailLocalPath ?? '/etc/fail2ban/jail.local';
        $this->actionDir = $actionDir ?? '/etc/fail2ban/action.d/';
        $this->nginxDenyFile = $nginxDenyFile ?? '/etc/nginx/conf.d/banned-ips.conf';
        $this->cloudflareRealipConf = $cloudflareRealipConf ?? '/etc/nginx/conf.d/cloudflare-realip.conf';
        $this->nginxSitesAvailable = $nginxSitesAvailable ?? '/etc/nginx/sites-available/';
        $this->forgeConfPath = $forgeConfPath ?? '/etc/nginx/forge-conf/';
        $this->homePath = $homePath ?? '/home';
    }

    /**
     * Returns the ignore IP list string for jail.local.
     */
    public function getIgnoreIpList(): string
    {
        $list = '127.0.0.1/8 ::1';
        foreach ($this->ignoredIps as $ip) {
            $list .= ' ' . $ip;
        }
        return $list;
    }

    /**
     * Returns the default failregex lines built from forbidden paths.
     */
    public function getDefaultFailRegex(): string
    {
        $lines = [];
        foreach ($this->forbiddenPaths as $path) {
            $lines[] = '      ^<HOST> .* "(GET|POST) ' . $path . '.*"';
        }
        return implode("\n", $lines);
    }

    /**
     * Returns a shortened name for a domain (max 18 chars).
     */
    public function getShortName(string $domain): string
    {
        return substr($domain, 0, 18);
    }
}
