<?php

namespace App\Config;

class FirewallConfig
{
    /** @var string[] */
    public readonly array $forbiddenPaths;

    /** @var string[] */
    public readonly array $ignoredIps;

    public readonly string $forgeApiToken;
    public readonly string $forgeServerId;

    public readonly string $filterDir;
    public readonly string $jailDir;
    public readonly string $jailLocalPath;
    public readonly string $actionDir;
    public readonly string $nginxDenyFile;
    public readonly string $cloudflareRealipConf;
    public readonly string $nginxSitesAvailable;
    public readonly string $forgeConfPath;
    public readonly string $homePath;
    private readonly string $configPath;

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
        $baseDir = dirname(__DIR__, 2);
        $this->configPath = $baseDir . '/config.json';
        $this->loadEnvFile($baseDir . '/.env');
        $config = json_decode(file_get_contents($this->configPath), true);

        $this->forbiddenPaths = $config['forbidden_paths'] ?? [];
        $this->ignoredIps = $config['ignored_ips'] ?? [];
        $this->forgeApiToken = getenv('FORGE_API_TOKEN') ?: '';
        $this->forgeServerId = getenv('FORGE_SERVER_ID') ?: '';

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
     * Loads variables from a .env file into the environment (does not override existing values).
     */
    private function loadEnvFile(string $path): void
    {
        if (!file_exists($path)) {
            return;
        }

        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (str_starts_with(trim($line), '#')) {
                continue;
            }
            if (str_contains($line, '=')) {
                [$key, $value] = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                if (getenv($key) === false) {
                    putenv("{$key}={$value}");
                }
            }
        }
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
        return rtrim(substr($domain, 0, 18), '.');
    }

    /**
     * Replaces the ignored_ips array in config.json and writes it back.
     *
     * @param string[] $ips
     */
    public function saveIgnoredIps(array $ips): void
    {
        $config = json_decode(file_get_contents($this->configPath), true);
        $config['ignored_ips'] = array_values($ips);
        file_put_contents($this->configPath, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    }
}
