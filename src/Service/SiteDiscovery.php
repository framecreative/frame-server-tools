<?php

namespace App\Service;

use App\Config\FirewallConfig;
use App\Config\SiteInfo;
use Symfony\Component\Finder\Finder;

class SiteDiscovery
{
    public function __construct(
        private readonly FirewallConfig $config,
    ) {}

    /**
     * Discovers all sites under /home, regardless of fail2ban.conf presence.
     *
     * @return SiteInfo[]
     */
    public function discoverAll(): array
    {
        $sites = [];

        $finder = new Finder();
        $finder->directories()->in($this->config->homePath)->depth('== 1');

        foreach ($finder as $siteDir) {
            $sitePath = $siteDir->getRealPath();
            $domain = $siteDir->getFilename();

            $confInCurrent = $sitePath . '/current/fail2ban.conf';
            $confInRoot = $sitePath . '/fail2ban.conf';
            $fail2banConf = null;

            if (file_exists($confInCurrent)) {
                $fail2banConf = $confInCurrent;
            } elseif (file_exists($confInRoot)) {
                $fail2banConf = $confInRoot;
            }

            $shortName = $this->config->getShortName($domain);
            $logPath = '/var/log/nginx/' . $domain . '-access.log';
            $nginxSiteConf = rtrim($this->config->nginxSitesAvailable, '/') . '/' . $domain;

            $forgeSiteConf = $this->findForgeSiteConf($domain);

            $sites[] = new SiteInfo(
                domain: $domain,
                sitePath: $sitePath,
                shortName: $shortName,
                fail2banConf: $fail2banConf,
                logPath: $logPath,
                nginxSiteConf: $nginxSiteConf,
                forgeSiteConf: $forgeSiteConf,
            );
        }

        return $sites;
    }

    /**
     * Discovers only sites under /home that have a fail2ban.conf.
     *
     * @return SiteInfo[]
     */
    public function discoverProtected(): array
    {
        return array_values(array_filter($this->discoverAll(), fn(SiteInfo $site) => $site->fail2banConf !== null));
    }

    /**
     * Finds the Forge site.conf for a domain by scanning forge-conf site ID directories.
     */
    private function findForgeSiteConf(string $domain): ?string
    {
        $forgeConfPath = rtrim($this->config->forgeConfPath, '/');

        if (!is_dir($forgeConfPath)) {
            return null;
        }

        $siteIdDirs = @scandir($forgeConfPath);
        if ($siteIdDirs === false) {
            return null;
        }

        foreach ($siteIdDirs as $siteId) {
            if ($siteId === '.' || $siteId === '..') {
                continue;
            }

            $domainSubdir = $forgeConfPath . '/' . $siteId . '/' . $domain;
            if (is_dir($domainSubdir)) {
                $siteConf = $forgeConfPath . '/' . $siteId . '/site.conf';
                if (file_exists($siteConf)) {
                    return $siteConf;
                }
            }
        }

        return null;
    }
}
