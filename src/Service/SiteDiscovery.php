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
     * Discovers all sites under /home that have a fail2ban.conf.
     *
     * @return SiteInfo[]
     */
    public function discover(): array
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
            } else {
                continue;
            }

            $shortName = $this->config->getShortName($domain);
            $logPath = '/var/log/nginx/' . $domain . '-access.log';
            $nginxSiteConf = rtrim($this->config->nginxSitesAvailable, '/') . '/' . $domain;

            $sites[] = new SiteInfo(
                domain: $domain,
                sitePath: $sitePath,
                shortName: $shortName,
                fail2banConf: $fail2banConf,
                logPath: $logPath,
                nginxSiteConf: $nginxSiteConf,
            );
        }

        return $sites;
    }
}
