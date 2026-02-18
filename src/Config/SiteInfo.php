<?php

namespace App\Config;

class SiteInfo
{
    public function __construct(
        public readonly string $domain,
        public readonly string $sitePath,
        public readonly string $shortName,
        public readonly ?string $fail2banConf,
        public readonly string $logPath,
        public readonly string $nginxSiteConf,
    ) {}
}
