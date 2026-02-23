<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Config\SiteInfo;
use App\Service\Fail2Ban;
use App\Service\Nginx;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Finder\Finder;

#[AsCommand(
    name: 'firewall:status',
    description: 'Shows firewall component status and active bans',
    help: <<<'HELP'
    Without arguments, displays a dashboard of all firewall components: Cloudflare
    realip config, banned IPs, fail2ban service status, and per-jail ban counts.

    When a site is specified (by domain, shortName, or jail name), shows detailed
    status for that site including its nginx config, access log, fail2ban jail,
    and all currently banned IPs.
    HELP,
    usages: [
        'firewall:status',
        'firewall:status example.com',
        'firewall:status myshortname',
    ],
)]
class StatusCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('site', InputArgument::OPTIONAL, 'Show detailed status for a specific site (domain, shortName, or jail name)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $siteName = $input->getArgument('site');

        if ($siteName !== null) {
            return $this->executeSiteStatus($config, $siteName);
        }

        $this->io->title('Firewall Status Dashboard');

        $fail2ban = new Fail2Ban($config);
        $nginx = new Nginx($config);

        $this->showCloudflareStatus($config);
        $this->showBannedIps($nginx, $config);
        $this->showFail2banService($fail2ban);
        $this->showJailStatus($fail2ban, $config);

        return Command::SUCCESS;
    }

    private function showCloudflareStatus(FirewallConfig $config): void
    {
        $this->io->section('Cloudflare Real IP Config');
        if (file_exists($config->cloudflareRealipConf)) {
            $content = file_get_contents($config->cloudflareRealipConf);
            $ipCount = substr_count($content, 'set_real_ip_from');
            $this->io->text("  Config: {$config->cloudflareRealipConf} (exists, {$ipCount} IP ranges)");
        } else {
            $this->io->warning("Config not found: {$config->cloudflareRealipConf}");
        }
    }

    private function showBannedIps(Nginx $nginx, FirewallConfig $config): void
    {
        $this->io->section('Banned IPs');
        if (!file_exists($config->nginxDenyFile)) {
            $this->io->warning("Banned IPs file not found: {$config->nginxDenyFile}");
            return;
        }

        $bans = $nginx->getAllBans();
        $banCount = count($bans);
        $this->io->text("  File: {$config->nginxDenyFile} (exists, {$banCount} active bans)");

        foreach ($bans as $ip => $comment) {
            $line = "deny {$ip};";
            if ($comment !== '') {
                $line .= " # {$comment}";
            }
            $this->io->text("    {$line}");
        }
    }

    private function showFail2banService(Fail2Ban $fail2ban): void
    {
        $this->io->section('fail2ban Service');
        if ($fail2ban->isRunning()) {
            $this->io->text('  Status: running');
            $jails = $fail2ban->getJails();
            $this->io->text('  Number of jail: ' . count($jails));
            if (!empty($jails)) {
                $this->io->text('  Jail list: ' . implode(', ', $jails));
            }
        } else {
            $this->io->error('fail2ban is not running or not accessible');
        }
    }

    private function showJailStatus(Fail2Ban $fail2ban, FirewallConfig $config): void
    {
        $this->io->section('Jail Status');

        if (!is_dir($config->jailDir)) {
            $this->io->text('  No jail directory found');
            return;
        }

        $finder = new Finder();
        $finder->files()->in($config->jailDir)->name('forge-*.conf');

        foreach ($finder as $file) {
            $jailName = $file->getFilenameWithoutExtension();
            if ($fail2ban->isJailActive($jailName)) {
                $bannedCount = $fail2ban->getJailBannedCount($jailName);
                $this->io->text("  {$jailName}: enabled, {$bannedCount} currently banned");
            } else {
                $this->io->text("  {$jailName}: not active");
            }
        }
    }

    private function executeSiteStatus(FirewallConfig $config, string $siteName): int
    {
        $discovery = new SiteDiscovery($config);
        $sites = $discovery->discoverAll();
        $site = $discovery->findSite($siteName, $sites);

        if ($site === null) {
            $this->io->error("Site not found: $siteName");
            $this->io->text('Available sites:');
            foreach ($sites as $s) {
                $this->io->text("  - {$s->domain}");
            }
            return Command::FAILURE;
        }

        $this->io->title("Firewall Status: {$site->domain}");

        $fail2ban = new Fail2Ban($config);
        $nginx = new Nginx($config);

        $this->showSiteInfo($site);
        $this->showAccessLog($site);
        $this->showFail2banProtection($site);
        $this->showNginxInclude($site, $config);
        $this->showJailDetail($site, $fail2ban);
        $this->showGlobalNginxBans($nginx, $config);

        return Command::SUCCESS;
    }

    private function showSiteInfo(SiteInfo $site): void
    {
        $this->io->section('Site Info');
        $this->io->text("  Domain:     {$site->domain}");
        $this->io->text("  Path:       {$site->sitePath}");
        $this->io->text("  Short name: {$site->shortName}");
        $this->io->text("  Nginx conf: {$site->nginxSiteConf}");
        $this->io->text("  Forge conf: " . ($site->forgeSiteConf ?? '<not found>'));
    }

    private function showAccessLog(SiteInfo $site): void
    {
        $this->io->section('Access Log');
        $this->io->text("  Log path: {$site->logPath}");
        if (file_exists($site->logPath)) {
            $size = filesize($site->logPath);
            $this->io->text('  Status:   <fg=green>exists</> (' . $this->formatBytes($size) . ')');
        } else {
            $this->io->text('  Status:   <fg=yellow>not found</>');
        }
    }

    private function showFail2banProtection(SiteInfo $site): void
    {
        $this->io->section('fail2ban Protection');
        if ($site->fail2banConf !== null) {
            $this->io->text("  <fg=green>Enabled</> - config: {$site->fail2banConf}");
        } else {
            $this->io->text('  <fg=yellow>Not configured</> - no fail2ban.conf found for this site');
        }
    }

    private function showNginxInclude(SiteInfo $site, FirewallConfig $config): void
    {
        $this->io->section('Nginx Banned IPs Include');
        if ($site->forgeSiteConf !== null && file_exists($site->forgeSiteConf)) {
            $nginxContent = file_get_contents($site->forgeSiteConf);
            $includeDirective = 'include ' . $config->nginxDenyFile . ';';
            if (str_contains($nginxContent, $includeDirective)) {
                $this->io->text("  <fg=green>Present</> - banned IPs include found in {$site->forgeSiteConf}");
            } else {
                $this->io->text("  <fg=yellow>Missing</> - banned IPs include not found in {$site->forgeSiteConf}");
            }
        } elseif ($site->forgeSiteConf === null) {
            $this->io->text("  <fg=red>No Forge site.conf found for this domain</>");
        } else {
            $this->io->text("  <fg=red>Forge site.conf not found:</> {$site->forgeSiteConf}");
        }
    }

    private function showJailDetail(SiteInfo $site, Fail2Ban $fail2ban): void
    {
        $jailName = 'forge-' . $site->shortName;
        $this->io->section("fail2ban Jail: $jailName");

        if (!$fail2ban->isJailActive($jailName)) {
            $this->io->text('  Status: <fg=yellow>not active</>');
            return;
        }

        $bannedCount = $fail2ban->getJailBannedCount($jailName);
        $bannedIps = $fail2ban->getJailBannedIps($jailName);

        $this->io->text("  Status: <fg=green>active</>");
        $this->io->text("  Currently banned: $bannedCount");

        if (!empty($bannedIps)) {
            $this->io->newLine();
            $this->io->text('  Banned IPs in this jail:');
            foreach ($bannedIps as $ip) {
                $this->io->text("    - $ip");
            }
        }
    }

    private function showGlobalNginxBans(Nginx $nginx, FirewallConfig $config): void
    {
        $this->io->section('Global Nginx Bans (all sites)');
        if (!file_exists($config->nginxDenyFile)) {
            $this->io->text("  Banned IPs file not found: {$config->nginxDenyFile}");
            return;
        }

        $bans = $nginx->getAllBans();
        $banCount = count($bans);
        $this->io->text("  File: {$config->nginxDenyFile} ({$banCount} active bans)");

        if ($banCount > 0) {
            $this->io->newLine();
            foreach ($bans as $ip => $comment) {
                $line = "deny {$ip};";
                if ($comment !== '') {
                    $line .= " # {$comment}";
                }
                $this->io->text("    {$line}");
            }
        }
    }

    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 1) . ' ' . $units[$i];
    }
}
