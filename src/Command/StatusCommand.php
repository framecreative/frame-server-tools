<?php

namespace App\Command;

use App\Config\FirewallConfig;
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
)]
class StatusCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('site', InputArgument::OPTIONAL, 'Show detailed status for a specific site (domain name)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $siteName = $input->getArgument('site');

        if ($siteName !== null) {
            return $this->executeSiteStatus($io, $config, $siteName);
        }

        $io->title('Firewall Status Dashboard');

        // Cloudflare realip config
        $io->section('Cloudflare Real IP Config');
        if (file_exists($config->cloudflareRealipConf)) {
            $content = file_get_contents($config->cloudflareRealipConf);
            $ipCount = substr_count($content, 'set_real_ip_from');
            $io->text("  Config: {$config->cloudflareRealipConf} (exists, {$ipCount} IP ranges)");
        } else {
            $io->warning("Config not found: {$config->cloudflareRealipConf}");
        }

        // Banned IPs file
        $io->section('Banned IPs');
        if (file_exists($config->nginxDenyFile)) {
            $content = file_get_contents($config->nginxDenyFile);
            $banCount = substr_count($content, 'deny ');
            $io->text("  File: {$config->nginxDenyFile} (exists, {$banCount} active bans)");

            if ($banCount > 0) {
                $lines = array_filter(explode("\n", trim($content)));
                foreach ($lines as $line) {
                    $io->text("    {$line}");
                }
            }
        } else {
            $io->warning("Banned IPs file not found: {$config->nginxDenyFile}");
        }

        // fail2ban service status
        $io->section('fail2ban Service');
        exec('fail2ban-client status 2>&1', $statusOutput, $exitCode);
        if ($exitCode === 0) {
            $io->text('  Status: running');
            foreach ($statusOutput as $line) {
                $io->text("  {$line}");
            }
        } else {
            $io->error('fail2ban is not running or not accessible');
        }

        // Per-jail status
        $io->section('Jail Status');
        $finder = new Finder();

        if (is_dir($config->jailDir)) {
            $finder->files()->in($config->jailDir)->name('forge-*.conf');

            foreach ($finder as $file) {
                $jailName = $file->getFilenameWithoutExtension();
                exec('fail2ban-client status ' . escapeshellarg($jailName) . ' 2>&1', $jailOutput, $jailExit);

                if ($jailExit === 0) {
                    $bannedCount = 0;
                    foreach ($jailOutput as $line) {
                        if (str_contains($line, 'Currently banned')) {
                            preg_match('/(\d+)/', $line, $matches);
                            $bannedCount = (int) ($matches[1] ?? 0);
                        }
                    }
                    $io->text("  {$jailName}: enabled, {$bannedCount} currently banned");
                } else {
                    $io->text("  {$jailName}: not active");
                }

                $jailOutput = [];
            }
        } else {
            $io->text('  No jail directory found');
        }

        return Command::SUCCESS;
    }

    private function executeSiteStatus(SymfonyStyle $io, FirewallConfig $config, string $siteName): int
    {
        $discovery = new SiteDiscovery($config);
        $sites = $discovery->discoverAll();

        $site = null;
        foreach ($sites as $s) {
            if ($s->domain === $siteName) {
                $site = $s;
                break;
            }
        }

        if ($site === null) {
            $io->error("Site not found: $siteName");
            $io->text('Available sites:');
            foreach ($sites as $s) {
                $io->text("  - {$s->domain}");
            }
            return Command::FAILURE;
        }

        $io->title("Firewall Status: {$site->domain}");

        // Site info
        $io->section('Site Info');
        $io->text("  Domain:     {$site->domain}");
        $io->text("  Path:       {$site->sitePath}");
        $io->text("  Short name: {$site->shortName}");
        $io->text("  Nginx conf: {$site->nginxSiteConf}");
        $io->text("  Forge conf: " . ($site->forgeSiteConf ?? '<not found>'));

        // Access log
        $io->section('Access Log');
        $io->text("  Log path: {$site->logPath}");
        if (file_exists($site->logPath)) {
            $size = filesize($site->logPath);
            $io->text('  Status:   <fg=green>exists</> (' . $this->formatBytes($size) . ')');
        } else {
            $io->text('  Status:   <fg=yellow>not found</>');
        }

        // fail2ban protection
        $io->section('fail2ban Protection');
        if ($site->fail2banConf !== null) {
            $io->text("  <fg=green>Enabled</> - config: {$site->fail2banConf}");
        } else {
            $io->text('  <fg=yellow>Not configured</> - no fail2ban.conf found for this site');
        }

        // Nginx banned-ips include (Forge site.conf)
        $io->section('Nginx Banned IPs Include');
        if ($site->forgeSiteConf !== null && file_exists($site->forgeSiteConf)) {
            $nginxContent = file_get_contents($site->forgeSiteConf);
            $includeDirective = 'include ' . $config->nginxDenyFile . ';';
            if (str_contains($nginxContent, $includeDirective)) {
                $io->text("  <fg=green>Present</> - banned IPs include found in {$site->forgeSiteConf}");
            } else {
                $io->text("  <fg=yellow>Missing</> - banned IPs include not found in {$site->forgeSiteConf}");
            }
        } elseif ($site->forgeSiteConf === null) {
            $io->text("  <fg=red>No Forge site.conf found for this domain</>");
        } else {
            $io->text("  <fg=red>Forge site.conf not found:</> {$site->forgeSiteConf}");
        }

        // fail2ban jail status with banned IP list
        $jailName = 'forge-' . $site->shortName;
        $io->section("fail2ban Jail: $jailName");

        exec('fail2ban-client status ' . escapeshellarg($jailName) . ' 2>&1', $jailOutput, $jailExit);

        if ($jailExit === 0) {
            $bannedCount = 0;
            $bannedIps = [];

            foreach ($jailOutput as $line) {
                if (preg_match('/Currently banned:\s*(\d+)/', $line, $matches)) {
                    $bannedCount = (int) $matches[1];
                }
                if (preg_match('/Banned IP list:\s*(.+)/', $line, $matches)) {
                    $bannedIps = array_filter(array_map('trim', explode(' ', $matches[1])));
                }
            }

            $io->text("  Status: <fg=green>active</>");
            $io->text("  Currently banned: $bannedCount");

            if (!empty($bannedIps)) {
                $io->newLine();
                $io->text('  Banned IPs in this jail:');
                foreach ($bannedIps as $ip) {
                    $io->text("    - $ip");
                }
            }
        } else {
            $io->text('  Status: <fg=yellow>not active</>');
        }

        // Global nginx deny file bans
        $io->section('Global Nginx Bans (all sites)');
        if (file_exists($config->nginxDenyFile)) {
            $content = file_get_contents($config->nginxDenyFile);
            $lines = array_filter(explode("\n", trim($content)));
            $banCount = count($lines);
            $io->text("  File: {$config->nginxDenyFile} ({$banCount} active bans)");

            if ($banCount > 0) {
                $io->newLine();
                foreach ($lines as $line) {
                    $io->text("    {$line}");
                }
            }
        } else {
            $io->text("  Banned IPs file not found: {$config->nginxDenyFile}");
        }

        return Command::SUCCESS;
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
