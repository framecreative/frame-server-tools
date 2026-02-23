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
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('site', InputArgument::OPTIONAL, 'Show detailed status for a specific site (domain name)');
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

        // Cloudflare realip config
        $this->io->section('Cloudflare Real IP Config');
        if (file_exists($config->cloudflareRealipConf)) {
            $content = file_get_contents($config->cloudflareRealipConf);
            $ipCount = substr_count($content, 'set_real_ip_from');
            $this->io->text("  Config: {$config->cloudflareRealipConf} (exists, {$ipCount} IP ranges)");
        } else {
            $this->io->warning("Config not found: {$config->cloudflareRealipConf}");
        }

        // Banned IPs file
        $this->io->section('Banned IPs');
        if (file_exists($config->nginxDenyFile)) {
            $content = file_get_contents($config->nginxDenyFile);
            $banCount = substr_count($content, 'deny ');
            $this->io->text("  File: {$config->nginxDenyFile} (exists, {$banCount} active bans)");

            if ($banCount > 0) {
                $lines = array_filter(explode("\n", trim($content)));
                foreach ($lines as $line) {
                    $this->io->text("    {$line}");
                }
            }
        } else {
            $this->io->warning("Banned IPs file not found: {$config->nginxDenyFile}");
        }

        // fail2ban service status
        $this->io->section('fail2ban Service');
        exec('fail2ban-client status 2>&1', $statusOutput, $exitCode);
        if ($exitCode === 0) {
            $this->io->text('  Status: running');
            foreach ($statusOutput as $line) {
                $this->io->text("  {$line}");
            }
        } else {
            $this->io->error('fail2ban is not running or not accessible');
        }

        // Per-jail status
        $this->io->section('Jail Status');
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
                    $this->io->text("  {$jailName}: enabled, {$bannedCount} currently banned");
                } else {
                    $this->io->text("  {$jailName}: not active");
                }

                $jailOutput = [];
            }
        } else {
            $this->io->text('  No jail directory found');
        }

        return Command::SUCCESS;
    }

    private function executeSiteStatus(FirewallConfig $config, string $siteName): int
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
            $this->io->error("Site not found: $siteName");
            $this->io->text('Available sites:');
            foreach ($sites as $s) {
                $this->io->text("  - {$s->domain}");
            }
            return Command::FAILURE;
        }

        $this->io->title("Firewall Status: {$site->domain}");

        // Site info
        $this->io->section('Site Info');
        $this->io->text("  Domain:     {$site->domain}");
        $this->io->text("  Path:       {$site->sitePath}");
        $this->io->text("  Short name: {$site->shortName}");
        $this->io->text("  Nginx conf: {$site->nginxSiteConf}");
        $this->io->text("  Forge conf: " . ($site->forgeSiteConf ?? '<not found>'));

        // Access log
        $this->io->section('Access Log');
        $this->io->text("  Log path: {$site->logPath}");
        if (file_exists($site->logPath)) {
            $size = filesize($site->logPath);
            $this->io->text('  Status:   <fg=green>exists</> (' . $this->formatBytes($size) . ')');
        } else {
            $this->io->text('  Status:   <fg=yellow>not found</>');
        }

        // fail2ban protection
        $this->io->section('fail2ban Protection');
        if ($site->fail2banConf !== null) {
            $this->io->text("  <fg=green>Enabled</> - config: {$site->fail2banConf}");
        } else {
            $this->io->text('  <fg=yellow>Not configured</> - no fail2ban.conf found for this site');
        }

        // Nginx banned-ips include (Forge site.conf)
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

        // fail2ban jail status with banned IP list
        $jailName = 'forge-' . $site->shortName;
        $this->io->section("fail2ban Jail: $jailName");

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

            $this->io->text("  Status: <fg=green>active</>");
            $this->io->text("  Currently banned: $bannedCount");

            if (!empty($bannedIps)) {
                $this->io->newLine();
                $this->io->text('  Banned IPs in this jail:');
                foreach ($bannedIps as $ip) {
                    $this->io->text("    - $ip");
                }
            }
        } else {
            $this->io->text('  Status: <fg=yellow>not active</>');
        }

        // Global nginx deny file bans
        $this->io->section('Global Nginx Bans (all sites)');
        if (file_exists($config->nginxDenyFile)) {
            $content = file_get_contents($config->nginxDenyFile);
            $lines = array_filter(explode("\n", trim($content)));
            $banCount = count($lines);
            $this->io->text("  File: {$config->nginxDenyFile} ({$banCount} active bans)");

            if ($banCount > 0) {
                $this->io->newLine();
                foreach ($lines as $line) {
                    $this->io->text("    {$line}");
                }
            }
        } else {
            $this->io->text("  Banned IPs file not found: {$config->nginxDenyFile}");
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
