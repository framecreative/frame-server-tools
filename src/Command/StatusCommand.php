<?php

namespace App\Command;

use App\Config\FirewallConfig;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
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
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();

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
}
