<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:ban-list',
    description: 'Show all currently banned IPs across nginx and fail2ban',
    help: <<<'HELP'
    Displays a unified view of all banned IPs from both the nginx deny file and
    all active fail2ban jails. Each IP shows its source (nginx deny file comment
    and/or which jail(s) it appears in).

    Use --jail to filter to a specific jail.
    HELP,
    usages: [
        'firewall:ban-list',
        'firewall:ban-list --jail=forge-myshortname',
        'firewall:ban-list -j example.com',
    ],
)]
class BanListCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addOption('jail', 'j', InputOption::VALUE_REQUIRED, 'Filter to a specific jail (domain, shortName, or jail name)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $jailFilter = $input->getOption('jail');

        // Parse nginx deny file
        $nginxBans = [];
        if (file_exists($config->nginxDenyFile)) {
            $lines = file($config->nginxDenyFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (preg_match('/^deny\s+([^;]+);\s*(?:#\s*(.*))?$/', $line, $m)) {
                    $nginxBans[trim($m[1])] = trim($m[2] ?? '');
                }
            }
        }

        // Get fail2ban jails
        $jails = $this->getFail2banJails();

        // Resolve --jail filter
        if ($jailFilter !== null) {
            $discovery = new SiteDiscovery($config);
            $sites = $discovery->discoverProtected();
            $matched = $discovery->findSite($jailFilter, $sites);

            if ($matched === null) {
                $this->io->error("No protected site found matching: {$jailFilter}");
                $this->io->text('Available jails:');
                foreach ($sites as $s) {
                    $this->io->text("  forge-{$s->shortName} ({$s->domain})");
                }
                return Command::FAILURE;
            }

            $resolvedJail = 'forge-' . $matched->shortName;
            $jails = in_array($resolvedJail, $jails, true) ? [$resolvedJail] : [];
        }

        // Get banned IPs per jail
        $jailBans = [];
        foreach ($jails as $jail) {
            foreach ($this->getJailBannedIps($jail) as $ip) {
                $jailBans[$ip][] = $jail;
            }
        }

        // Merge all unique IPs
        $allIps = array_unique(array_merge(array_keys($nginxBans), array_keys($jailBans)));

        $this->io->title('Banned IPs');

        if (empty($allIps)) {
            $this->io->text('No banned IPs found.');
            return Command::SUCCESS;
        }

        sort($allIps);

        $rows = [];
        foreach ($allIps as $ip) {
            $rows[] = [
                $ip,
                $nginxBans[$ip] ?? '-',
                isset($jailBans[$ip]) ? implode(', ', $jailBans[$ip]) : '-',
            ];
        }

        $this->io->table(['IP', 'Nginx Deny Comment', 'Fail2ban Jail(s)'], $rows);

        $nginxCount = count($nginxBans);
        $jailIpCount = count($jailBans);
        $this->io->text(sprintf(
            '%d unique IP(s) — %d in nginx deny file, %d in fail2ban jails',
            count($allIps),
            $nginxCount,
            $jailIpCount,
        ));

        return Command::SUCCESS;
    }

    private function getFail2banJails(): array
    {
        exec('fail2ban-client status 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return [];
        }

        foreach ($output as $line) {
            if (preg_match('/Jail list:\s*(.+)/', $line, $matches)) {
                return array_map('trim', explode(',', $matches[1]));
            }
        }

        return [];
    }

    private function getJailBannedIps(string $jail): array
    {
        exec('fail2ban-client status ' . escapeshellarg($jail) . ' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return [];
        }

        foreach ($output as $line) {
            if (preg_match('/Banned IP list:\s*(.+)/', $line, $matches)) {
                return array_filter(array_map('trim', explode(' ', $matches[1])));
            }
        }

        return [];
    }
}
