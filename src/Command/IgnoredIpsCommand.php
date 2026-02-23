<?php

namespace App\Command;

use App\Config\FirewallConfig;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:ignored-ips',
    description: 'Show ignored (whitelisted) IPs for jail.local and all active jails',
)]
class IgnoredIpsCommand extends Command
{
    private SymfonyStyle $io;

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();

        $this->io->title('Ignored IPs');

        // Global defaults from jail.local
        $this->io->section('jail.local [DEFAULT]');
        $this->io->text('ignoreip = ' . $config->getIgnoreIpList());

        // Per-jail ignored IPs from fail2ban
        $jails = $this->getFail2banJails();

        if (empty($jails)) {
            $this->io->newLine();
            $this->io->text('No active fail2ban jails found.');
            return Command::SUCCESS;
        }

        $rows = [];
        foreach ($jails as $jail) {
            $ips = $this->getJailIgnoredIps($jail);
            $rows[] = [$jail, $ips ?: '(none)'];
        }

        $this->io->newLine();
        $this->io->section('Active Jails');
        $this->io->table(['Jail', 'Ignored IPs'], $rows);

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

    private function getJailIgnoredIps(string $jail): string
    {
        exec('fail2ban-client get ' . escapeshellarg($jail) . ' ignoreip 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return '(error querying jail)';
        }

        $ips = [];
        foreach ($output as $line) {
            $line = trim($line);
            // fail2ban-client outputs IPs one per line, prefixed with `|- ` or `\- `
            if (preg_match('/^[|\\\\]-\s+(.+)/', $line, $matches)) {
                $ips[] = $matches[1];
            }
        }

        return implode(', ', $ips);
    }
}
