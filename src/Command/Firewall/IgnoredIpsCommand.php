<?php

namespace App\Command\Firewall;

use App\Config\FirewallConfig;
use App\Service\Fail2Ban;
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
        $fail2ban = new Fail2Ban($config);

        $this->io->title('Ignored IPs');

        // Global defaults from jail.local
        $this->io->section('jail.local [DEFAULT]');
        $this->io->text('ignoreip = ' . $config->getIgnoreIpList());

        // Per-jail ignored IPs from fail2ban
        $jails = $fail2ban->getJails();

        if (empty($jails)) {
            $this->io->newLine();
            $this->io->text('No active fail2ban jails found.');
            return Command::SUCCESS;
        }

        $rows = [];
        foreach ($jails as $jail) {
            $ips = $fail2ban->getJailIgnoredIps($jail);
            $rows[] = [$jail, $ips ?: '(none)'];
        }

        $this->io->newLine();
        $this->io->section('Active Jails');
        $this->io->table(['Jail', 'Ignored IPs'], $rows);

        return Command::SUCCESS;
    }
}
