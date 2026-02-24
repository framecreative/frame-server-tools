<?php

namespace App\Command\Firewall;

use App\Config\FirewallConfig;
use App\Service\Fail2Ban;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:unban',
    description: 'Remove an IP ban from fail2ban jails',
    help: <<<'HELP'
    Unbans an IP from all fail2ban jails. The jail's actionunban handler
    takes care of removing the deny rule from nginx and reloading.
    HELP,
    usages: [
        'firewall:unban 203.0.113.50',
    ],
)]
class UnbanIpCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('ip', InputArgument::REQUIRED, 'The IP address to unban');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $ip = $input->getArgument('ip');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->io->error("Invalid IP address: $ip");
            return Command::FAILURE;
        }

        $config = new FirewallConfig();
        $fail2ban = new Fail2Ban($config);

        if (!$fail2ban->unbanIp($ip)) {
            $this->io->error("Failed to unban $ip from fail2ban.");
            return Command::FAILURE;
        }

        $this->io->success("Unbanned IP $ip");
        return Command::SUCCESS;
    }
}
