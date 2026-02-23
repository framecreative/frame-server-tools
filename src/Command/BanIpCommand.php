<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\Nginx;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:ban',
    description: 'Manually ban an IP address via nginx deny file',
    help: <<<'HELP'
    Adds a deny rule for the given IP to the shared nginx banned-ips file, then
    tests and reloads nginx. The ban applies to all sites. If the IP is already
    banned, the existing entry is shown and no changes are made. If the nginx
    config test fails after writing, the entry is automatically rolled back.
    HELP,
    usages: [
        'firewall:ban 203.0.113.50',
        'firewall:ban 203.0.113.50 "brute force login"',
    ],
)]
class BanIpCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('ip', InputArgument::REQUIRED, 'The IP address to ban')
            ->addArgument('reason', InputArgument::OPTIONAL, 'Reason for the ban');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $ip = $input->getArgument('ip');
        $reason = $input->getArgument('reason');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->io->error("Invalid IP address: $ip");
            return Command::FAILURE;
        }

        $config = new FirewallConfig();
        $nginx = new Nginx($config);

        if ($nginx->isIpBanned($ip)) {
            $this->io->warning("IP $ip is already banned.");
            $line = $nginx->getBanLine($ip);
            if ($line) {
                $this->io->text("  Existing entry: $line");
            }
            return Command::SUCCESS;
        }

        $nginx->banIp($ip, $reason);

        if (!$nginx->test()) {
            $this->io->error('nginx config test failed after adding ban. Removing the entry.');
            $nginx->unbanIp($ip);
            return Command::FAILURE;
        }

        if (!$nginx->reload()) {
            $this->io->error('nginx reload failed.');
            return Command::FAILURE;
        }

        $this->io->success("Banned IP $ip" . ($reason ? " (reason: $reason)" : ''));
        return Command::SUCCESS;
    }
}
