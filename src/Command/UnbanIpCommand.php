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
    name: 'firewall:unban',
    description: 'Remove an IP ban from nginx deny file and fail2ban',
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
        $nginx = new Nginx($config);

        if (!$nginx->isIpBanned($ip)) {
            $this->io->warning("IP $ip is not in the nginx deny file.");
            return Command::SUCCESS;
        }

        // Unban from fail2ban first to prevent re-banning on next cycle
        exec('fail2ban-client unban ' . escapeshellarg($ip) . ' 2>&1', $f2bOutput, $f2bExit);
        if ($f2bExit === 0) {
            $this->io->text("Removed $ip from fail2ban.");
        }

        if (!$nginx->unbanIp($ip)) {
            $this->io->error("Failed to remove $ip from deny file.");
            return Command::FAILURE;
        }

        if (!$nginx->test()) {
            $this->io->error('nginx config test failed after removing ban.');
            return Command::FAILURE;
        }

        if (!$nginx->reload()) {
            $this->io->error('nginx reload failed.');
            return Command::FAILURE;
        }

        $this->io->success("Unbanned IP $ip");
        return Command::SUCCESS;
    }
}
