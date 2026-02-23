<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\Fail2Ban;
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
    help: <<<'HELP'
    Removes an IP ban. The IP is first removed from all fail2ban jails (to prevent
    re-banning on the next cycle), then removed from the nginx banned-ips deny file.
    Nginx is tested and reloaded after the change.
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
        $nginx = new Nginx($config);
        $fail2ban = new Fail2Ban($config);

        if (!$nginx->isIpBanned($ip)) {
            $this->io->warning("IP $ip is not in the nginx deny file.");
            return Command::SUCCESS;
        }

        // Unban from fail2ban first to prevent re-banning on next cycle
        if ($fail2ban->unbanIp($ip)) {
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
