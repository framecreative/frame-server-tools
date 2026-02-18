<?php

namespace App\Command;

use App\Service\Fail2Ban;
use App\Config\FirewallConfig;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:reload',
    description: 'Reloads the fail2ban service',
)]
class ReloadFail2BanCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $fail2ban = new Fail2Ban($config);

        $io->text('Reloading fail2ban...');

        if ($fail2ban->reload()) {
            $io->success('fail2ban reloaded successfully');
            return Command::SUCCESS;
        }

        $io->error('fail2ban reload failed');
        return Command::FAILURE;
    }
}
