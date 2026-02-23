<?php

namespace App\Command\Firewall;

use App\Config\FirewallConfig;
use App\Service\Fail2Ban;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:ban',
    description: 'Manually ban an IP address in a fail2ban jail',
    help: <<<'HELP'
    Bans an IP address in the specified fail2ban jail. The ban follows the jail's
    configured bantime and will expire automatically like any other fail2ban ban.

    The jail can be identified by its full domain, its shortName, or its jail name
    (forge-{shortName}). Only protected sites (those with a fail2ban.conf) can be
    used as ban targets.
    HELP,
    usages: [
        'firewall:ban 203.0.113.50 example.com',
        'firewall:ban 203.0.113.50 myshortname',
        'firewall:ban 203.0.113.50 forge-myshortname',
    ],
)]
class BanIpCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('ip', InputArgument::REQUIRED, 'The IP address to ban')
            ->addArgument('jail', InputArgument::REQUIRED, 'The jail to ban in (domain, shortName, or jail name)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $ip = $input->getArgument('ip');
        $jail = $input->getArgument('jail');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->io->error("Invalid IP address: $ip");
            return Command::FAILURE;
        }

        $config = new FirewallConfig();
        $discovery = new SiteDiscovery($config);
        $sites = $discovery->discoverProtected();

        $matched = $discovery->findSite($jail, $sites);

        if ($matched === null) {
            $this->io->error("No protected site found matching: {$jail}");
            $this->io->text('Available jails:');
            foreach ($sites as $s) {
                $this->io->text("  forge-{$s->shortName} ({$s->domain})");
            }
            return Command::FAILURE;
        }

        $jailName = 'forge-' . $matched->shortName;
        $fail2ban = new Fail2Ban($config);

        if (!$fail2ban->banIp($ip, $jailName)) {
            $this->io->error("Failed to ban $ip in jail $jailName. Is the jail active?");
            return Command::FAILURE;
        }

        $this->io->success("Banned IP $ip in jail $jailName");
        return Command::SUCCESS;
    }
}
