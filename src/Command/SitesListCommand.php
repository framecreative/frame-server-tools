<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'sites:list',
    description: 'Lists all discovered sites and their fail2ban protection status',
)]
class SitesListCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $discovery = new SiteDiscovery($config);

        $sites = $discovery->discoverAll();
        $total = count($sites);

        $io->title('Discovered Sites');

        if ($total === 0) {
            $io->warning('No sites found.');
            return Command::SUCCESS;
        }

        $protected = 0;
        $rows = [];
        foreach ($sites as $site) {
            $hasFail2ban = $site->fail2banConf !== null;
            if ($hasFail2ban) {
                $protected++;
            }
            $rows[] = [$site->domain, $site->shortName, $hasFail2ban ? 'Yes' : 'No', $site->sitePath];
        }

        $io->table(['Domain', 'Short Name', 'Fail2ban.conf', 'Path'], $rows);
        $io->success("Total sites: {$total} ({$protected} protected, " . ($total - $protected) . " unprotected)");

        return Command::SUCCESS;
    }
}
