<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:access-log',
    description: 'Displays recent access log entries for a site',
)]
class AccessLogCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('site', InputArgument::REQUIRED, 'Site domain, shortName, or jail name (forge-{shortName})')
            ->addOption('lines', 'l', InputOption::VALUE_REQUIRED, 'Number of lines to display', 50);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $site = $input->getArgument('site');
        $lines = (int) $input->getOption('lines');

        $config = new FirewallConfig();
        $discovery = new SiteDiscovery($config);
        $sites = $discovery->discoverAll();

        $matched = $discovery->findSite($site, $sites);

        if ($matched === null) {
            $this->io->error("No site found matching: {$site}");
            $this->io->text('Available sites:');
            foreach ($sites as $s) {
                $this->io->text("  {$s->domain} (shortName: {$s->shortName})");
            }
            return Command::FAILURE;
        }

        if (!file_exists($matched->logPath)) {
            $this->io->error("Access log not found: {$matched->logPath}");
            return Command::FAILURE;
        }

        $allLines = file($matched->logPath, FILE_IGNORE_NEW_LINES);
        $tail = array_slice($allLines, -$lines);

        $this->io->title("{$matched->domain} — Access Log");
        $this->io->text("Log file: {$matched->logPath}");
        $this->io->text("Showing last {$lines} lines:");
        $this->io->newLine();

        foreach ($tail as $line) {
            $output->writeln($line);
        }

        return Command::SUCCESS;
    }
}
