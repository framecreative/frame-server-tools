<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\Fail2Ban;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:reload-jail',
    description: 'Reloads a specific fail2ban jail or all jails',
)]
class ReloadJailCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('jail', InputArgument::REQUIRED, 'Jail name or "all" to reload all jails')
            ->addOption('regenerate', null, InputOption::VALUE_NONE, 'Regenerate filter/jail config files before reloading');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $jail = $input->getArgument('jail');
        $regenerate = $input->getOption('regenerate');

        $config = new FirewallConfig();
        $fail2ban = new Fail2Ban($config);

        if ($jail === 'all') {
            return $this->reloadAll($io, $config, $fail2ban, $regenerate);
        }

        return $this->reloadSingle($io, $config, $fail2ban, $jail, $regenerate);
    }

    private function reloadAll(SymfonyStyle $io, FirewallConfig $config, Fail2Ban $fail2ban, bool $regenerate): int
    {
        if ($regenerate) {
            $io->text('Regenerating all jail and filter configs...');
            $discovery = new SiteDiscovery($config);
            $sites = $discovery->discover();

            foreach ($sites as $site) {
                $fail2ban->createFilter($site);
                $fail2ban->createJail($site);
                $io->text("  > Regenerated forge-{$site->shortName}");
            }
        }

        $io->text('Reloading fail2ban (all jails)...');

        if ($fail2ban->reload()) {
            $io->success('fail2ban reloaded successfully');
            return Command::SUCCESS;
        }

        $io->error('fail2ban reload failed');
        return Command::FAILURE;
    }

    private function reloadSingle(SymfonyStyle $io, FirewallConfig $config, Fail2Ban $fail2ban, string $jail, bool $regenerate): int
    {
        if ($regenerate) {
            $io->text("Regenerating config for jail: {$jail}");
            $discovery = new SiteDiscovery($config);
            $sites = $discovery->discover();

            // Find the matching site by jail name
            $found = false;
            foreach ($sites as $site) {
                if ('forge-' . $site->shortName === $jail) {
                    $fail2ban->createFilter($site);
                    $fail2ban->createJail($site);
                    $io->text("  > Regenerated {$jail}");
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                $io->warning("No matching site found for jail: {$jail}");
            }
        }

        $io->text("Reloading jail: {$jail}...");

        if ($fail2ban->reloadJail($jail)) {
            $io->success("Jail {$jail} reloaded successfully");
            return Command::SUCCESS;
        }

        $io->error("Failed to reload jail: {$jail}");
        return Command::FAILURE;
    }
}
