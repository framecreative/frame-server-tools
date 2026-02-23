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
    name: 'firewall:refresh-jail',
    description: 'Refreshes fail2ban jail configs and reloads',
)]
class RefreshJailConfigCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('site', InputArgument::OPTIONAL, 'Site domain or shortName (omit to refresh all)')
            ->addOption('no-regenerate', null, InputOption::VALUE_NONE, 'Skip regenerating config files before reloading');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $site = $input->getArgument('site');
        $regenerate = !$input->getOption('no-regenerate');

        $config = new FirewallConfig();
        $fail2ban = new Fail2Ban($config);

        if ($site === null) {
            return $this->reloadAll($config, $fail2ban, $regenerate);
        }

        $discovery = new SiteDiscovery($config);
        $sites = $discovery->discoverProtected();

        $matched = null;
        foreach ($sites as $s) {
            if ($s->domain === $site || $s->shortName === $site || 'forge-' . $s->shortName === $site) {
                $matched = $s;
                break;
            }
        }

        if ($matched === null) {
            $this->io->error("No protected site found matching: {$site}");
            $this->io->text('Available sites:');
            foreach ($sites as $s) {
                $this->io->text("  {$s->domain} (shortName: {$s->shortName})");
            }
            return Command::FAILURE;
        }

        $jail = 'forge-' . $matched->shortName;

        return $this->reloadSingle($config, $fail2ban, $jail, $regenerate, $matched);
    }

    private function reloadAll(FirewallConfig $config, Fail2Ban $fail2ban, bool $regenerate): int
    {
        if ($regenerate) {
            $this->io->text('Regenerating all jail and filter configs...');
            $discovery = new SiteDiscovery($config);
            $sites = $discovery->discoverProtected();

            foreach ($sites as $site) {
                $fail2ban->createFilter($site);
                $fail2ban->createJail($site);
                $this->io->text("  > Regenerated forge-{$site->shortName}");
            }
        }

        $this->io->text('Reloading fail2ban (all jails)...');

        if ($fail2ban->reload()) {
            $this->io->success('fail2ban reloaded successfully');
            return Command::SUCCESS;
        }

        $this->io->error('fail2ban reload failed');
        return Command::FAILURE;
    }

    private function reloadSingle(FirewallConfig $config, Fail2Ban $fail2ban, string $jail, bool $regenerate, \App\Config\SiteInfo $site): int
    {
        if ($regenerate) {
            $this->io->text("Regenerating config for jail: {$jail}");
            $fail2ban->createFilter($site);
            $fail2ban->createJail($site);
            $this->io->text("  > Regenerated {$jail}");
        }

        $this->io->text("Reloading jail: {$jail}...");

        if ($fail2ban->reloadJail($jail)) {
            $this->io->success("Jail {$jail} reloaded successfully");
            return Command::SUCCESS;
        }

        $this->io->error("Failed to reload jail: {$jail}");
        return Command::FAILURE;
    }
}
