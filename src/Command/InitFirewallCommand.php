<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\Fail2Ban;
use App\Service\Nginx;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:init',
    description: 'Sets up Fail2ban jails, filters, actions and nginx ban layer',
)]
class InitFirewallCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Print generated config content without writing files')
            ->addOption('skip-cloudflare', null, InputOption::VALUE_NONE, 'Skip Cloudflare IP fetch')
            ->addOption('skip-reload', null, InputOption::VALUE_NONE, 'Write configs only, don\'t reload services');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $dryRun = $input->getOption('dry-run');
        $skipCloudflare = $input->getOption('skip-cloudflare');
        $skipReload = $input->getOption('skip-reload');

        $config = new FirewallConfig();
        $nginx = new Nginx($config);
        $fail2ban = new Fail2Ban($config);
        $discovery = new SiteDiscovery($config);

        if ($dryRun) {
            $this->io->note('DRY RUN - no files will be written, no services reloaded');
        }

        // Section 1: Nginx layer
        $this->io->section('Setting up nginx ban layer');

        if (!$skipCloudflare) {
            $this->io->text('Fetching current Cloudflare IP ranges...');
            $cfContent = $nginx->createCloudflareRealipConfig();
            if ($dryRun) {
                $this->io->text("Would write to: {$config->cloudflareRealipConf}");
                $this->io->block($cfContent, 'CONFIG');
            } else {
                $nginx->writeCloudflareRealipConfig($cfContent);
                $this->io->text("  > Cloudflare real IP config written to {$config->cloudflareRealipConf}");
            }
        } else {
            $this->io->text('Skipping Cloudflare IP fetch (--skip-cloudflare)');
        }

        if ($dryRun) {
            $this->io->text("Would ensure banned IPs file exists at: {$config->nginxDenyFile}");
        } else {
            if ($nginx->ensureBannedIpsFile()) {
                $this->io->text("  > Created empty banned IPs file at {$config->nginxDenyFile}");
            } else {
                $this->io->text("  > Banned IPs file already exists at {$config->nginxDenyFile}");
            }
        }

        // Section 2: Fail2Ban action
        $this->io->section('Creating fail2ban nginx-deny-file action');

        if ($dryRun) {
            $this->io->text("Would write to: {$config->actionDir}nginx-deny-file.conf");
            $this->io->block($fail2ban->getActionContent(), 'CONFIG');
        } else {
            $fail2ban->createAction();
            $this->io->text("  > nginx-deny-file action written to {$config->actionDir}nginx-deny-file.conf");
        }

        // Section 3 & 4: Per-site filters, jails, nginx includes
        $this->io->section('Creating per-site fail2ban filters and jails');

        $sites = $discovery->discoverProtected();

        if (empty($sites)) {
            $this->io->warning('No sites with fail2ban.conf found');
        }

        foreach ($sites as $site) {
            $this->io->text("> Processing {$site->domain}");

            if ($site->fail2banConf) {
                $this->io->text("  > Found repo config at {$site->fail2banConf}");
            }

            // Filter
            if ($dryRun) {
                $this->io->text("  Would write filter to: {$config->filterDir}forge-{$site->shortName}.conf");
                $this->io->block($fail2ban->getFilterContent($site), 'FILTER');
            } else {
                $fail2ban->createFilter($site);
                $this->io->text("  > Filter written for forge-{$site->shortName}");
            }

            // Jail
            if ($dryRun) {
                $this->io->text("  Would write jail to: {$config->jailDir}forge-{$site->shortName}.conf");
                $this->io->block($fail2ban->getJailContent($site), 'JAIL');
            } else {
                $fail2ban->createJail($site);
                $this->io->text("  > Jail written for forge-{$site->shortName}");
            }

            // Nginx include (Forge site.conf)
            if ($site->forgeSiteConf === null) {
                $this->io->warning("  No Forge site.conf found for {$site->domain} - add banned-ips include manually");
            } elseif ($dryRun) {
                $this->io->text("  Would append banned-ips include to: {$site->forgeSiteConf}");
            } else {
                if ($nginx->injectBannedIpsInclude($site)) {
                    $this->io->text("  > Appended banned-ips include to {$site->forgeSiteConf}");
                } else {
                    $this->io->text("  > Banned-ips include already present in {$site->forgeSiteConf}");
                }
            }
        }

        // Section 5: Global jail.local
        $this->io->section('Updating global fail2ban config');

        if ($dryRun) {
            $this->io->text("Would write to: {$config->jailLocalPath}");
            $this->io->block($fail2ban->getJailLocalContent(), 'CONFIG');
        } else {
            $fail2ban->writeJailLocal();
            $this->io->text('  > jail.local written with whitelist and nginx-deny-file as default action');
        }

        // Section 6: Test and reload
        if (!$dryRun && !$skipReload) {
            $this->io->section('Testing and reloading services');

            if ($nginx->test()) {
                $this->io->text('  > nginx config test passed');
                if ($nginx->reload()) {
                    $this->io->text('  > nginx reloaded');
                } else {
                    $this->io->error('nginx reload failed');
                }
            } else {
                $this->io->error('nginx config test failed! Check with: nginx -t');
                $this->io->text('  > Skipping nginx reload - fix the config and reload manually');
            }

            $this->io->text('Reloading fail2ban...');
            if ($fail2ban->reload()) {
                $this->io->text('  > fail2ban reloaded');
            } else {
                $this->io->error('fail2ban reload failed');
            }
        } elseif ($skipReload) {
            $this->io->note('Skipping service reload (--skip-reload)');
        }

        // Summary
        $this->io->success('Setup complete');
        $this->io->listing([
            "Cloudflare real IP config: {$config->cloudflareRealipConf}",
            "Banned IPs file: {$config->nginxDenyFile}",
            "fail2ban action: {$config->actionDir}nginx-deny-file.conf",
            'Test a ban: fail2ban-client set forge-<site> banip 192.0.2.1',
            "Check bans: cat {$config->nginxDenyFile}",
        ]);

        return Command::SUCCESS;
    }
}
