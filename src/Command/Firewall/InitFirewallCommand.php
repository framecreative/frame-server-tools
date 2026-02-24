<?php

namespace App\Command\Firewall;

use App\Config\FirewallConfig;
use App\Config\SiteInfo;
use App\Service\Fail2Ban;
use App\Service\ForgeApi;
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
    help: <<<'HELP'
    Performs a full firewall setup for all protected sites on the server:

      1. Fetches Cloudflare IP ranges and writes the nginx realip config
      2. Ensures the shared banned-ips.conf deny file exists
      3. Creates the fail2ban nginx-deny-file action
      4. Generates per-site fail2ban filters and jails for each site with a fail2ban.conf
      5. Injects the banned-ips include into each Forge site.conf
      6. Writes jail.local with whitelisted IPs and default action
      7. Registers a weekly Cloudflare update cron via the Forge API (if configured)
      8. Tests and reloads nginx and fail2ban

    Use --dry-run to preview all generated configs without writing anything.
    Set FORGE_API_TOKEN and FORGE_SERVER_ID env vars for automatic cron setup.
    HELP,
    usages: [
        'firewall:init',
        'firewall:init --dry-run',
        'firewall:init --skip-cloudflare --skip-reload',
        'firewall:init --skip-cron',
    ],
)]
class InitFirewallCommand extends Command
{
    private SymfonyStyle $io;
    private FirewallConfig $config;
    private Nginx $nginx;
    private Fail2Ban $fail2ban;
    private SiteDiscovery $discovery;
    private bool $dryRun;

    protected function configure(): void
    {
        $this
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Print generated config content without writing files')
            ->addOption('skip-cloudflare', null, InputOption::VALUE_NONE, 'Skip Cloudflare IP fetch')
            ->addOption('skip-reload', null, InputOption::VALUE_NONE, 'Write configs only, don\'t reload services')
            ->addOption('skip-cron', null, InputOption::VALUE_NONE, 'Skip Cloudflare update cron setup via Forge API');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $this->dryRun = $input->getOption('dry-run');
        $this->config = new FirewallConfig();
        $this->nginx = new Nginx($this->config);
        $this->fail2ban = new Fail2Ban($this->config);
        $this->discovery = new SiteDiscovery($this->config);

        if ($this->dryRun) {
            $this->io->note('DRY RUN - no files will be written, no services reloaded');
        }

        $this->setupNginxLayer($input->getOption('skip-cloudflare'));
        $this->createFail2banAction();
        $this->processSites();
        $this->updateGlobalJailConfig();
        $this->setupCloudflareCron($input->getOption('skip-cron'));

        if (!$this->dryRun && !$input->getOption('skip-reload')) {
            $this->reloadServices();
        } elseif ($input->getOption('skip-reload')) {
            $this->io->note('Skipping service reload (--skip-reload)');
        }

        $this->printSummary();

        return Command::SUCCESS;
    }

    private function setupNginxLayer(bool $skipCloudflare): void
    {
        $this->io->section('Setting up nginx ban layer');

        if (!$skipCloudflare) {
            $this->io->text('Fetching current Cloudflare IP ranges...');
            $cfContent = $this->nginx->createCloudflareRealipConfig();
            if ($this->dryRun) {
                $this->io->text("Would write to: {$this->config->cloudflareRealipConf}");
                $this->io->block($cfContent, 'CONFIG');
            } else {
                $this->nginx->writeCloudflareRealipConfig($cfContent);
                $this->io->text("  > Cloudflare real IP config written to {$this->config->cloudflareRealipConf}");
            }
        } else {
            $this->io->text('Skipping Cloudflare IP fetch (--skip-cloudflare)');
        }

        if ($this->dryRun) {
            $this->io->text("Would ensure banned IPs file exists at: {$this->config->nginxDenyFile}");
        } else {
            if ($this->nginx->ensureBannedIpsFile()) {
                $this->io->text("  > Created empty banned IPs file at {$this->config->nginxDenyFile}");
            } else {
                $this->io->text("  > Banned IPs file already exists at {$this->config->nginxDenyFile}");
            }
        }
    }

    private function createFail2banAction(): void
    {
        $this->io->section('Creating fail2ban nginx-deny-file action');

        if ($this->dryRun) {
            $this->io->text("Would write to: {$this->config->actionDir}nginx-deny-file.conf");
            $this->io->block($this->fail2ban->getActionContent(), 'CONFIG');
        } else {
            $this->fail2ban->createAction();
            $this->io->text("  > nginx-deny-file action written to {$this->config->actionDir}nginx-deny-file.conf");
        }
    }

    private function processSites(): void
    {
        $this->io->section('Creating per-site fail2ban filters and jails');

        $sites = $this->discovery->discoverProtected();

        if (empty($sites)) {
            $this->io->warning('No sites with fail2ban.conf found');
        }

        foreach ($sites as $site) {
            $this->processSite($site);
        }
    }

    private function processSite(SiteInfo $site): void
    {
        $this->io->text("> Processing {$site->domain}");

        if ($site->fail2banConf) {
            $this->io->text("  > Found repo config at {$site->fail2banConf}");
        }

        // Filter
        if ($this->dryRun) {
            $this->io->text("  Would write filter to: {$this->config->filterDir}forge-{$site->shortName}.conf");
            $this->io->block($this->fail2ban->getFilterContent($site), 'FILTER');
        } else {
            $this->fail2ban->createFilter($site);
            $this->io->text("  > Filter written for forge-{$site->shortName}");
        }

        // Jail
        if ($this->dryRun) {
            $this->io->text("  Would write jail to: {$this->config->jailDir}forge-{$site->shortName}.conf");
            $this->io->block($this->fail2ban->getJailContent($site), 'JAIL');
        } else {
            $this->fail2ban->createJail($site);
            $this->io->text("  > Jail written for forge-{$site->shortName}");
        }

        // Nginx include
        if ($site->forgeSiteConf === null) {
            $this->io->warning("  No Forge site.conf found for {$site->domain} - add banned-ips include manually");
        } elseif ($this->dryRun) {
            $this->io->text("  Would append banned-ips include to: {$site->forgeSiteConf}");
        } else {
            if ($this->nginx->injectBannedIpsInclude($site)) {
                $this->io->text("  > Appended banned-ips include to {$site->forgeSiteConf}");
            } else {
                $this->io->text("  > Banned-ips include already present in {$site->forgeSiteConf}");
            }
        }
    }

    private function updateGlobalJailConfig(): void
    {
        $this->io->section('Updating global fail2ban config');

        if ($this->dryRun) {
            $this->io->text("Would write to: {$this->config->jailLocalPath}");
            $this->io->block($this->fail2ban->getJailLocalContent(), 'CONFIG');
        } else {
            $this->fail2ban->writeJailLocal();
            $this->io->text('  > jail.local written with whitelist and nginx-deny-file as default action');
        }
    }

    private function setupCloudflareCron(bool $skipCron): void
    {
        $this->io->section('Cloudflare update cron');

        if ($skipCron) {
            $this->io->text('Skipping Cloudflare cron setup (--skip-cron)');
            return;
        }

        $forgeApi = new ForgeApi($this->config);

        if (!$forgeApi->isConfigured()) {
            $this->io->text('Skipping Cloudflare cron setup (FORGE_API_TOKEN/FORGE_SERVER_ID env vars not set)');
            return;
        }

        $frmdvPath = realpath(dirname(__DIR__, 3) . '/frmdv');
        $cronCommand = $frmdvPath . ' firewall:update-cloudflare --reload';

        if ($this->dryRun) {
            $this->io->text("Would register Forge scheduled job:");
            $this->io->text("  Command:   {$cronCommand}");
            $this->io->text("  Frequency: weekly");
            $this->io->text("  User:      root");
            return;
        }

        $jobs = $forgeApi->listJobs();
        foreach ($jobs as $job) {
            if (str_contains($job['command'], 'firewall:update-cloudflare')) {
                $this->io->text("  > Cloudflare update cron already registered (job #{$job['id']}, {$job['frequency']})");
                return;
            }
        }

        $job = $forgeApi->createJob($cronCommand, 'weekly', 'root');
        $this->io->text("  > Cloudflare update cron created (job #{$job['id']}, weekly)");
    }

    private function reloadServices(): void
    {
        $this->io->section('Testing and reloading services');

        if ($this->nginx->test()) {
            $this->io->text('  > nginx config test passed');
            if ($this->nginx->reload()) {
                $this->io->text('  > nginx reloaded');
            } else {
                $this->io->error('nginx reload failed');
            }
        } else {
            $this->io->error('nginx config test failed! Check with: nginx -t');
            $this->io->text('  > Skipping nginx reload - fix the config and reload manually');
        }

        $this->io->text('Reloading fail2ban...');
        if ($this->fail2ban->reload()) {
            $this->io->text('  > fail2ban reloaded');
        } else {
            $this->io->error('fail2ban reload failed');
        }
    }

    private function printSummary(): void
    {
        $this->io->success('Setup complete');
        $this->io->listing([
            "Cloudflare real IP config: {$this->config->cloudflareRealipConf}",
            "Banned IPs file: {$this->config->nginxDenyFile}",
            "fail2ban action: {$this->config->actionDir}nginx-deny-file.conf",
            'Test a ban: fail2ban-client set forge-<site> banip 192.0.2.1',
            "Check bans: cat {$this->config->nginxDenyFile}",
        ]);
    }
}
