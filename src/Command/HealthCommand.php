<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Config\SiteInfo;
use App\Service\Fail2Ban;
use App\Service\Nginx;
use App\Service\SiteDiscovery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:health',
    description: 'Run diagnostic checks on all firewall components',
    help: <<<'HELP'
    Verifies that all firewall components are correctly configured and running.
    Checks nginx, fail2ban, Cloudflare realip config, banned IPs file, and per-site
    jail/filter/log configuration. Outputs a pass/warn/fail status for each check
    with a summary at the end.
    HELP,
    usages: [
        'firewall:health',
    ],
)]
class HealthCommand extends Command
{
    private SymfonyStyle $io;
    private int $passed = 0;
    private int $warnings = 0;
    private int $failures = 0;

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $fail2ban = new Fail2Ban($config);
        $nginx = new Nginx($config);

        $this->io->title('Firewall Health Check');

        $this->checkNginx($nginx);
        $this->checkFail2ban($fail2ban);
        $this->checkCloudflareConfig($config);
        $this->checkBannedIpsFile($config);
        $this->checkSites($config, $fail2ban);

        return $this->showSummary();
    }

    private function checkNginx(Nginx $nginx): void
    {
        $this->io->section('nginx');
        $this->check(
            $nginx->test(),
            'nginx configuration test passed',
            'nginx configuration test failed',
        );
    }

    private function checkFail2ban(Fail2Ban $fail2ban): void
    {
        $this->io->section('fail2ban');
        $this->check(
            $fail2ban->isRunning(),
            'fail2ban is running',
            'fail2ban is not running or not accessible',
        );
    }

    private function checkCloudflareConfig(FirewallConfig $config): void
    {
        $this->io->section('Cloudflare Real IP Config');
        if (!file_exists($config->cloudflareRealipConf)) {
            $this->check(false, '', "Config missing: {$config->cloudflareRealipConf}");
            return;
        }

        $this->check(true, "Config exists: {$config->cloudflareRealipConf}");

        $age = time() - filemtime($config->cloudflareRealipConf);
        $lastUpdated = date('Y-m-d', filemtime($config->cloudflareRealipConf));
        if ($age > 30 * 86400) {
            $this->warn("Config is older than 30 days (last updated: {$lastUpdated}). Run firewall:update-cloudflare.");
        } else {
            $this->check(true, "Config is up to date (last updated: {$lastUpdated})");
        }
    }

    private function checkBannedIpsFile(FirewallConfig $config): void
    {
        $this->io->section('Banned IPs File');
        $this->check(
            file_exists($config->nginxDenyFile),
            "File exists: {$config->nginxDenyFile}",
            "File missing: {$config->nginxDenyFile}",
        );
    }

    private function checkSites(FirewallConfig $config, Fail2Ban $fail2ban): void
    {
        $this->io->section('Per-Site Checks');
        $discovery = new SiteDiscovery($config);
        $sites = $discovery->discoverProtected();

        if (empty($sites)) {
            $this->warn('No protected sites found (no sites with fail2ban.conf)');
            return;
        }

        foreach ($sites as $site) {
            $this->checkSite($site, $config, $fail2ban);
        }
    }

    private function checkSite(SiteInfo $site, FirewallConfig $config, Fail2Ban $fail2ban): void
    {
        $jail = 'forge-' . $site->shortName;
        $this->io->newLine();
        $this->io->text("  <options=bold>{$site->domain}</> ({$jail})");

        // Jail config
        $jailPath = rtrim($config->jailDir, '/') . '/' . $jail . '.conf';
        $this->check(
            file_exists($jailPath),
            "Jail config exists: {$jailPath}",
            "Jail config missing: {$jailPath}",
        );

        // Filter config
        $filterPath = rtrim($config->filterDir, '/') . '/' . $jail . '.conf';
        $this->check(
            file_exists($filterPath),
            "Filter config exists: {$filterPath}",
            "Filter config missing: {$filterPath}",
        );

        // Jail active
        $this->check(
            $fail2ban->isJailActive($jail),
            "Jail is active",
            "Jail is not active (run firewall:reload)",
        );

        // Access log
        if (file_exists($site->logPath) && is_readable($site->logPath)) {
            $this->check(true, "Access log readable: {$site->logPath}");
        } elseif (file_exists($site->logPath)) {
            $this->warn("Access log exists but not readable: {$site->logPath}");
        } else {
            $this->warn("Access log not found: {$site->logPath}");
        }

        // Banned-ips include in Forge site.conf
        if ($site->forgeSiteConf !== null && file_exists($site->forgeSiteConf)) {
            $content = file_get_contents($site->forgeSiteConf);
            $includeDirective = 'include ' . $config->nginxDenyFile . ';';
            if (str_contains($content, $includeDirective)) {
                $this->check(true, "Banned-ips include present in {$site->forgeSiteConf}");
            } else {
                $this->warn("Banned-ips include missing from {$site->forgeSiteConf}");
            }
        } elseif ($site->forgeSiteConf === null) {
            $this->warn("No Forge site.conf found for {$site->domain}");
        }
    }

    private function showSummary(): int
    {
        $this->io->newLine();
        $this->io->section('Summary');
        $total = $this->passed + $this->warnings + $this->failures;
        $summary = "{$this->passed} passed, {$this->warnings} warnings, {$this->failures} failures out of {$total} checks";

        if ($this->failures > 0) {
            $this->io->error($summary);
            return Command::FAILURE;
        } elseif ($this->warnings > 0) {
            $this->io->warning($summary);
            return Command::SUCCESS;
        }

        $this->io->success($summary);
        return Command::SUCCESS;
    }

    private function check(bool $pass, string $passMsg, string $failMsg = ''): void
    {
        if ($pass) {
            $this->io->text("    <fg=green>[PASS]</> {$passMsg}");
            $this->passed++;
        } else {
            $this->io->text("    <fg=red>[FAIL]</> {$failMsg}");
            $this->failures++;
        }
    }

    private function warn(string $msg): void
    {
        $this->io->text("    <fg=yellow>[WARN]</> {$msg}");
        $this->warnings++;
    }
}
