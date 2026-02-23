<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\Nginx;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:update-cloudflare',
    description: 'Updates Cloudflare real IP ranges for nginx (suitable for cron)',
    help: <<<'HELP'
    Fetches the current list of Cloudflare IP ranges and writes them to the nginx
    realip config so that CF-Connecting-IP is used as the real client address.

    Designed to be run from a cron job. Use --reload to also test and reload nginx
    after writing the config.
    HELP,
    usages: [
        'firewall:update-cloudflare',
        'firewall:update-cloudflare --reload',
    ],
)]
class UpdateCloudflareCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addOption('reload', null, InputOption::VALUE_NONE, 'Reload nginx after updating');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $nginx = new Nginx($config);

        $this->io->text('Fetching current Cloudflare IP ranges...');

        $content = $nginx->createCloudflareRealipConfig();
        $nginx->writeCloudflareRealipConfig($content);

        $ipCount = substr_count($content, 'set_real_ip_from');
        $this->io->text("  > Written {$ipCount} IP ranges to {$config->cloudflareRealipConf}");

        if ($input->getOption('reload')) {
            if ($nginx->test()) {
                $this->io->text('  > nginx config test passed');
                if ($nginx->reload()) {
                    $this->io->success('Cloudflare IPs updated and nginx reloaded');
                } else {
                    $this->io->error('nginx reload failed');
                    return Command::FAILURE;
                }
            } else {
                $this->io->error('nginx config test failed! Check with: nginx -t');
                return Command::FAILURE;
            }
        } else {
            $this->io->success('Cloudflare IPs updated (run with --reload to reload nginx)');
        }

        return Command::SUCCESS;
    }
}
