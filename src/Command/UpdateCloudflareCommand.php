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
)]
class UpdateCloudflareCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('reload', null, InputOption::VALUE_NONE, 'Reload nginx after updating');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $config = new FirewallConfig();
        $nginx = new Nginx($config);

        $io->text('Fetching current Cloudflare IP ranges...');

        $content = $nginx->createCloudflareRealipConfig();
        $nginx->writeCloudflareRealipConfig($content);

        $ipCount = substr_count($content, 'set_real_ip_from');
        $io->text("  > Written {$ipCount} IP ranges to {$config->cloudflareRealipConf}");

        if ($input->getOption('reload')) {
            if ($nginx->test()) {
                $io->text('  > nginx config test passed');
                if ($nginx->reload()) {
                    $io->success('Cloudflare IPs updated and nginx reloaded');
                } else {
                    $io->error('nginx reload failed');
                    return Command::FAILURE;
                }
            } else {
                $io->error('nginx config test failed! Check with: nginx -t');
                return Command::FAILURE;
            }
        } else {
            $io->success('Cloudflare IPs updated (run with --reload to reload nginx)');
        }

        return Command::SUCCESS;
    }
}
