<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\Nginx;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:ip-lookup',
    description: 'Look up ban status of an IP in nginx deny file and fail2ban jails',
)]
class IpLookupCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('ip', InputArgument::REQUIRED, 'The IP address to look up');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $ip = $input->getArgument('ip');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $io->error("Invalid IP address: $ip");
            return Command::FAILURE;
        }

        $config = new FirewallConfig();
        $nginx = new Nginx($config);
        $found = false;

        // Check nginx deny file
        $io->section('Nginx deny file');
        $banLine = $nginx->getBanLine($ip);
        if ($banLine) {
            $io->text("  <fg=red>BANNED</> $banLine");
            $found = true;
        } else {
            $io->text('  Not found in nginx deny file.');
        }

        // Check fail2ban jails
        $io->section('Fail2ban jails');
        $jails = $this->getFail2banJails();

        if (empty($jails)) {
            $io->text('  No fail2ban jails found (fail2ban may not be running).');
        } else {
            $jailMatches = [];
            foreach ($jails as $jail) {
                if ($this->isIpInJail($ip, $jail)) {
                    $jailMatches[] = $jail;
                }
            }

            if (!empty($jailMatches)) {
                $found = true;
                foreach ($jailMatches as $jail) {
                    $io->text("  <fg=red>BANNED</> in jail: $jail");
                }
            } else {
                $io->text('  Not found in any fail2ban jail.');
            }
        }

        if (!$found) {
            $io->newLine();
            $io->text("<fg=green>IP $ip is not banned anywhere.</>");
        }

        return Command::SUCCESS;
    }

    private function getFail2banJails(): array
    {
        exec('fail2ban-client status 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return [];
        }

        foreach ($output as $line) {
            if (preg_match('/Jail list:\s*(.+)/', $line, $matches)) {
                return array_map('trim', explode(',', $matches[1]));
            }
        }

        return [];
    }

    private function isIpInJail(string $ip, string $jail): bool
    {
        exec('fail2ban-client status ' . escapeshellarg($jail) . ' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            return false;
        }

        foreach ($output as $line) {
            if (preg_match('/Banned IP list:\s*(.+)/', $line, $matches)) {
                $bannedIps = array_map('trim', explode(' ', $matches[1]));
                return in_array($ip, $bannedIps, true);
            }
        }

        return false;
    }
}
