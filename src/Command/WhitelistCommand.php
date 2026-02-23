<?php

namespace App\Command;

use App\Config\FirewallConfig;
use App\Service\Fail2Ban;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'firewall:whitelist',
    description: 'Manage whitelisted IPs that are ignored by fail2ban',
    help: <<<'HELP'
    Manages the IP whitelist stored in config.json. Whitelisted IPs are added to
    fail2ban's ignoreip directive so they are never banned.

    Actions:
      list   — Display all currently whitelisted IPs
      add    — Add an IP to the whitelist
      remove — Remove an IP from the whitelist

    After adding or removing, the jail.local file is rewritten and fail2ban is
    reloaded to apply the change immediately.
    HELP,
    usages: [
        'firewall:whitelist list',
        'firewall:whitelist add 203.0.113.50',
        'firewall:whitelist remove 203.0.113.50',
    ],
)]
class WhitelistCommand extends Command
{
    private SymfonyStyle $io;

    protected function configure(): void
    {
        $this
            ->addArgument('action', InputArgument::REQUIRED, 'Action to perform: list, add, or remove')
            ->addArgument('ip', InputArgument::OPTIONAL, 'IP address (required for add/remove)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $action = $input->getArgument('action');

        return match ($action) {
            'list' => $this->executeList(),
            'add' => $this->executeAdd($input),
            'remove' => $this->executeRemove($input),
            default => $this->invalidAction($action),
        };
    }

    private function executeList(): int
    {
        $config = new FirewallConfig();

        $this->io->title('Whitelisted IPs');

        if (empty($config->ignoredIps)) {
            $this->io->text('No whitelisted IPs configured.');
            return Command::SUCCESS;
        }

        $this->io->listing($config->ignoredIps);
        $this->io->text('jail.local ignoreip directive:');
        $this->io->text("  {$config->getIgnoreIpList()}");

        return Command::SUCCESS;
    }

    private function executeAdd(InputInterface $input): int
    {
        $ip = $input->getArgument('ip');
        if ($ip === null) {
            $this->io->error("IP address is required for 'add' action.");
            return Command::FAILURE;
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->io->error("Invalid IP address: $ip");
            return Command::FAILURE;
        }

        $config = new FirewallConfig();

        if (in_array($ip, $config->ignoredIps, true)) {
            $this->io->warning("IP $ip is already whitelisted.");
            return Command::SUCCESS;
        }

        $newIps = [...$config->ignoredIps, $ip];
        $config->saveIgnoredIps($newIps);
        $this->io->text("Added $ip to whitelist in config.json.");

        return $this->applyJailLocal();
    }

    private function executeRemove(InputInterface $input): int
    {
        $ip = $input->getArgument('ip');
        if ($ip === null) {
            $this->io->error("IP address is required for 'remove' action.");
            return Command::FAILURE;
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->io->error("Invalid IP address: $ip");
            return Command::FAILURE;
        }

        $config = new FirewallConfig();

        if (!in_array($ip, $config->ignoredIps, true)) {
            $this->io->warning("IP $ip is not in the whitelist.");
            return Command::SUCCESS;
        }

        $newIps = array_values(array_filter($config->ignoredIps, fn($existing) => $existing !== $ip));
        $config->saveIgnoredIps($newIps);
        $this->io->text("Removed $ip from whitelist in config.json.");

        return $this->applyJailLocal();
    }

    private function applyJailLocal(): int
    {
        $freshConfig = new FirewallConfig();
        $fail2ban = new Fail2Ban($freshConfig);

        $fail2ban->writeJailLocal();
        $this->io->text('Updated jail.local with new whitelist.');

        if ($fail2ban->reload()) {
            $this->io->success('fail2ban reloaded.');
            return Command::SUCCESS;
        }

        $this->io->error('fail2ban reload failed. The whitelist was saved but you may need to reload manually.');
        return Command::FAILURE;
    }

    private function invalidAction(string $action): int
    {
        $this->io->error("Unknown action: {$action}. Use 'list', 'add', or 'remove'.");
        return Command::FAILURE;
    }
}
