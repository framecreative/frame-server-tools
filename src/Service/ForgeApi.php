<?php

namespace App\Service;

use App\Config\FirewallConfig;
use RuntimeException;

class ForgeApi
{
    private const BASE_URL = 'https://forge.laravel.com/api/v1';

    public function __construct(
        private readonly FirewallConfig $config,
    ) {}

    /**
     * Whether the Forge API token and server ID are both configured.
     */
    public function isConfigured(): bool
    {
        return $this->config->forgeApiToken !== '' && $this->config->forgeServerId !== '';
    }

    /**
     * Lists all scheduled jobs on the server.
     *
     * @return array<int, array{id: int, command: string, frequency: string, user: string}>
     */
    public function listJobs(): array
    {
        $response = $this->request('GET', "/servers/{$this->config->forgeServerId}/jobs");

        return $response['jobs'] ?? [];
    }

    /**
     * Creates a scheduled job on the server.
     *
     * @return array{id: int, command: string, frequency: string, user: string}
     */
    public function createJob(string $command, string $frequency, string $user): array
    {
        $response = $this->request('POST', "/servers/{$this->config->forgeServerId}/jobs", [
            'command' => $command,
            'frequency' => $frequency,
            'user' => $user,
        ]);

        return $response['job'] ?? $response;
    }

    /**
     * Deletes a scheduled job from the server.
     */
    public function deleteJob(int $jobId): bool
    {
        $this->request('DELETE', "/servers/{$this->config->forgeServerId}/jobs/{$jobId}");

        return true;
    }

    /**
     * Sends an HTTP request to the Forge API.
     */
    private function request(string $method, string $path, ?array $data = null): array
    {
        $url = self::BASE_URL . $path;

        $headers = [
            'Authorization: Bearer ' . $this->config->forgeApiToken,
            'Accept: application/json',
            'Content-Type: application/json',
        ];

        $options = [
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'ignore_errors' => true,
                'timeout' => 15,
            ],
        ];

        if ($data !== null) {
            $options['http']['content'] = json_encode($data);
        }

        $context = stream_context_create($options);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            throw new RuntimeException("Forge API request failed: {$method} {$path}");
        }

        // Extract status code from response headers
        $statusCode = 0;
        if (isset($http_response_header[0])) {
            preg_match('/\d{3}/', $http_response_header[0], $matches);
            $statusCode = (int) ($matches[0] ?? 0);
        }

        if ($statusCode >= 400) {
            $body = json_decode($response, true);
            $message = $body['message'] ?? $response;
            throw new RuntimeException("Forge API error ({$statusCode}): {$message}");
        }

        // DELETE returns empty body
        if ($response === '') {
            return [];
        }

        $decoded = json_decode($response, true);
        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Forge API returned invalid JSON: ' . json_last_error_msg());
        }

        return $decoded;
    }
}
