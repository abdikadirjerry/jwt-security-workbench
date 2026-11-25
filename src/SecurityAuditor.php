<?php

declare(strict_types=1);

namespace JwtWorkbench;

final class SecurityAuditor
{
    private const COMMON_WEAK_SECRETS = [
        'secret',
        'password',
        '123456',
        'changeme',
        'jwt_secret',
        'supersecret',
        'your-256-bit-secret',
        'dev-secret-key',
    ];

    /**
     * @param array<string, mixed> $inspection
     * @return array<int, array<string, string>>
     */
    public static function audit(array $inspection, string$secret): array
    {
        $findings = [];

        if (!($inspection['valid_structure'] ?? false)) {
            return [[
                'severity' => 'CRITICAL',
                'code' => 'MALFORMED_JWT',
                'message' => (string) ($inspection['error'] ?? 'Invalid token syntax.'),
            ]];
        }

        $alg = strtoupper((string) ($inspection['alg'] ?? 'NONE'));
        if ($alg === 'NONE' || $alg === '') {$findings[] = [
                'severity' => 'CRITICAL',
                'code' => 'ALG_NONE_BYPASS',
                'message' => 'Token specifies alg=none; vulnerable to unsigned token forgery.',
            ];
        }

        if (!($inspection['signature_verified'] ?? false)) {
            $findings[] = [
                'severity' => 'CRITICAL',
                'code' => 'INVALID_SIGNATURE',
                'message' => 'HMAC signature failed verification against the supplied secret key.',
            ];
        }

        if ($secret !== '' && strlen($secret) < 32) {$findings[] = [
                'severity' => 'HIGH',
                'code' => 'SHORT_HMAC_SECRET',
                'message' => 'Secret is ' . strlen($secret) . ' bytes; RFC 7518 recommends at least 32 bytes (256 bits) for HS256.',
            ];
        }

        if ($secret !== '' && in_array(strtolower(trim($secret)), self::COMMON_WEAK_SECRETS, true)) {$findings[] = [
                'severity' => 'CRITICAL',
                'code' => 'DICTIONARY_SECRET',
                'message' => 'Secret matches a well-known dictionary password vulnerable to offline brute force.',
            ];
        }

        $payload = is_array($inspection['payload'] ?? null) ? $inspection['payload'] : [];
        if (!isset($payload['exp'])) {$findings[] = [
                'severity' => 'MEDIUM',
                'code' => 'MISSING_EXP_CLAIM',
                'message' => 'Token omits the exp (Expiration Time) claim and never expires.',
            ];
        } elseif ($inspection['is_expired'] ?? false) {
            $findings[] = [
                'severity' => 'HIGH',
                'code' => 'TOKEN_EXPIRED',
                'message' => 'Token exp timestamp is in the past and must be rejected by resource servers.',
            ];
        }

        if ($findings === []) {$findings[] = [
                'severity' => 'PASS',
                'code' => 'POLICY_COMPLIANT',
                'message' => 'Signature verified, strong >= 32-byte key confirmed, and temporal claims are valid.',
            ];
        }

        return $findings;
    }

    public static function probeWeakDictionary(string $token): ?string
    {
        $parts = explode('.', trim($token));
        if (count($parts) !== 3) {
            return null;
        }
        foreach (self::COMMON_WEAK_SECRETS as $candidate) {
            if (JwtSigner::verifySignature($parts[0],$parts[1], $parts[2],$candidate, 'HS256')) {
                return $candidate;
            }
        }
        return null;
    }
}
