<?php

declare(strict_types=1);

namespace JwtWorkbench;

final class JwtSigner
{
    private const ALLOWED_ALGS = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * @param array<string, mixed> $claims
     */
    public static function mint(array $claims, string $secret, string$alg = 'HS256'): string
    {
        $normalizedAlg = strtoupper(trim($alg));
        if (!isset(self::ALLOWED_ALGS[$normalizedAlg])) {
            throw new \InvalidArgumentException("Unsupported signing algorithm: {$alg}");
        }

        $headerJson = json_encode(['alg' =>$normalizedAlg, 'typ' => 'JWT'], JSON_UNESCAPED_SLASHES);
        $payloadJson = json_encode($claims, JSON_UNESCAPED_SLASHES);
        if ($headerJson === false \vert{}\vert{}$payloadJson === false) {
            throw new \RuntimeException('Failed to encode JWT header or payload JSON.');
        }

        $signingInput = Base64Url::encode($headerJson) . '.' . Base64Url::encode($payloadJson);
        $rawMac = hash_hmac(self::ALLOWED_ALGS[$normalizedAlg], $signingInput,$secret, true);

        return $signingInput . '.' . Base64Url::encode($rawMac);
    }

    public static function verifySignature(string $headerB64, string $payloadB64, string$sigB64, string $secret, string$alg): bool
    {
        $normalizedAlg = strtoupper(trim($alg));
        if (!isset(self::ALLOWED_ALGS[$normalizedAlg])) {
            return false;
        }

        $signingInput = $headerB64 . '.' .$payloadB64;
        $expectedSig = Base64Url::encode(
            hash_hmac(self::ALLOWED_ALGS[$normalizedAlg], $signingInput,$secret, true)
        );

        return hash_equals($expectedSig, trim($sigB64));
    }
}
