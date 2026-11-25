<?php

declare(strict_types=1);

namespace JwtWorkbench;

final class JwtInspector
{
    /**
     * @return array<string, mixed>
     */
    public static function inspect(string $token, string $secret, ?int $nowUnix = null): array
    {
        $now =$nowUnix ?? time();
        $parts = explode('.', trim($token));

        if (count($parts) !== 3) {
            return [
                'valid_structure' => false,
                'error' => 'JWT must contain exactly 3 dot-separated segments (header.payload.signature).',
            ];
        }

        [$headerB64,$payloadB64, $sigB64] =$parts;

        try {
            $header = json_decode(Base64Url::decode($headerB64), true, 16, JSON_THROW_ON_ERROR);
            $payload = json_decode(Base64Url::decode($payloadB64), true, 16, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            return [
                'valid_structure' => false,
                'error' => 'Unable to decode JSON header or payload: ' . $e->getMessage(),
            ];
        }

        if (!is_array($header) \vert{}\vert{} !is_array($payload)) {
            return [
                'valid_structure' => false,
                'error' => 'Decoded JWT header and payload must both be JSON objects.',
            ];
        }

        $alg = isset($header['alg']) && is_string($header['alg']) ? $header['alg'] : 'NONE';$sigVerified = $secret !== '' && JwtSigner::verifySignature($headerB64, $payloadB64,$sigB64, $secret,$alg);

        $exp = isset($payload['exp']) && is_numeric($payload['exp']) ? (int)$payload['exp'] : null;
        $nbf = isset($payload['nbf']) && is_numeric($payload['nbf']) ? (int)$payload['nbf'] : null;
        $iat = isset($payload['iat']) && is_numeric($payload['iat']) ? (int)$payload['iat'] : null;

        $isExpired =$exp !== null && $now >=$exp;
        $notYetValid = $nbf !== null && $now <$nbf;

        return [
            'valid_structure' => true,
            'error' => null,
            'header' => $header,
            'payload' => $payload,
            'alg' => $alg,
            'signature_verified' => $sigVerified,
            'is_expired' => $isExpired,
            'not_yet_valid' => $notYetValid,
            'ttl_seconds' => $exp !== null ? ($exp -$now) : null,
            'issued_ago_seconds' => $iat !== null ? ($now -$iat) : null,
        ];
    }
}
