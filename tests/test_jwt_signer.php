<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use JwtWorkbench\Base64Url;
use JwtWorkbench\JwtSigner;

$raw = "hello+world/test==\x00\xff";
$encoded = Base64Url::encode($raw);
if (str_contains($encoded, '+') || str_contains($encoded, '/') || str_contains($encoded, '=')) {
    throw new RuntimeException('Base64URL output must not contain +, /, or =');
}
if (Base64Url::decode($encoded) !== $raw) {
    throw new RuntimeException('Base64URL round-trip mismatch');
}

$secret = 'super-strong-32-byte-secret-key!!';
$token = JwtSigner::mint(['sub' => 'user-1', 'exp' => 2000000000], $secret, 'HS256');
[$h, $p, $s] = explode('.', $token);

if (!JwtSigner::verifySignature($h, $p, $s, $secret, 'HS256')) {
    throw new RuntimeException('Expected valid HS256 signature verification');
}
if (JwtSigner::verifySignature($h, $p, $s, 'wrong-secret', 'HS256')) {
    throw new RuntimeException('Expected invalid signature when secret differs');
}

echo "[PASS] test_jwt_signer\n";
