<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use JwtWorkbench\JwtInspector;
use JwtWorkbench\JwtSigner;

$secret = 'unit-test-secret-key-with-32-bytes!';
$token = JwtSigner::mint(['sub' => 'alice', 'iat' => 1000, 'exp' => 2000], $secret, 'HS256');

$active = JwtInspector::inspect($token, $secret, 1500);
if (!$active['signature_verified'] || $active['is_expired'] || $active['ttl_seconds'] !== 500) {
    throw new RuntimeException('Expected active token with 500s remaining TTL');
}

$expired = JwtInspector::inspect($token, $secret, 2500);
if (!$expired['is_expired']) {
    throw new RuntimeException('Expected expired token when current time exceeds exp');
}

$malformed = JwtInspector::inspect('only.two', $secret);
if ($malformed['valid_structure'] !== false) {
    throw new RuntimeException('Expected valid_structure=false for 2-segment token');
}

echo "[PASS] test_jwt_inspector\n";
