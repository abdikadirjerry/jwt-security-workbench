<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use JwtWorkbench\JwtInspector;
use JwtWorkbench\JwtSigner;
use JwtWorkbench\SecurityAuditor;

$weakToken = JwtSigner::mint(['sub' => 'bob'], 'secret', 'HS256');
$cracked = SecurityAuditor::probeWeakDictionary($weakToken);
if ($cracked !== 'secret') {
    throw new RuntimeException('Expected dictionary probe to detect weak secret');
}

$inspection = JwtInspector::inspect($weakToken, 'secret');
$findings = SecurityAuditor::audit($inspection, 'secret');
$codes = array_column($findings, 'code');

if (!in_array('DICTIONARY_SECRET', $codes, true) || !in_array('MISSING_EXP_CLAIM', $codes, true)) {
    throw new RuntimeException('Expected DICTIONARY_SECRET and MISSING_EXP_CLAIM findings');
}

echo "[PASS] test_security_auditor\n";
