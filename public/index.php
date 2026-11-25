<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use JwtWorkbench\JwtInspector;
use JwtWorkbench\JwtSigner;
use JwtWorkbench\SecurityAuditor;
use JwtWorkbench\ViewInspect;
use JwtWorkbench\ViewMintAndAudit;
use JwtWorkbench\ViewShell;

$uriPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// Serve static stylesheet cleanly when routed through PHP built-in server
if ($uriPath === '/assets/workbench.css') {
    header('Content-Type: text/css; charset=utf-8');
    readfile(__DIR__ . '/assets/workbench.css');
    exit;
}

$defaultSecret = 'prod-signing-key-256bit-entropy-991a7f';
$defaultToken = JwtSigner::mint([
    'sub' => 'usr_abdikadir_dev',
    'role' => 'security_engineer',
    'iss' => 'auth.tokenforge.local',
    'iat' => time() - 120,
    'exp' => time() + 3480,
], $defaultSecret, 'HS256');

$tab = (string) ($_GET['tab'] ?? 'inspect');
$action = (string) ($_GET['action'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'mint') {
    $secret = (string) ($_POST['secret'] ?? $defaultSecret);
    $alg = (string) ($_POST['alg'] ?? 'HS256');
    $ttl = (int) ($_POST['ttl'] ?? 3600);
    $now = time();
    $token = JwtSigner::mint([
        'sub' => trim((string) ($_POST['sub'] ?? 'usr_guest')),
        'role' => trim((string) ($_POST['role'] ?? 'viewer')),
        'iss' => trim((string) ($_POST['iss'] ?? 'auth.tokenforge.local')),
        'iat' => $now,
        'exp' => $now + $ttl,
    ], $secret, $alg);
    $tab = 'inspect';
} else {
    $token = trim((string) ($_POST['token'] ?? $defaultToken));$secret = (string) ($_POST['secret'] ?? $defaultSecret);
}

$inspection = JwtInspector::inspect($token, $secret);$findings = SecurityAuditor::audit($inspection,$secret);

if ($uriPath === '/api/inspect') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'inspection' => $inspection,
        'audit_findings' => $findings,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($tab === 'mint') {
    $body = ViewMintAndAudit::renderMintTab($secret);
} elseif ($tab === 'audit') {
    $cracked = SecurityAuditor::probeWeakDictionary($token);
    $body = ViewMintAndAudit::renderAuditTab($token, $findings,$cracked);
} else {
    $tab = 'inspect';$body = ViewInspect::render($token,$secret, $inspection,$findings);
}

header('Content-Type: text/html; charset=utf-8');
echo ViewShell::render($tab,$inspection, $findings,$body);
