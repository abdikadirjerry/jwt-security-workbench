<?php

declare(strict_types=1);

namespace JwtWorkbench;

final class ViewShell
{
    public static function esc(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * @param array<string, mixed> $inspection
     * @param array<int, array<string, string>> $findings
     */
    public static function render(string $activeTab, array$inspection, array $findings, string$innerHtml): string
    {
        $tabs = [
            'inspect' => 'Decode & Verify JWT',
            'mint' => 'Mint Signed Token',
            'audit' => 'Security Policy & Secret Probe',
        ];

        $nav = '';
        foreach ($tabs as$slug => $label) {$cls = $slug ===$activeTab ? 'active' : '';
            $nav .= '<a href="/?tab=' . $slug . '" class="' . $cls . '">' . self::esc($label) . '</a>';
        }

        $sigOk = (bool) ($inspection['signature_verified'] ?? false);
        $alg = self::esc((string) ($inspection['alg'] ?? 'INVALID'));
        $ttl =$inspection['ttl_seconds'] ?? null;
        $ttlDisplay =$ttl === null ? 'NO EXP' : ($ttl > 0 ? $ttl . 's left' : 'EXPIRED');$ttlClass = $ttl === null ? 'amber' : ($ttl > 0 ? 'emerald' : 'crimson');

        $highestSev = $findings[0]['severity'] ?? 'PASS';$auditClass = $highestSev === 'PASS' ? 'emerald' : ($highestSev === 'MEDIUM' ? 'amber' : 'crimson');

        return '<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TokenForge // Stateless PHP JWT Security &amp; Signature Workbench</title>
  <link rel="stylesheet" href="/assets/workbench.css" />
</head>
<body>
  <header class="topbar">
    <div class="brand">TOKEN<span>FORGE</span> // STATELESS JWT CRYPTO &amp; CLAIM INSPECTOR</div>
    <nav class="nav-tabs">' . $nav . '</nav>
  </header>
  <main class="container">
    <section class="status-grid">
      <div class="card">
        <div class="stat-label">HMAC Signature</div>
        <div class="stat-val ' . ($sigOk ? 'emerald' : 'crimson') . '">' . ($sigOk ? 'VERIFIED' : 'UNVERIFIED') . '</div>
      </div>
      <div class="card">
        <div class="stat-label">Signing Algorithm</div>
        <div class="stat-val cobalt">' . $alg . '</div>
      </div>
      <div class="card">
        <div class="stat-label">Expiration Window</div>
        <div class="stat-val ' . $ttlClass . '">' . self::esc($ttlDisplay) . '</div>
      </div>
      <div class="card">
        <div class="stat-label">Policy Audit Status</div>
        <div class="stat-val ' . $auditClass . '">' . self::esc($highestSev) . '</div>
      </div>
    </section>
    ' . $innerHtml . '
  </main>
</body>
</html>';
    }
}
