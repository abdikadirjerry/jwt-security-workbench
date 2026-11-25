<?php

declare(strict_types=1);

namespace JwtWorkbench;

final class ViewMintAndAudit
{
    public static function renderMintTab(string $secret): string
    {
        return '<section class="card" style="max-width:760px;">
          <div class="panel-header">
            <h2>Mint New Stateless Signed JWT</h2>
          </div>
          <form class="jwt-form" method="POST" action="/?tab=inspect&amp;action=mint">
            <label>
              Subject (sub)
              <input type="text" name="sub" value="usr_abdikadir_dev" required />
            </label>
            <label>
              Authorized Role / Scope
              <input type="text" name="role" value="platform_admin" required />
            </label>
            <label>
              Issuer (iss)
              <input type="text" name="iss" value="auth.tokenforge.local" required />
            </label>
            <label>
              HMAC Algorithm
              <select name="alg">
                <option value="HS256">HS256 (HMAC + SHA-256)</option>
                <option value="HS384">HS384 (HMAC + SHA-384)</option>
                <option value="HS512">HS512 (HMAC + SHA-512)</option>
              </select>
            </label>
            <label>
              Time-To-Live (seconds from now; negative creates an expired token)
              <input type="number" name="ttl" value="3600" required />
            </label>
            <label>
              Signing Secret Key
              <input type="text" name="secret" value="' . ViewShell::esc($secret) . '" required />
            </label>
            <button type="submit" class="btn-primary">Sign JWT &amp; Open in Inspector</button>
          </form>
        </section>';
    }

    /**
     * @param array<int, array<string, string>> $findings
     */
    public static function renderAuditTab(string $token, array $findings, ?string $crackedSecret): string
    {
        $probeBanner =$crackedSecret !== null
            ? '<div class="finding-row"><span class="badge sev-CRITICAL">CRACKED</span><div>Weak dictionary secret discovered: <code>' . ViewShell::esc($crackedSecret) . '</code></div></div>'
            : '<div class="finding-row"><span class="badge sev-PASS">RESISTANT</span><div>Token resisted offline dictionary probe across common weak secrets.</div></div>';

        $rows = '';
        foreach ($findings as $f) {$sev = ViewShell::esc($f['severity']);$rows .= '<div class="finding-row">'
                . '<span class="badge sev-' . $sev . '">' . $sev . '</span>'
                . '<div><strong>' . ViewShell::esc($f['code']) . ':</strong> ' . ViewShell::esc($f['message']) . '</div>'
                . '</div>';
        }

        return '<section class="card" style="max-width:860px; display:flex; flex-direction:column; gap:1rem;">
          <div class="panel-header" style="margin-bottom:0;">
            <h2>RFC 7518 Key Strength &amp; Offline Brute-Force Probe</h2>
          </div>
          <form class="jwt-form" method="POST" action="/?tab=audit">
            <label>
              Target JWT to Probe
              <textarea name="token" rows="3" required>' . ViewShell::esc($token) . '</textarea>
            </label>
            <button type="submit" class="btn-primary">Run Weak-Secret Dictionary Audit</button>
          </form>
          <div>
            <div class="stat-label" style="margin-bottom:0.4rem;">Offline Dictionary Probe Result</div>
            ' . $probeBanner . '
          </div>
          <div>
            <div class="stat-label" style="margin-bottom:0.4rem;">Cryptographic Policy Report</div>
            ' . $rows . '
          </div>
        </section>';
    }
}
