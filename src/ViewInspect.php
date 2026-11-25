<?php

declare(strict_types=1);

namespace JwtWorkbench;

final class ViewInspect
{
    /**
     * @param array<string, mixed> $inspection
     * @param array<int, array<string, string>> $findings
     */
    public static function render(string $token, string$secret, array $inspection, array$findings): string
    {
        $parts = explode('.', trim($token));
        $highlightedToken = count($parts) === 3
            ? '<span class="seg-header">' . ViewShell::esc($parts[0]) . '</span>.'
              . '<span class="seg-payload">' . ViewShell::esc($parts[1]) . '</span>.'
              . '<span class="seg-sig">' . ViewShell::esc($parts[2]) . '</span>'
            : ViewShell::esc($token);

        $headerPretty = isset($inspection['header'])
            ? (string) json_encode($inspection['header'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
            : '{}';
        $payloadPretty = isset($inspection['payload'])
            ? (string) json_encode($inspection['payload'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
            : '{}';

        $findingCards = '';
        foreach ($findings as $f) {$sev = ViewShell::esc($f['severity']);$findingCards .= '<div class="finding-row">'
                . '<span class="badge sev-' . $sev . '">' . $sev . '</span>'
                . '<div><strong>' . ViewShell::esc($f['code']) . ':</strong> ' . ViewShell::esc($f['message']) . '</div>'
                . '</div>';
        }

        return '<div class="split-grid">
          <section class="card">
            <div class="panel-header">
              <h2>Encoded JWT &amp; HMAC Secret</h2>
            </div>
            <form class="jwt-form" method="POST" action="/?tab=inspect">
              <label>
                Bearer Token (header.payload.signature)
                <textarea name="token" rows="5" required>' . ViewShell::esc($token) . '</textarea>
              </label>
              <label>
                HMAC Verification Secret
                <input type="text" name="secret" value="' . ViewShell::esc($secret) . '" />
              </label>
              <button type="submit" class="btn-primary">Decode &amp; Verify Signature</button>
            </form>
            <div style="margin-top:1rem;">
              <div class="stat-label" style="margin-bottom:0.4rem;">Color-Coded Token Segments</div>
              <div class="token-preview">' . $highlightedToken . '</div>
            </div>
          </section>

          <section class="card" style="display:flex; flex-direction:column; gap:1rem;">
            <div class="panel-header" style="margin-bottom:0;">
              <h2>Decoded Claims &amp; Security Findings</h2>
            </div>
            <div>
              <div class="stat-label" style="margin-bottom:0.35rem; color:#fb7185;">JOSE Header</div>
              <pre class="json-box">' . ViewShell::esc($headerPretty) . '</pre>
            </div>
            <div>
              <div class="stat-label" style="margin-bottom:0.35rem; color:#c084fc;">Payload Claims</div>
              <pre class="json-box">' . ViewShell::esc($payloadPretty) . '</pre>
            </div>
            <div>
              <div class="stat-label" style="margin-bottom:0.4rem;">Automated Policy Checks</div>
              ' . $findingCards . '
            </div>
          </section>
        </div>';
    }
}
