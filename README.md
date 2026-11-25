# TokenForge — Stateless PHP 8 JWT Security & Signature Workbench (`php-jwt-security-workbench`)

A zero-dependency, database-free **JSON Web Token (JWT) Inspector, HMAC-SHA256/384/512 Signer, and Security Policy Auditor** built with pure PHP 8.

## Why Stateless & Database-Free?
All RFC 4648 Base64URL decoding, constant-time `hash_equals` signature checks, `exp`/`nbf`/`iat` claim evaluations, and weak-secret dictionary probes execute purely in memory per request—requiring no MySQL, no SQLite, no XAMPP, and no Composer packages.

## Running Locally
```bash
php -S 127.0.0.1:8088 -t public
```
Open `http://127.0.0.1:8088` in your browser, or run the CLI test suite:
```bash
php tests/run_all.php
```
