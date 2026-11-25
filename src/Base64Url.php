<?php

declare(strict_types=1);

namespace JwtWorkbench;

final class Base64Url
{
    public static function encode(string $rawBytes): string
    {
        return rtrim(strtr(base64_encode($rawBytes), '+/', '-_'), '=');
    }

    public static function decode(string $encoded): string
    {
        $clean = trim($encoded);
        $remainder = strlen($clean) % 4;
        if ($remainder > 0) {
            $clean .= str_repeat('=', 4 -$remainder);
        }
        $decoded = base64_decode(strtr($clean, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Malformed Base64URL segment.');
        }
        return $decoded;
    }
}
