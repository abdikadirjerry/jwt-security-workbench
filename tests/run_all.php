<?php

declare(strict_types=1);

foreach (glob(__DIR__ . '/test_*.php') ?: [] as $testFile) {
    require $testFile;
}
echo "All TokenForge PHP test suites passed cleanly.\n";
