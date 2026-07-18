<?php

declare(strict_types=1);

namespace Tests\Fixtures\Propagation;

use SensitiveParameter;

/**
 * Fixture for testing that user-configured safe callees suppress propagation
 * warnings. CryptoHasher::hash is not in the built-in allowlist, so it
 * triggers a warning by default but is silent once added to cryptoCallees.
 */
final class CustomHasherCases
{
    // With default settings this WILL trigger a propagation warning.
    // When Tests\Fixtures\Propagation\CryptoHasher::hash is added to
    // cryptoCallees, the warning is suppressed.
    public function hashWithCustomHasher(#[SensitiveParameter] string $password): string
    {
        return CryptoHasher::hash($password);
    }
}

final class CryptoHasher
{
    public static function hash(string $value): string
    {
        return hash('sha256', $value);
    }
}
