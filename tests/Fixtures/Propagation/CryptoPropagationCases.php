<?php

declare(strict_types=1);

namespace Tests\Fixtures\Propagation;

use SensitiveParameter;

/**
 * Test fixtures for verifying that passing #[\SensitiveParameter] arguments
 * into well-known cryptographic functions does NOT trigger a propagation
 * warning: those functions are specifically designed to receive sensitive data.
 */
final class CryptoPropagationCases
{
    // Passing a sensitive parameter to password_hash() is the correct usage - should NOT trigger warning
    public function hashWithPasswordHash(#[SensitiveParameter] string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    // Passing a sensitive parameter to password_verify() is correct - should NOT trigger warning
    public function verifyWithPasswordVerify(#[SensitiveParameter] string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    // Passing a sensitive parameter to hash_hmac() is correct - should NOT trigger warning
    public function computeHmac(#[SensitiveParameter] string $secret, string $data): string
    {
        return hash_hmac('sha256', $data, $secret);
    }

    // Passing a sensitive parameter to crypt() is correct - should NOT trigger warning
    public function cryptPassword(#[SensitiveParameter] string $password, string $salt): string
    {
        return crypt($password, $salt);
    }

    // Passing a sensitive parameter to hash() is correct - should NOT trigger warning
    public function computeHash(#[SensitiveParameter] string $value): string
    {
        return hash('sha256', $value);
    }
}
