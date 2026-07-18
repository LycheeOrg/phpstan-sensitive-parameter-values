<?php

declare(strict_types=1);

namespace Tests\Fixtures;

final class BooleanCases
{
    // Skipped: parameter name starts with the "is" boolean-naming convention
    public function checkStatus(bool $isPassword): bool
    {
        return true;
    }

    // Skipped: the "is" prefix check matches even though the parameter isn't
    // actually a boolean
    public function checkToken(string $isSecretToken): bool
    {
        return true;
    }

    // Skipped: the declared type hint is bool
    public function authenticate(bool $hasSecret): bool
    {
        return true;
    }

    // Skipped: nullable bool type hint
    public function authenticateNullable(?bool $hasSecret): bool
    {
        return true;
    }

    // Not skipped: bool is only part of a union type, so the parameter can
    // still hold a non-boolean value
    public function authenticateUnion(bool|string $hasSecret): bool
    {
        return true;
    }

    // Not skipped: the prefix check is case-sensitive, so "Is" does not match
    // (a non-bool type is used here so the type-based skip doesn't apply)
    public function checkFlag(string $IsPassword): bool
    {
        return true;
    }

    // Not skipped: unrelated to the boolean logic
    public function login(string $password): bool
    {
        return true;
    }
}
