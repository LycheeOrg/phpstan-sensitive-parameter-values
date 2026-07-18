<?php

declare(strict_types=1);

namespace Tests\Fixtures\Types;

use SensitiveParameterValue;
use stdClass;

use function PHPStan\Testing\assertType;

final class SensitiveParameterValueTypes
{
    public function stringValue(string $password): void
    {
        $value = new SensitiveParameterValue($password);

        assertType('SensitiveParameterValue<string>', $value);
        assertType('string', $value->getValue());
    }

    public function intValue(int $pin): void
    {
        $value = new SensitiveParameterValue($pin);

        assertType('SensitiveParameterValue<int>', $value);
        assertType('int', $value->getValue());
    }

    public function nullableValue(?string $token): void
    {
        $value = new SensitiveParameterValue($token);

        assertType('SensitiveParameterValue<string|null>', $value);
        assertType('string|null', $value->getValue());
    }

    /**
     * @param array<string, mixed> $credentials
     */
    public function arrayValue(array $credentials): void
    {
        $value = new SensitiveParameterValue($credentials);

        assertType('SensitiveParameterValue<array<string, mixed>>', $value);
        assertType('array<string, mixed>', $value->getValue());
    }

    public function objectValue(stdClass $secret): void
    {
        $value = new SensitiveParameterValue($secret);

        assertType('SensitiveParameterValue<stdClass>', $value);
        assertType('stdClass', $value->getValue());
    }
}
