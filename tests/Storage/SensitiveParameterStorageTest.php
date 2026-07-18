<?php

declare(strict_types=1);

it('flags sensitive values that are stored without being wrapped in SensitiveParameterValue', function () {
    $this->analyse([__DIR__.'/../Fixtures/Storage/StorageCases.php'], [
        [
            'Promoted property $promotedPassword receives a sensitive value but assigns it directly, bypassing \\SensitiveParameterValue. Declare the property without promotion and assign `new \\SensitiveParameterValue($promotedPassword)` in the constructor body, or ignore with `@phpstan-ignore sensitiveParameter.unwrappedPromotion`.',
            24,
        ],
        [
            '$password is a sensitive value and must be wrapped in \\SensitiveParameterValue before being stored, e.g. `... = new \\SensitiveParameterValue($password);`. Ignore with `@phpstan-ignore sensitiveParameter.unwrappedStorage`.',
            35,
        ],
        [
            '$password->getValue() unwraps a \\SensitiveParameterValue and must not be stored raw. Store $password itself instead of calling getValue() on it. Ignore with `@phpstan-ignore sensitiveParameter.unwrappedGetValue`.',
            47,
        ],
        [
            '$password is a sensitive value and must be wrapped in \\SensitiveParameterValue before being stored, e.g. `... = new \\SensitiveParameterValue($password);`. Ignore with `@phpstan-ignore sensitiveParameter.unwrappedStorage`.',
            54,
        ],
        [
            '$secret is a sensitive value and must be wrapped in \\SensitiveParameterValue before being stored, e.g. `... = new \\SensitiveParameterValue($secret);`. Ignore with `@phpstan-ignore sensitiveParameter.unwrappedStorage`.',
            60,
        ],
    ]);
});
