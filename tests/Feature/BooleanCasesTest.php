<?php

declare(strict_types=1);

it('skips boolean parameters (by name prefix or type) but still detects others', function () {
    $this->analyse([__DIR__.'/../Fixtures/BooleanCases.php'], [
        [
            'Parameter $hasSecret in Tests\\Fixtures\\BooleanCases::authenticateUnion might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            36,
        ],
        [
            'Parameter $IsPassword in Tests\\Fixtures\\BooleanCases::checkFlag might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            43,
        ],
        [
            'Parameter $password in Tests\\Fixtures\\BooleanCases::login might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            49,
        ],
    ]);
});
