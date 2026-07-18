<?php

declare(strict_types=1);

it('flags sensitive parameters that are passed to a callee parameter without being marked sensitive there too', function () {
    $this->analyse([__DIR__.'/../Fixtures/Propagation/PropagationCases.php'], [
        [
            'Parameter $password is marked #[\\SensitiveParameter] but is passed to a parameter ($password) that is not itself marked with #[\\SensitiveParameter]. Add the attribute there too or ignore with `@phpstan-ignore sensitiveParameter.propagation`.',
            25,
        ],
        [
            'Parameter $token is marked #[\\SensitiveParameter] but is passed to a parameter ($token) that is not itself marked with #[\\SensitiveParameter]. Add the attribute there too or ignore with `@phpstan-ignore sensitiveParameter.propagation`.',
            62,
        ],
        [
            'Parameter $secret is marked #[\\SensitiveParameter] but is passed to a parameter ($secret) that is not itself marked with #[\\SensitiveParameter]. Add the attribute there too or ignore with `@phpstan-ignore sensitiveParameter.propagation`.',
            68,
        ],
        [
            'Parameter $apiKey is marked #[\\SensitiveParameter] but is passed to a parameter ($apiKey) that is not itself marked with #[\\SensitiveParameter]. Add the attribute there too or ignore with `@phpstan-ignore sensitiveParameter.propagation`.',
            74,
        ],
        [
            'Parameter $secret is marked #[\\SensitiveParameter] but is passed to a parameter ($values) that is not itself marked with #[\\SensitiveParameter]. Add the attribute there too or ignore with `@phpstan-ignore sensitiveParameter.propagation`.',
            81,
        ],
    ]);
});
