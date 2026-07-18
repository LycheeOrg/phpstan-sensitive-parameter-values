<?php

declare(strict_types=1);

use LycheeOrg\PHPStan\Rules\SensitiveParameterPropagationRule;

it('does not flag sensitive parameters passed to built-in cryptographic functions', function () {
    $this->analyse([__DIR__.'/../Fixtures/Propagation/CryptoPropagationCases.php'], []);
});

it('flags sensitive parameters passed to an unknown callee by default', function () {
    $this->analyse([__DIR__.'/../Fixtures/Propagation/CustomHasherCases.php'], [
        [
            'Parameter $password is marked #[\\SensitiveParameter] but is passed to a parameter ($value) that is not itself marked with #[\\SensitiveParameter]. Add the attribute there too or ignore with `@phpstan-ignore sensitiveParameter.propagation`.',
            21,
        ],
    ]);
});

it('does not flag sensitive parameters passed to a user-configured safe callee', function () {
    $this->rule = new SensitiveParameterPropagationRule(
        $this->createReflectionProvider(),
        ['Tests\Fixtures\Propagation\CryptoHasher::hash'],
    );

    $this->analyse([__DIR__.'/../Fixtures/Propagation/CustomHasherCases.php'], []);
});
