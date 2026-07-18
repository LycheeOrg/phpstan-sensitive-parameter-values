<?php

declare(strict_types=1);

use LycheeOrg\PHPStan\Rules\SensitiveParameterDetectorRule;

beforeEach(function () {
    $this->rule = new SensitiveParameterDetectorRule();
});

it('detects basic sensitive parameters', function () {
    $this->analyse([__DIR__.'/../Fixtures/Detector/BasicSensitiveParameters.php'], [
        [
            'Parameter $userSecret in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::regularFunction might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            13,
        ],
        [
            'Parameter $credential in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::regularFunction might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            13,
        ],
        [
            'Parameter $password in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::authenticate might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            19,
        ],
        [
            'Parameter $apikey in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::setApiCredentials might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            24,
        ],
        [
            'Parameter $apisecret in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::setApiCredentials might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            24,
        ],
        [
            'Parameter $cardNumber in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::processPayment might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            29,
        ],
        [
            'Parameter $cvv in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::processPayment might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            29,
        ],
        [
            'Parameter $creditCardToken in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::processPayment might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            29,
        ],
        [
            'Parameter $ssn in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::storeUserData might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            34,
        ],
        [
            'Parameter $privateKey in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::storeUserData might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            34,
        ],
        [
            'Parameter $authToken in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::handleTokens might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            39,
        ],
        [
            'Parameter $refreshToken in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::handleTokens might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            39,
        ],
        [
            'Parameter $accessToken in Tests\\Fixtures\\Detector\\BasicSensitiveParameters::handleTokens might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            39,
        ],
        [
            'Parameter $password in globalAuthFunction might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            46,
        ],
    ]);
});

test('does not warn for protected sensitive parameters', function () {
    $this->analyse([__DIR__.'/../Fixtures/Detector/ProtectedSensitiveParameters.php'], [
        [
            'Parameter $apikey in Tests\\Fixtures\\Detector\\ProtectedSensitiveParameters::setApiCredentials might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            22,
        ],
        [
            'Parameter $cvv in Tests\\Fixtures\\Detector\\ProtectedSensitiveParameters::processPayment might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            28,
        ],
    ]);
});

test('detects edge cases correctly', function () {
    $this->analyse([__DIR__.'/../Fixtures/Detector/EdgeCases.php'], [
        [
            'Parameter $apikey in Tests\\Fixtures\\Detector\\EdgeCases::__construct might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            13,
        ],
        [
            'Parameter $credential in Tests\\Fixtures\\Detector\\EdgeCases::staticMethod might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            18,
        ],
        [
            'Parameter $userPassword in Tests\\Fixtures\\Detector\\EdgeCases::partialMatches might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            24,
        ],
        [
            'Parameter $secretKey in Tests\\Fixtures\\Detector\\EdgeCases::partialMatches might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            24,
        ],
        [
            'Parameter $apiToken in Tests\\Fixtures\\Detector\\EdgeCases::partialMatches might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            24,
        ],
        [
            'Parameter $Password in Tests\\Fixtures\\Detector\\EdgeCases::caseVariations might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            30,
        ],
        [
            'Parameter $SECRET in Tests\\Fixtures\\Detector\\EdgeCases::caseVariations might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            30,
        ],
        [
            'Parameter $Token in Tests\\Fixtures\\Detector\\EdgeCases::caseVariations might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            30,
        ],
        [
            'Parameter $myPassword in Tests\\Fixtures\\Detector\\EdgeCases::mixedCaseCompounds might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            36,
        ],
        [
            'Parameter $userSecret in Tests\\Fixtures\\Detector\\EdgeCases::mixedCaseCompounds might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            36,
        ],
        [
            'Parameter $appToken in Tests\\Fixtures\\Detector\\EdgeCases::mixedCaseCompounds might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            36,
        ],
        [
            'Parameter $passwordless in Tests\\Fixtures\\Detector\\EdgeCases::falsePositives might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            42,
        ],
        [
            'Parameter $secretion in Tests\\Fixtures\\Detector\\EdgeCases::falsePositives might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            42,
        ],
        [
            'Parameter $password in Tests\\Fixtures\\Detector\\EdgeCases::multiplePasswords might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            49,
        ],
        [
            'Parameter $confirmPassword in Tests\\Fixtures\\Detector\\EdgeCases::multiplePasswords might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            49,
        ],
        [
            'Parameter $oldPassword in Tests\\Fixtures\\Detector\\EdgeCases::multiplePasswords might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            49,
        ],
        [
            'Parameter $password123 in Tests\\Fixtures\\Detector\\EdgeCases::unusualCases might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            55,
        ],
        [
            'Parameter $password_hash in Tests\\Fixtures\\Detector\\EdgeCases::unusualCases might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            55,
        ],
        [
            'Parameter $secret in Tests\\Fixtures\\Detector\\EdgeCases::privateMethod might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            61,
        ],
        [
            'Parameter $token in Tests\\Fixtures\\Detector\\EdgeCases::protectedMethod might contain sensitive information. Add the #[\\SensitiveParameter] attribute or ignore with `@phpstan-ignore sensitiveParameter.missing`.',
            66,
        ],
    ]);
});
