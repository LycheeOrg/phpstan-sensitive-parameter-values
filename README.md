# PHPStan SensitiveParameter Detector

[![CI](https://github.com/LycheeOrg/phpstan-sensitive-parameter/workflows/CI/badge.svg)](https://github.com/LycheeOrg/phpstan-sensitive-parameter/actions)
<!-- [![Latest Stable Version](https://poser.pugx.org/LycheeOrg/phpstan-sensitive-parameter/v/stable)](https://packagist.org/packages/LycheeOrg/phpstan-sensitive-parameter) -->
<!-- [![Total Downloads](https://poser.pugx.org/LycheeOrg/phpstan-sensitive-parameter/downloads)](https://packagist.org/packages/LycheeOrg/phpstan-sensitive-parameter) -->
[![License](https://poser.pugx.org/LycheeOrg/phpstan-sensitive-parameter/license)](https://packagist.org/packages/LycheeOrg/phpstan-sensitive-parameter)
[![OpenSSF Scorecard][ossf-shield]](https://securityscorecards.dev/viewer/?uri=github.com/LycheeOrg/Lychee-Facial-Recognition)

A PHPStan extension that detects parameters that might contain sensitive information and should be marked with the `#[\SensitiveParameter]` attribute (added in PHP 8.2+).

## About SensitiveParameter

The `#[\SensitiveParameter]` attribute was introduced in PHP 8.2 to mark sensitive data that should be hidden from stack traces and debugging output. This extension helps you identify parameters that should use this attribute for better security.

Learn more: [PHP RFC: Redact parameters in back traces](https://wiki.php.net/rfc/redact_parameters_in_back_traces)

## Requirements

- PHP 8.2 or higher
- PHPStan 2.0 or higher

## Installation

```bash
composer require --dev built-fast/phpstan-sensitive-parameter
```

## Usage

The extension will be automatically registered if you use [PHPStan's extension installer](https://github.com/phpstan/extension-installer).

Alternatively, include the extension in your PHPStan configuration:

```neon
includes:
    - vendor/built-fast/phpstan-sensitive-parameter/extension.neon
```

## Typed `SensitiveParameterValue`

PHP's built-in `\SensitiveParameterValue::getValue()` is natively typed as
`mixed`, so calling it normally loses type information. This extension ships
a PHPStan stub that declares `SensitiveParameterValue` as generic over the
type of the value passed to its constructor, so PHPStan can narrow the
return type of `getValue()` accordingly:

```php
function example(string $password): void {
    $sensitive = new \SensitiveParameterValue($password);

    // PHPStan now sees $sensitive as SensitiveParameterValue<string>
    // and infers the return type of getValue() as string, not mixed.
    $plain = $sensitive->getValue();
}
```

This is most useful when inspecting exception traces, where PHP replaces
sensitive arguments with `SensitiveParameterValue` instances:

```php
foreach ($exception->getTrace() as $frame) {
    foreach ($frame['args'] ?? [] as $arg) {
        if ($arg instanceof \SensitiveParameterValue) {
            // getValue() keeps the original argument's type.
            $original = $arg->getValue();
        }
    }
}
```

## Propagating sensitivity through the call graph

Marking a parameter `#[\SensitiveParameter]` only protects that one call
frame. If the value is then forwarded unchanged into a callee whose
corresponding parameter is *not* marked sensitive, protection stops there: an
exception thrown from inside the callee will still expose the value in
plaintext.

```php
class AuthService {
    // $password is marked sensitive here...
    public function authenticate(#[\SensitiveParameter] string $password): bool {
        // ...but login()'s parameter isn't, so the value is unprotected
        // as soon as it enters login()'s stack frame.
        return $this->login($password);
    }

    public function login(string $password): bool {
        // ...
    }
}
```

`SensitiveParameterPropagationRule` flags `login()`'s `$password`
in this example, with:

```
Parameter $password is marked #[\SensitiveParameter] but is passed to a
parameter ($password) that is not itself marked with #[\SensitiveParameter].
Add the attribute there too or ignore with
`@phpstan-ignore sensitiveParameter.propagation`.
```

This is detected across method calls, static calls, constructors, and plain
function calls. Only simple, unmodified pass-through arguments (a bare
`$variable` matching a sensitive parameter of the enclosing function/method)
are tracked — values that are transformed, wrapped, or reassigned before
being passed on are not.

## Storing sensitive values safely

Marking a parameter sensitive prevents it from leaking through stack traces,
but that protection is undone if the raw value is then saved into a property
— anything that inspects, dumps, or serializes the object exposes it again.
`SensitiveParameterStorageRule` requires sensitive values to be wrapped in
`\SensitiveParameterValue` before being stored:

```php
class Credentials {
    private string $password; // ❌ raw storage

    public function __construct(#[\SensitiveParameter] string $password) {
        $this->password = $password; // flagged: sensitiveParameter.unwrappedStorage
    }
}
```

```php
class Credentials {
    private \SensitiveParameterValue $password; // ✅ wrapped storage

    public function __construct(#[\SensitiveParameter] string $password) {
        $this->password = new \SensitiveParameterValue($password);
    }
}
```

Constructor property promotion is also checked, since promotion assigns the
raw value directly with no place to wrap it:

```php
class Credentials {
    public function __construct(
        // flagged: sensitiveParameter.unwrappedPromotion
        #[\SensitiveParameter] private readonly string $password,
    ) {}
}
```

A value that's already wrapped is also checked: unwrapping it via
`->getValue()` right before storing defeats the point of wrapping it in the
first place, so it's flagged too:

```php
class Credentials {
    private string $password;

    public function __construct(\SensitiveParameterValue $password) {
        // flagged: sensitiveParameter.unwrappedGetValue
        $this->password = $password->getValue();
    }
}
```

Only direct, unmodified assignments of a bare `$variable` (or a bare
`->getValue()` call on one) into a property are detected; values transformed
before being stored are not tracked.

## What it detects

The rule detects parameters with names containing common sensitive keywords:

- Authentication: `password`, `secret`, `token`, `credential`, `auth`, `bearer`
- API Security: `apikey` (matches `apisecret`, `clientsecret` via `secret`)
- Financial: `credit`, `card`, `ccv`, `cvv`, `ssn`, `pin`
- Security: `private`, `signature`, `hash`, `salt`, `nonce`, `otp`, `passcode`, `csrf`

Note: Due to substring matching, `secret` catches `apisecret`/`clientsecret` and `token` catches `refreshtoken`/`accesstoken`.

It works with:

- Regular functions
- Class methods (public, private, protected, static)
- Constructors
- Case-insensitive matching (`Password`, `SECRET`, etc.)
- Partial matches (`userPassword`, `secretKey`, etc.)

## Examples

### ❌ Will trigger warnings:

```php
function login(string $username, string $password) {
    // Parameter $password should use #[\SensitiveParameter]
}

class AuthService {
    public function setCredentials(string $apikey, string $secret) {
        // Both $apikey and $secret should be marked sensitive
    }
}
```

### ✅ Properly protected:

```php
// Function-level protection
#[\SensitiveParameter]
function login(string $username, string $password) {
    // All parameters are protected
}

// Parameter-level protection
function authenticate(
    string $username,
    #[\SensitiveParameter] string $password
) {
    // Only $password is protected
}

// Mixed protection
class AuthService {
    public function verify(
        #[\SensitiveParameter] string $token,
        string $userId,
        string $apikey  // This will still trigger a warning
    ) {
        // $token is protected, $apikey needs protection
    }
}
```

## Advanced Configuration

To use custom sensitive keywords instead of the defaults, override the service:

```neon
includes:
    - vendor/built-fast/phpstan-sensitive-parameter/extension.neon

services:
    # Override the default service with custom keywords
    -
        class: BuiltFast\Rules\SensitiveParameterDetectorRule
        arguments:
            - ['password', 'apikey', 'token', 'banking', 'medical']  # Your custom keywords
        tags:
            - phpstan.rules.rule
```

This completely replaces the default keyword list with your own.

## Suppressing Warnings

You can suppress warnings using PHPStan's ignore comments:

```php
// @phpstan-ignore-next-line sensitiveParameter.missing
function legacyFunction(string $password) {
    // Legacy code that cannot be updated
}

// @phpstan-ignore-next-line sensitiveParameter.missing
function anotherLegacyFunction(string $secret) {
    // Another legacy function
}

function modernFunction(string $password): void // @phpstan-ignore-line sensitiveParameter.missing
{
    // Function with inline ignore comment
}
```

### Constructor Parameters

Due to a PHPStan limitation, ignore comments for constructor parameters must
be placed before the constructor:

```php
// @phpstan-ignore-next-line sensitiveParameter.missing
public function __construct(
    private readonly SomeService $serviceWithSensitiveKeywordInName
) {}
```

**Note:** This ignores ALL parameter warnings for that constructor. For
functions with multiple parameters where only some are false positives,
consider renaming the problematic parameter to avoid the sensitive keyword
match.

## Common Issues

### False Positives

The rule uses substring matching, which can occasionally trigger false
positives:

- `$appInstall` triggers due to "install" containing "pin"
- `$passwordService` triggers due to containing "password"
- `$signatureMethod` triggers due to containing "signature"

For these cases, use ignore comments as shown above or consider renaming
parameters to be more specific (e.g., `$applicationToInstall`, `$authService`,
`$verificationMethod`).

## Reporting Issues

Found a bug or have a feature request? Please [report it on GitHub](https://github.com/built-fast/phpstan-sensitive-parameter/issues).

When reporting issues, please include:

- PHP version
- PHPStan version
- Code sample that demonstrates the issue
- Expected vs actual behavior

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

**Development setup:**

```bash
git clone https://github.com/built-fast/phpstan-sensitive-parameter.git
cd phpstan-sensitive-parameter
composer install
```

**Running tests:**

```bash
vendor/bin/pest             # Run tests
vendor/bin/phpstan analyze  # Static analysis
vendor/bin/pint --test      # Code style check
```

## License

MIT License - see [`LICENSE`](./LICENSE) for details.

[ossf-shield]: https://api.securityscorecards.dev/projects/github.com/LycheeOrg/phpstan-sensitive-parameter-value/badge
