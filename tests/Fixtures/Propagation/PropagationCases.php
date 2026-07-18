<?php

declare(strict_types=1);

namespace Tests\Fixtures\Propagation;

use SensitiveParameter;

/**
 * Test fixture for SensitiveParameterPropagationRule: a parameter marked
 * #[\SensitiveParameter] that is passed unmodified into a callee must have
 * that callee's corresponding parameter marked sensitive too.
 */
final class PropagationCases
{
    // Helper callee whose parameter is NOT sensitive
    public static function nonSensitiveStaticMethod(string $secret): void
    {
    }

    // $password is marked sensitive here but forwarded into a callee whose parameter isn't - should trigger warning
    public function missingPropagationOnMethodCall(#[SensitiveParameter] string $password): void
    {
        $this->nonSensitiveMethod($password);
    }

    // $password is marked sensitive here and forwarded into a callee that is also marked sensitive - should NOT trigger warning
    public function protectedByCalleeParameterAttribute(#[SensitiveParameter] string $password): void
    {
        $this->sensitiveMethod($password);
    }

    // $password is marked sensitive here and forwarded into a callee protected via a function-level attribute - should NOT trigger warning
    public function protectedByCalleeFunctionLevelAttribute(#[SensitiveParameter] string $password): void
    {
        $this->functionLevelProtectedMethod($password);
    }

    // $password isn't marked sensitive here, so there's nothing to propagate even though the callee's parameter is sensitive - should NOT trigger warning
    public function nonSensitiveParameterIsNotFlagged(string $password): void
    {
        $this->sensitiveMethod($password);
    }

    // $password is concatenated before being passed on, so it's no longer a bare variable pass-through - should NOT trigger warning
    public function transformedValueIsNotFlagged(#[SensitiveParameter] string $password): void
    {
        $this->nonSensitiveMethod($password.'-suffix');
    }

    // $other isn't a parameter of this function at all, so there's nothing to propagate - should NOT trigger warning
    public function unrelatedLocalVariableIsNotFlagged(): void
    {
        $other = 'value';
        $this->nonSensitiveMethod($other);
    }

    // $token is marked sensitive here but forwarded into a constructor whose parameter isn't - should trigger warning
    public function missingPropagationOnConstructorCall(#[SensitiveParameter] string $token): void
    {
        new NonSensitiveConsumer($token);
    }

    // $secret is marked sensitive here but forwarded into a static call whose parameter isn't - should trigger warning
    public function missingPropagationOnStaticCall(#[SensitiveParameter] string $secret): void
    {
        self::nonSensitiveStaticMethod($secret);
    }

    // $apiKey is marked sensitive here but forwarded into a plain function whose parameter isn't - should trigger warning
    public function missingPropagationOnFunctionCall(#[SensitiveParameter] string $apiKey): void
    {
        propagationGlobalNonSensitiveFunction($apiKey);
    }

    // $secret is marked sensitive here and passed as an unknown named argument, which is
    // collected into the callee's unprotected variadic parameter - should trigger warning
    public function missingPropagationOnNamedVariadicCall(#[SensitiveParameter] string $secret): void
    {
        $this->nonSensitiveVariadicMethod(secret: $secret);
    }

    // $password is marked sensitive here but reassigned to a literal before being forwarded, so
    // it no longer provably holds the original sensitive value - should NOT trigger warning
    public function reassignedParameterIsNotFlagged(#[SensitiveParameter] string $password): void
    {
        $password = 'redacted';
        $this->nonSensitiveMethod($password);
    }

    // Helper callee whose parameter is NOT sensitive
    public function nonSensitiveMethod(string $password): void
    {
    }

    // Helper callee whose parameter IS sensitive
    public function sensitiveMethod(#[SensitiveParameter] string $password): void
    {
    }

    // Helper callee protected via a function-level attribute
    #[SensitiveParameter]
    public function functionLevelProtectedMethod(string $password): void
    {
    }

    // Helper callee whose variadic catch-all parameter is NOT sensitive
    public function nonSensitiveVariadicMethod(mixed ...$values): void
    {
    }
}

// Helper class whose constructor parameter is NOT sensitive, used by missingPropagationOnConstructorCall()
final class NonSensitiveConsumer
{
    public function __construct(string $token)
    {
    }
}

// Helper global function whose parameter is NOT sensitive, used by missingPropagationOnFunctionCall()
function propagationGlobalNonSensitiveFunction(string $apiKey): void
{
}
