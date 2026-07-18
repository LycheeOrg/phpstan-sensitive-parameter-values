<?php

declare(strict_types=1);

namespace Tests\Fixtures\Storage;

use SensitiveParameter;
use SensitiveParameterValue;

/**
 * Test fixture for SensitiveParameterStorageRule: sensitive values must be
 * wrapped in \SensitiveParameterValue before being stored in a property.
 */
final class StorageCases
{
    private string $password;

    private SensitiveParameterValue $wrappedPassword;

    private static string $staticSecret;

    public function __construct(
        // Promoted property receiving a raw sensitive value - should trigger warning
        #[SensitiveParameter] private readonly string $promotedPassword,
        // Promoted property already typed as \SensitiveParameterValue - should NOT trigger warning
        #[SensitiveParameter] private readonly SensitiveParameterValue $promotedWrappedPassword,
        // Promoted property that isn't sensitive at all - should NOT trigger warning
        private readonly string $promotedUsername,
    ) {
    }

    // Sensitive parameter assigned directly to a property, unwrapped - should trigger warning
    public function unwrappedAssignmentIsFlagged(#[SensitiveParameter] string $password): void
    {
        $this->password = $password;
    }

    // Sensitive parameter wrapped in \SensitiveParameterValue before storage - should NOT trigger warning
    public function wrappedAssignmentIsNotFlagged(#[SensitiveParameter] string $password): void
    {
        $this->wrappedPassword = new SensitiveParameterValue($password);
    }

    // Sensitive parameter wrapped in \SensitiveParameterValue but unwrapped via getValue() before storage - should trigger warning
    public function wrappedAssignmentIsFlagged(SensitiveParameterValue $password): void
    {
        $this->password = $password->getValue();
    }

    // Function-level SensitiveParameter also makes $password sensitive, so unwrapped storage should still trigger warning
    #[SensitiveParameter]
    public function functionLevelAttributeIsAlsoDetected(string $password): void
    {
        $this->password = $password;
    }

    // Sensitive parameter assigned directly to a static property, unwrapped - should trigger warning
    public function unwrappedStaticAssignmentIsFlagged(#[SensitiveParameter] string $secret): void
    {
        self::$staticSecret = $secret;
    }

    // Non-sensitive parameter stored directly - should NOT trigger warning
    public function nonSensitiveAssignmentIsNotFlagged(string $username): void
    {
        $this->password = $username;
    }

    // Sensitive parameter is transformed before storage, so it's no longer a bare variable pass-through - should NOT trigger warning
    public function transformedValueIsNotFlagged(#[SensitiveParameter] string $password): void
    {
        $this->password = mb_trim($password);
    }

    // Sensitive parameter is unwrapped before storage, but the warning is ignored - should NOT trigger warning
    public function unwrappedAssignmentWithIgnore(SensitiveParameterValue $password): void
    {
        // Unwrap the value.
        $password_temp = $password->getValue();
        // We now store the unwrapped value, this is voluntary unsafe and the developer is aware of the risk, so we ignore the warning.
        $this->password = $password_temp;
    }
}
