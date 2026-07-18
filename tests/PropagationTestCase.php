<?php

declare(strict_types=1);

namespace Tests;

use BuiltFast\Rules\SensitiveParameterPropagationRule;
use PHPStan\Testing\RuleTestCase;

/**
 * @extends RuleTestCase<SensitiveParameterPropagationRule>
 */
abstract class PropagationTestCase extends RuleTestCase
{
    protected SensitiveParameterPropagationRule $rule;

    protected function getRule(): SensitiveParameterPropagationRule
    {
        return $this->rule ?? new SensitiveParameterPropagationRule($this->createReflectionProvider());
    }
}
