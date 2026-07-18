<?php

declare(strict_types=1);

namespace Tests;

use LycheeOrg\PHPStan\Rules\SensitiveParameterStorageRule;
use PHPStan\Testing\RuleTestCase;

/**
 * @extends RuleTestCase<SensitiveParameterStorageRule>
 */
abstract class StorageTestCase extends RuleTestCase
{
    protected SensitiveParameterStorageRule $rule;

    protected function getRule(): SensitiveParameterStorageRule
    {
        return $this->rule ?? new SensitiveParameterStorageRule();
    }
}
