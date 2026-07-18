<?php

declare(strict_types=1);

namespace Tests\Types;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPStan\Testing\TypeInferenceTestCase;

final class SensitiveParameterValueTypesTest extends TypeInferenceTestCase
{
    /**
     * @return iterable<mixed>
     */
    public static function dataFileAsserts(): iterable
    {
        yield from self::gatherAssertTypes(__DIR__.'/../Fixtures/Types/SensitiveParameterValueTypes.php');
    }

    /**
     * @return string[]
     */
    public static function getAdditionalConfigFiles(): array
    {
        return [__DIR__.'/../../extension.neon'];
    }

    /**
     * @param  mixed  ...$args
     */
    #[DataProvider('dataFileAsserts')]
    public function testFileAsserts(string $assertType, string $file, ...$args): void
    {
        $this->assertFileAsserts($assertType, $file, ...$args);
    }
}
