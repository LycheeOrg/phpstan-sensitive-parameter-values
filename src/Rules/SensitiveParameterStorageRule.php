<?php

declare(strict_types=1);

namespace BuiltFast\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticPropertyFetch;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\FunctionLike;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeFinder;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * PHPStan rule that ensures values coming from #[\SensitiveParameter]
 * parameters are never stored in their raw form.
 *
 * Once a value is known to be sensitive, saving it directly into an object or
 * static property defeats the purpose of marking it sensitive: anything
 * reading that property (var_dump, serialization, error reporting, ...) will
 * expose the raw value again. The value should instead be wrapped in
 * \SensitiveParameterValue before being stored.
 *
 * This rule flags three situations:
 *
 * 1. A sensitive parameter is assigned directly to a property:
 *    `$this->password = $password;` instead of
 *    `$this->password = new \SensitiveParameterValue($password);`
 * 2. A sensitive parameter is promoted directly into a property
 *    (constructor property promotion), which performs the raw assignment
 *    implicitly and offers no place to wrap the value.
 * 3. A parameter already typed as \SensitiveParameterValue is unwrapped via
 *    `->getValue()` before being stored: `$this->password =
 *    $password->getValue();` instead of storing the wrapped value itself.
 *
 * Only direct, unmodified assignments of a bare `$variable` (or a bare
 * `->getValue()` call on one) are detected. Values that are transformed
 * before being stored are not tracked.
 *
 * @implements Rule<FunctionLike>
 */
final class SensitiveParameterStorageRule implements Rule
{
    public function getNodeType(): string
    {
        return FunctionLike::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (! $node instanceof ClassMethod && ! $node instanceof Function_) {
            return [];
        }

        $functionProtected = $this->hasSensitiveAttributeGroups($node->attrGroups);

        /** @var array<string, true> $sensitiveParamNames */
        $sensitiveParamNames = [];
        /** @var array<string, true> $wrappedParamNames */
        $wrappedParamNames = [];
        $errors = [];

        foreach ($node->getParams() as $param) {
            if (! $param->var instanceof Variable || ! is_string($param->var->name)) {
                continue;
            }

            if ($this->isSensitiveParameterValueType($param->type)) {
                $wrappedParamNames[$param->var->name] = true;
            }

            $paramSensitive = $functionProtected || $this->hasSensitiveAttributeGroups($param->attrGroups);
            if (! $paramSensitive) {
                continue;
            }

            $sensitiveParamNames[$param->var->name] = true;

            if ($param->flags !== 0 && ! $this->isSensitiveParameterValueType($param->type)) {
                $errors[] = RuleErrorBuilder::message(sprintf(
                    'Promoted property $%s receives a sensitive value but assigns it directly, bypassing \\SensitiveParameterValue. Declare the property without promotion and assign `new \\SensitiveParameterValue($%s)` in the constructor body, or ignore with `@phpstan-ignore sensitiveParameter.unwrappedPromotion`.',
                    $param->var->name,
                    $param->var->name,
                ))
                    ->identifier('sensitiveParameter.unwrappedPromotion')
                    ->line($param->getStartLine())
                    ->build();
            }
        }

        if (($sensitiveParamNames === [] && $wrappedParamNames === []) || $node->getStmts() === null) {
            return $errors;
        }

        foreach ((new NodeFinder())->findInstanceOf($node->getStmts(), Assign::class) as $assign) {
            foreach ($this->checkAssign($assign, $sensitiveParamNames, $wrappedParamNames) as $error) {
                $errors[] = $error;
            }
        }

        return $errors;
    }

    /**
     * @param  array<string, true>  $sensitiveParamNames
     * @param  array<string, true>  $wrappedParamNames
     * @return IdentifierRuleError[]
     */
    private function checkAssign(Assign $assign, array $sensitiveParamNames, array $wrappedParamNames): array
    {
        if (! $assign->var instanceof PropertyFetch && ! $assign->var instanceof StaticPropertyFetch) {
            return [];
        }

        if (
            $assign->expr instanceof Variable
            && is_string($assign->expr->name)
            && isset($sensitiveParamNames[$assign->expr->name])
        ) {
            return [
                RuleErrorBuilder::message(sprintf(
                    '$%s is a sensitive value and must be wrapped in \\SensitiveParameterValue before being stored, e.g. `... = new \\SensitiveParameterValue($%s);`. Ignore with `@phpstan-ignore sensitiveParameter.unwrappedStorage`.',
                    $assign->expr->name,
                    $assign->expr->name,
                ))
                    ->identifier('sensitiveParameter.unwrappedStorage')
                    ->line($assign->getStartLine())
                    ->build(),
            ];
        }

        if (
            $assign->expr instanceof MethodCall
            && $assign->expr->name instanceof Node\Identifier
            && $assign->expr->name->toString() === 'getValue'
            && $assign->expr->var instanceof Variable
            && is_string($assign->expr->var->name)
            && isset($wrappedParamNames[$assign->expr->var->name])
        ) {
            return [
                RuleErrorBuilder::message(sprintf(
                    '$%s->getValue() unwraps a \\SensitiveParameterValue and must not be stored raw. Store $%s itself instead of calling getValue() on it. Ignore with `@phpstan-ignore sensitiveParameter.unwrappedGetValue`.',
                    $assign->expr->var->name,
                    $assign->expr->var->name,
                ))
                    ->identifier('sensitiveParameter.unwrappedGetValue')
                    ->line($assign->getStartLine())
                    ->build(),
            ];
        }

        return [];
    }

    /**
     * @param  Node\AttributeGroup[]  $attrGroups
     */
    private function hasSensitiveAttributeGroups(array $attrGroups): bool
    {
        foreach ($attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                $attrName = $attr->name->toString();
                if (
                    $attrName === 'SensitiveParameter' ||
                    $attrName === '\SensitiveParameter' ||
                    mb_strpos($attrName, 'SensitiveParameter') !== false
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isSensitiveParameterValueType(?Node $type): bool
    {
        if ($type instanceof Node\NullableType) {
            $type = $type->type;
        }

        if ($type instanceof Node\UnionType) {
            foreach ($type->types as $subType) {
                if ($this->isSensitiveParameterValueType($subType)) {
                    return true;
                }
            }

            return false;
        }

        if ($type instanceof Node\Name) {
            $name = $type->toString();

            return $name === 'SensitiveParameterValue' || $name === '\\SensitiveParameterValue';
        }

        return false;
    }
}
