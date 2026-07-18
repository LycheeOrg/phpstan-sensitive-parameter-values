<?php

declare(strict_types=1);

namespace LycheeOrg\PHPStan\Rules;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\CallLike;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\AttributeReflection;
use PHPStan\Reflection\ExtendedParameterReflection;
use PHPStan\Reflection\ExtendedParametersAcceptor;
use PHPStan\Reflection\ParametersAcceptorSelector;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * PHPStan rule that ensures sensitivity is propagated through the call graph.
 *
 * When a function or method parameter is marked with #[\SensitiveParameter]
 * and is passed unmodified as an argument to a callee, the callee's
 * corresponding parameter must be marked as sensitive too (either directly,
 * or through a function-level attribute). Otherwise the value stops being
 * protected the moment it enters the callee's stack frame: an exception
 * thrown from inside the callee would expose it in plaintext.
 *
 * Only simple, unmodified pass-through arguments (a bare `$variable` matching
 * a sensitive parameter of the enclosing function/method) are detected.
 * Values that are transformed or wrapped before being passed on are not
 * tracked. Reassignment is only partially detected: if PHPStan can prove the
 * variable now holds a literal/constant value at the call site, it is no
 * longer treated as the original parameter; reassignment to another
 * non-constant expression of the same type is not detected.
 *
 * @implements Rule<CallLike>
 */
final class SensitiveParameterPropagationRule implements Rule
{
    public function __construct(private ReflectionProvider $reflectionProvider)
    {
    }

    public function getNodeType(): string
    {
        return CallLike::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (
            ! $node instanceof New_
            && ! $node instanceof MethodCall
            && ! $node instanceof NullsafeMethodCall
            && ! $node instanceof StaticCall
            && ! $node instanceof FuncCall
        ) {
            return [];
        }

        $callerFunction = $scope->getFunction();
        if ($callerFunction === null) {
            return [];
        }

        $callerParams = $callerFunction->getParameters();
        if ($callerParams === []) {
            return [];
        }

        $callerFunctionProtected = $this->hasSensitiveAttribute($callerFunction->getAttributes());

        $callee = $this->resolveCallee($node, $scope);
        if ($callee === null) {
            return [];
        }

        [$calleeAttributes, $calleeParams] = $callee;
        if ($calleeParams === []) {
            return [];
        }

        $calleeFunctionProtected = $this->hasSensitiveAttribute($calleeAttributes);

        $errors = [];

        foreach ($node->getArgs() as $position => $arg) {
            if (! $arg->value instanceof Variable || ! is_string($arg->value->name)) {
                continue;
            }

            $callerParam = $this->findParameterByName($callerParams, $arg->value->name);
            if ($callerParam === null) {
                continue;
            }

            if (! $callerFunctionProtected && ! $this->hasSensitiveAttribute($callerParam->getAttributes())) {
                continue;
            }

            if ($scope->getVariableType($arg->value->name)->isConstantValue()->yes()) {
                // The variable has been reassigned to a literal/constant value
                // and no longer certainly holds the original sensitive value.
                continue;
            }

            $calleeParam = $this->resolveCalleeParameter($calleeParams, $arg, $position);
            if ($calleeParam === null) {
                continue;
            }

            if ($calleeFunctionProtected || $this->hasSensitiveAttribute($calleeParam->getAttributes())) {
                continue;
            }

            $errors[] = RuleErrorBuilder::message(sprintf(
                'Parameter $%s is marked #[\\SensitiveParameter] but is passed to a parameter ($%s) that is not itself marked with #[\\SensitiveParameter]. Add the attribute there too or ignore with `@phpstan-ignore sensitiveParameter.propagation`.',
                $callerParam->getName(),
                $calleeParam->getName(),
            ))
                ->identifier('sensitiveParameter.propagation')
                ->build();
        }

        return $errors;
    }

    /**
     * @return array{0: AttributeReflection[], 1: ExtendedParameterReflection[]}|null
     */
    private function resolveCallee(CallLike $node, Scope $scope): ?array
    {
        if ($node instanceof New_) {
            $type = $scope->getType($node);
            if (! $type->isObject()->yes() || ! $type->hasMethod('__construct')->yes()) {
                return null;
            }

            $method = $type->getMethod('__construct', $scope);
            $variant = $this->selectVariant($scope, $node, $method->getVariants(), $method->getNamedArgumentsVariants());

            return $variant === null ? null : [$method->getAttributes(), $variant->getParameters()];
        }

        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
            if (! $node->name instanceof Node\Identifier) {
                return null;
            }

            $type = $scope->getType($node->var);
            if (! $type->isObject()->yes()) {
                return null;
            }

            $methodName = $node->name->toString();
            if (! $type->hasMethod($methodName)->yes()) {
                return null;
            }

            $method = $type->getMethod($methodName, $scope);
            $variant = $this->selectVariant($scope, $node, $method->getVariants(), $method->getNamedArgumentsVariants());

            return $variant === null ? null : [$method->getAttributes(), $variant->getParameters()];
        }

        if ($node instanceof StaticCall) {
            if (! $node->name instanceof Node\Identifier) {
                return null;
            }

            $type = $node->class instanceof Node\Name
                ? $scope->resolveTypeByName($node->class)
                : $scope->getType($node->class);

            if (! $type->isObject()->yes()) {
                return null;
            }

            $methodName = $node->name->toString();
            if (! $type->hasMethod($methodName)->yes()) {
                return null;
            }

            $method = $type->getMethod($methodName, $scope);
            $variant = $this->selectVariant($scope, $node, $method->getVariants(), $method->getNamedArgumentsVariants());

            return $variant === null ? null : [$method->getAttributes(), $variant->getParameters()];
        }

        if (! $node instanceof FuncCall || ! $node->name instanceof Node\Name) {
            return null;
        }

        if (! $this->reflectionProvider->hasFunction($node->name, $scope)) {
            return null;
        }

        $function = $this->reflectionProvider->getFunction($node->name, $scope);
        $variant = $this->selectVariant($scope, $node, $function->getVariants(), $function->getNamedArgumentsVariants());

        return $variant === null ? null : [$function->getAttributes(), $variant->getParameters()];
    }

    /**
     * Picks the variant matching the actual call-site arguments (handling
     * overloads and named-argument variants) instead of blindly assuming the
     * first declared variant is the right one.
     *
     * @param  ExtendedParametersAcceptor[]  $variants
     * @param  ExtendedParametersAcceptor[]|null  $namedArgumentsVariants
     */
    private function selectVariant(Scope $scope, CallLike $node, array $variants, ?array $namedArgumentsVariants): ?ExtendedParametersAcceptor
    {
        if ($variants === []) {
            return null;
        }

        $selected = ParametersAcceptorSelector::selectFromArgs($scope, $node->getArgs(), $variants, $namedArgumentsVariants);

        return $selected instanceof ExtendedParametersAcceptor ? $selected : null;
    }

    /**
     * @param  ExtendedParameterReflection[]  $params
     */
    private function findParameterByName(array $params, string $name): ?ExtendedParameterReflection
    {
        foreach ($params as $param) {
            if ($param->getName() === $name) {
                return $param;
            }
        }

        return null;
    }

    /**
     * @param  ExtendedParameterReflection[]  $calleeParams
     */
    private function resolveCalleeParameter(array $calleeParams, Arg $arg, int $position): ?ExtendedParameterReflection
    {
        if ($arg->name instanceof Node\Identifier) {
            $named = $this->findParameterByName($calleeParams, $arg->name->toString());

            return $named ?? $this->variadicParameter($calleeParams);
        }

        return $calleeParams[$position] ?? $this->variadicParameter($calleeParams);
    }

    /**
     * @param  ExtendedParameterReflection[]  $calleeParams
     */
    private function variadicParameter(array $calleeParams): ?ExtendedParameterReflection
    {
        $lastParam = $calleeParams[count($calleeParams) - 1] ?? null;

        return ($lastParam !== null && $lastParam->isVariadic()) ? $lastParam : null;
    }

    /**
     * @param  AttributeReflection[]  $attributes
     */
    private function hasSensitiveAttribute(array $attributes): bool
    {
        foreach ($attributes as $attribute) {
            $name = $attribute->getName();
            if ($name === 'SensitiveParameter' || $name === '\\SensitiveParameter') {
                return true;
            }
        }

        return false;
    }
}
