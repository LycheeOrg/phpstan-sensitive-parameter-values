.PHONY: help install update test test-coverage pint pint-test stan check ci clean

help:
	@echo "Available targets:"
	@echo "  install       Install composer dependencies"
	@echo "  update        Update composer dependencies"
	@echo "  test          Run the test suite (Pest)"
	@echo "  test-coverage Run the test suite with coverage report"
	@echo "  pint          Fix code style (Laravel Pint)"
	@echo "  pint-test     Check code style without fixing"
	@echo "  stan          Run static analysis (PHPStan)"
	@echo "  check         Run pint-test and stan (no tests)"
	@echo "  ci            Run test, pint-test and stan (mirrors CI)"
	@echo "  clean         Remove vendor and lock file"

install:
	composer install

update:
	composer update

test:
	vendor/bin/pest
test-coverage:
	vendor/bin/pest --coverage

pint:
	vendor/bin/pint

pint-test:
	vendor/bin/pint --test

stan:
	vendor/bin/phpstan analyze

check: pint-test stan

ci: test pint-test stan

clean:
	rm -rf vendor composer.lock
