.PHONY: setup lint test format clean run-example

setup:
	poetry install

lint:
	poetry run ruff check .
	poetry run mypy isecure_client tests

lint-fix:
	poetry run ruff check --fix .

format:
	poetry run ruff format .
	poetry run isort .

test:
	PYTHONPATH=. poetry run pytest -v

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__ dist build

run-example:
	poetry run python examples/full_workflow.py
