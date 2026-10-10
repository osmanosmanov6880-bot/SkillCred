.PHONY: install test lint run demo check-env clean

install:
	python -m pip install -e '.[dev]'

test:
	python -m pytest --cov=skillcred --cov-report=term-missing

lint:
	ruff check .

run:
	uvicorn skillcred.api:app --host 127.0.0.1 --port 8000

demo:
	PYTHONPATH=. python examples/demo.py

check-env:
	python scripts/check_env.py

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov build dist *.egg-info
