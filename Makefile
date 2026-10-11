PYTHON ?= .venv/bin/python

.PHONY: build check compile format help install lint

check: lint compile build

install:
	$(PYTHON) -m pip install .

lint:
	$(PYTHON) -m ruff check src

format:
	$(PYTHON) -m ruff format src

compile:
	$(PYTHON) -m compileall -q src

build:
	$(PYTHON) -m pip wheel --no-build-isolation --no-deps --wheel-dir dist .

help:
	$(PYTHON) -m threattrace.cli.ops --help
