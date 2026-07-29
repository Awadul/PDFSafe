.DEFAULT_GOAL := help
PY ?= python
VENV ?= .venv

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup ----
.PHONY: install
install: ## Create a venv and install everything (desktop + build + dev tools)
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e ".[dev]"
	-$(VENV)/bin/pre-commit install

.PHONY: install-desktop
install-desktop: ## Install only what the shipped application needs
	$(PY) -m pip install -e ".[desktop]"

# ----------------------------------------------------------------- run -----
.PHONY: run
run: ## Launch the desktop application
	$(PY) -m pdfsafe.desktop.app

.PHONY: scan
scan: ## Scan a file from the CLI: make scan f=path/to/file.pdf
	$(PY) -m pdfsafe.cli scan "$(f)"

# --------------------------------------------------------------- quality ---
.PHONY: lint
lint: ## Ruff + mypy
	ruff check src tests
	ruff format --check src tests
	mypy src

.PHONY: fmt
fmt: ## Auto-format and fix
	ruff format src tests
	ruff check --fix src tests

.PHONY: test
test: ## Run the test suite
	pytest

.PHONY: test-fast
test-fast: ## Skip the GUI suite (no Qt needed)
	pytest -m "not gui"

# ----------------------------------------------------------------- ship ----
.PHONY: icons
icons: ## Render packaging/assets/pdfsafe.ico
	$(PY) tools/make_icons.py --output packaging/assets

.PHONY: build
build: ## Build the Windows executable and installer (PowerShell)
	powershell -ExecutionPolicy Bypass -File packaging/build.ps1

.PHONY: build-exe
build-exe: ## Build the executable only
	powershell -ExecutionPolicy Bypass -File packaging/build.ps1 -SkipInstaller

# ---------------------------------------------------------------- misc -----
.PHONY: clean
clean: ## Remove build artefacts and caches
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
