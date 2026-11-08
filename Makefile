# Reproducible examples: fixed timestamp so regenerated files are byte-identical.
export SOURCE_DATE_EPOCH := 1794096000
export PYTHONDONTWRITEBYTECODE := 1
PYTHON ?= python3
TMP := $(shell mktemp -d 2>/dev/null || echo /tmp/scr-make)

.PHONY: test validate examples examples-check

test:
	$(PYTHON) -m pytest -q

validate:
	$(PYTHON) scripts/validate_skill.py

examples:
	$(PYTHON) scripts/scan_repository.py examples/vulnerable-demo --mode full -o $(TMP)/raw.json
	$(PYTHON) scripts/normalize_findings.py $(TMP)/raw.json --add examples/agent-findings.json --triage examples/triage.json -o examples/sample-report.json
	$(PYTHON) scripts/generate_report.py examples/sample-report.json -f markdown -o examples/sample-review.md
	$(PYTHON) scripts/generate_report.py examples/sample-report.json -f sarif --sarif-path-prefix examples/vulnerable-demo -o examples/sample-report.sarif

examples-check:
	$(PYTHON) scripts/scan_repository.py examples/vulnerable-demo --mode full -o $(TMP)/raw.json
	$(PYTHON) scripts/normalize_findings.py $(TMP)/raw.json --add examples/agent-findings.json --triage examples/triage.json -o $(TMP)/sample-report.json
	$(PYTHON) scripts/generate_report.py $(TMP)/sample-report.json -f markdown -o $(TMP)/sample-review.md
	$(PYTHON) scripts/generate_report.py $(TMP)/sample-report.json -f sarif --sarif-path-prefix examples/vulnerable-demo -o $(TMP)/sample-report.sarif
	diff -u examples/sample-report.json $(TMP)/sample-report.json
	diff -u examples/sample-review.md $(TMP)/sample-review.md
	diff -u examples/sample-report.sarif $(TMP)/sample-report.sarif
	@echo "examples are up to date"
