# GuardIntent

GuardIntent is a CLI security automation and triage framework for SOC-style workflows. It ingests logs, correlates IOC feeds, runs rule detections, scores incidents, enriches findings, and exports incident reports.

## Implemented Capabilities

- Log parsing and normalization
  - Input: JSONL, JSON, CSV
  - Unified event schema for auth/network/process/DNS
- IOC engine
  - Input: TXT, JSON
  - IOC types: IP, domain, URL, SHA-256
  - Validation and deduplication
- Detection rules with MITRE ATT&CK mappings
  - `ioc_match`
  - `brute_force`
  - `privileged_abnormal`
  - `rare_process`
  - `lateral_movement`
- Plugin rule system
  - Load custom rules using `--plugin path/to/plugin.py`
  - Example plugin: `plugins/sample_custom_rule.py`
- Scoring and triage
  - Severity: low, medium, high, critical
  - Graph-based incident grouping with temporal window correlation
- Report generation
  - Markdown, JSON, HTML dashboard
- Report drift analysis
  - compare baseline/current JSON reports and flag regressions
- Optional enrich/export integrations
  - VirusTotal enrichment (`--enrich-vt`, API key required)
  - Webhook export (`--webhook-url`)
  - Jira issue creation (`--jira-*`)
  - Retry/backoff and rate-limit handling for external integrations
- Delivery tooling
  - Dockerfile
  - GitHub Actions CI workflow

## Project Structure

```text
GuardIntent/
|-- guard_intent/
|   |-- cli.py
|   |-- config.py
|   |-- models.py
|   |-- scoring.py
|   |-- normalize/
|   |-- iocs/
|   |-- rules/
|   |-- plugins/
|   |-- enrichment/
|   |-- integrations/
|   `-- reporting/
|-- plugins/
|   `-- sample_custom_rule.py
|-- data/
|-- reports/
|-- tests/
|-- .github/workflows/ci.yml
|-- Dockerfile
|-- config.yaml
|-- plan.md
`-- pyproject.toml
```

## Install

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

python -m pip install -U pip
python -m pip install -e .
python -m pip install pytest
```

## CLI Usage

### Full scan

```bash
guardintent scan \
  --logs data/sample_logs.jsonl \
  --iocs data/sample_iocs.txt \
  --out reports \
  --format md,json,html \
  --min-severity medium \
  --config config.yaml \
  --verbose
```

### Scan with plugin rule

```bash
guardintent scan \
  --logs data/sample_logs.jsonl \
  --iocs data/sample_iocs.txt \
  --plugin plugins/sample_custom_rule.py \
  --format json,html \
  --out reports
```

### Scan with enrichment/export integrations

```bash
guardintent scan \
  --logs data/sample_logs.jsonl \
  --iocs data/sample_iocs.txt \
  --enrich-vt \
  --vt-api-key <VT_API_KEY> \
  --webhook-url https://example.com/hook \
  --jira-url https://your-org.atlassian.net \
  --jira-user you@example.com \
  --jira-token <JIRA_API_TOKEN> \
  --jira-project-key SEC
```

### Other commands

```bash
guardintent parse --logs data/sample_logs.jsonl --out data/normalized_logs.jsonl
guardintent iocs --iocs data/sample_iocs.txt
guardintent rules --list
guardintent rules --show brute_force
guardintent compare --baseline reports/old.json --current reports/new.json --out reports/diff.json
```

## Rule Plugin Interface

A plugin module must expose a `RULES` variable containing rule classes that inherit `BaseRule`.

```python
RULES = [MyCustomRule]
```

## Severity Mapping

- `0-24`: low
- `25-49`: medium
- `50-74`: high
- `75+`: critical

## Testing

```bash
python -m pytest -q
```

## Docker

```bash
docker build -t guardintent:latest .
docker run --rm guardintent:latest --help
```

## CI

GitHub Actions workflow at `.github/workflows/ci.yml` runs tests on Python 3.10, 3.11, and 3.12.

## Current Gaps / Next Improvements

- Add ATT&CK tactic-to-technique validation against an external ATT&CK dataset.
- Add circuit-breaker behavior for repeated integration outages.
- Improve grouping precision with source-specific graph weights and confidence scores.
- Add snapshot tests for full Markdown/HTML report rendering.
- Add benchmark tests for large log files and high-cardinality IOC sets.

## Docs

- `docs/README.md`: docs index for the repository
- `docs/implementation_checklist.md`
- `docs/project_vision.md`
- `docs/stack_inventory.md`

