# GuardIntent Project Plan (v1)

## MVP
- Parse JSONL and CSV logs
- Load IOC feeds from TXT and JSON
- Run IOC/rule detections with risk scoring
- Generate Markdown and JSON incident reports

## CLI Commands
- `guardintent scan`
- `guardintent parse`
- `guardintent iocs`
- `guardintent rules`

## Done Criteria
- `scan` produces timestamped reports in `reports/`
- At least three incidents are produced by sample data
- Unit tests cover parser, IOC, and scan flow
