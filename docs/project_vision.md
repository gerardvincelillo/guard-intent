# Project Vision

This document keeps the direction for `guard-intent` explicit while the broader defensive repo family is being consolidated.

## Repository Identity

- Repo: `guard-intent`
- Working title: `GuardIntent`
- Current repository type: security triage and reporting framework
- Current role: source of reusable scoring, triage, and report patterns

## Current Framing

GuardIntent is strongest when it behaves like a readable correlation and incident-packaging engine.

Its most reusable value is in:

- normalized evidence handling
- score-to-severity translation
- grouped incidents
- drift comparison between reports
- Markdown/JSON/HTML report generation

Those patterns are important on their own, but they also map well into HostIntent’s future analysis and reporting layers.

## Strategic Focus

- Keep GuardIntent useful as a transparent triage engine.
- Favor reporting and correlation quality over feature sprawl.
- Treat this repo as a pattern source for HostIntent’s future reasoning and reporting layers.

## Practical Direction

Near-term work in this repo should focus on:

- improving incident grouping quality
- keeping report outputs clean and explainable
- tightening integration and enrichment boundaries
- documenting where its abstractions can transfer into HostIntent later

## Planning Rule

If a new GuardIntent feature is really endpoint-state reasoning for local hosts, that belongs in HostIntent instead of growing overlap here.
