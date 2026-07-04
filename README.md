# Sentinel

CI/CD release guardian that turns deterministic engineering evidence into an
explainable release-risk assessment.

Sentinel is a pre-1.0 CLI. Its mock provider enables end-to-end testing before
the production LLM integration is added.

## How it works

```text
tests and scanners -> normalized evidence -> policy and risk
                                      |
                                      +-> mock/LLM explanation -> report
```

Deterministic checks own pass/fail decisions. Analysis providers explain the
evidence but cannot override failed checks, write repositories, or deploy.

## Run

```sh
python -m pip install --editable .
```

Collect deterministic evidence from an allowlisted check plan:

```sh
sentinel collect \
  --plan plan.json \
  --workspace . \
  --output evidence.json
```

Create the assessment:

```sh
sentinel assess \
  --provider mock \
  --input evidence.json \
  --json-output assessment.json \
  --markdown-output assessment.md
```

Run tests with:

```sh
python -m unittest discover --start-directory tests --verbose
```

Backend Lab owns the project-specific configuration, architecture, and roadmap.
Sentinel runs in CI and is not a persistent Docker Compose service.
