# Sentinel

The Python release-analysis CLI used by Backend Lab CI. Backend Lab owns its
project policy, workflow integration,
[architecture](https://github.com/mateoRc/lab/blob/main/content/docs/architecture/sentinel.md),
and [roadmap](https://github.com/mateoRc/lab/blob/main/content/docs/roadmaps/sentinel.md).

## Develop

```sh
python -m pip install --editable .
python -m unittest discover --start-directory tests --verbose
```

Collect evidence:

```sh
sentinel collect \
  --plan plan.json \
  --workspace . \
  --output evidence.json
```

Calculate affected checks:

```sh
sentinel impact \
  --changes changes.json \
  --rules sentinel-impact.json \
  --output impact.json
```

Create an assessment:

```sh
sentinel assess \
  --provider mock \
  --input evidence.json \
  --config ../lab/sentinel.yml \
  --json-output assessment.json \
  --markdown-output assessment.md
```
