# DevSecOps Pipeline - "Shift-Left" Security for a Small API

A CI/CD pipeline that automatically checks every change for security problems **before** it can be merged: unit tests, static code analysis (SAST), vulnerable dependencies (SCA), leaked secrets, Dockerfile and workflow misconfiguration, container vulnerabilities, and a runtime smoke test of the hardened container. It also produces a Software Bill of Materials (SBOM).

The pipeline protects a deliberately small Flask task-tracking API (`app/`) that is itself written with secure-coding practices, so the project shows both sides: *writing* secure code and *verifying* it automatically.

## Pipeline overview

| Stage (job) | Tool | Catches | Fails the build when |
|---|---|---|---|
| `test` | pytest + pytest-cov | Broken behaviour, regressions, untested code | a test fails or coverage < 90% |
| `sast` | Bandit | Insecure code patterns (injection, weak crypto, hard-coded secrets) | any MEDIUM+ finding |
| `dependencies` | pip-audit | Known-vulnerable Python packages (SCA) | any known vulnerability |
| `secrets` | Gitleaks | API keys / tokens committed to the repo or its history | any secret detected |
| `config-scan` | Checkov | Insecure Dockerfile and GitHub Actions settings | any failed check |
| `container` | Hadolint, Trivy | Dockerfile smells; OS/library CVEs in the final image | warning-level lint, or HIGH/CRITICAL fixable CVEs |
| `container` | Trivy (CycloneDX) | - (produces an SBOM artifact for incident response) | - |
| `container` | docker run (read-only, no caps) | Hardening that does not actually work at runtime | the 401/200 auth checks or health check fail |

Other good practices built in: least-privilege `GITHUB_TOKEN` (`permissions: contents: read`), a **weekly scheduled re-scan** (new CVEs appear even if your code does not change), Dependabot for dependencies, base image and the actions themselves, and concurrency control to cancel superseded runs.

## What the application does for security

- Parameterised SQL only (no string-built queries) - proven by a test that tries `x'); DROP TABLE tasks;--`
- API-key authentication with `hmac.compare_digest` (constant-time); key read from the environment, and the app **refuses to start** without one (fail closed)
- Strict input validation, JSON-only bodies, 16 KB request limit
- Security response headers (`nosniff`, `X-Frame-Options`, strict CSP, `no-store`)
- Generic error responses: no stack traces or internals leak
- Container: slim base image, non-root user, health check, designed to run read-only with all Linux capabilities dropped

## Verification status (read this)

| Check | Status |
|---|---|
| 17 unit/security tests, 98% coverage | Run - passing |
| Bandit on the application | Run - clean (after fixing a finding, see below) |
| pip-audit on pinned dependencies | Run - no known vulnerabilities (as of the build date; this changes over time) |
| Checkov on Dockerfile (48 checks) and workflow (128 checks) | Run - all passed |
| Workflow YAML syntax | Run - valid |
| Docker build, Hadolint, Trivy, Gitleaks, runtime smoke test | **Not run by the author.** No Docker daemon was available where this was built. They execute in GitHub Actions on your first push. Action/image version tags should be checked against what is currently published. |

**The pipeline found a real bug in the first run.** Bandit flagged the original default database path (`/tmp/tasks.db`, rule B108: predictable file in a shared temp directory, a symlink-attack risk). The fix was to remove the insecure default instead of silencing the warning with `# nosec`. That is the behaviour a security team wants to see.

## Run it yourself

```bash
cd app
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# tests with coverage gate
pytest -q --cov=app --cov-fail-under=90

# security scans
bandit -r . -x tests -ll
pip-audit -r requirements.txt --no-deps --disable-pip

# run the API locally
API_KEY=change-me-locally python -m flask --app "app:create_app" run
curl -H "X-API-Key: change-me-locally" localhost:5000/tasks

# build and run the container the hardened way
docker build -t devsecops-demo .
docker run --rm -p 8000:8000 -e API_KEY=change-me-locally \
  --read-only --tmpfs /data:rw,noexec,nosuid,uid=10001 \
  --cap-drop ALL --security-opt no-new-privileges:true devsecops-demo
```

### See what the scanners catch

`demo/insecure_example.py` contains intentionally vulnerable code (all values are dummies). The pipeline does not scan it, but you can:

```bash
bandit -r demo/
```

Bandit reports, among others: hard-coded password (B105), SQL string building (B608), `shell=True` command injection (B602), unsafe `pickle` deserialisation (B301) and weak MD5 hashing (B324). Being able to explain *why* each is dangerous and how to fix it is excellent interview material.

## To make the pipeline actually enforce policy

Pushing the workflow is not enough. On GitHub, enable **branch protection** on `main` and mark the jobs above as **required status checks**, so code cannot be merged while a security gate is red.

## Hardening ideas for later

- Pin third-party actions and container images to **commit SHAs / digests** instead of tags (tags can be moved by an attacker who compromises the upstream repository). Dependabot can then update them.
- Add Semgrep or CodeQL for deeper SAST, and OWASP ZAP for dynamic testing (DAST) against the running container.
- Sign images (cosign) and generate build provenance (SLSA).
- Add rate limiting and structured audit logging to the API.

## Structure

```text
app/                  Flask API, tests, Dockerfile, pinned requirements
demo/                 intentionally insecure examples for training
.github/workflows/    devsecops.yml pipeline
.github/dependabot.yml
.gitleaks.toml        scanner config (allowlists only the demo folder)
```
