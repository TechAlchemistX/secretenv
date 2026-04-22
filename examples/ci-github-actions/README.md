# CI/CD: GitHub Actions

Reference workflow showing SecretEnv in a GitHub Actions job. Uses
OIDC-assumed AWS credentials (no long-lived secrets stored in GitHub)
and `SECRETENV_REGISTRY` to point the binary at a registry without
needing a `config.toml` on the runner.

## When to use this

- Deploy jobs that run on ephemeral GitHub runners.
- Any pipeline that calls a command needing cloud secrets — tests,
  migrations, smoke tests.
- Want to stop copy-pasting `with: env:` blocks everywhere.

## What's in this directory

- `deploy.yml` — canonical workflow. Copy to
  `.github/workflows/deploy.yml` in your repo.
- `secretenv.toml` — matching project manifest.

## Key lines in the workflow

1. `aws-actions/configure-aws-credentials@v4` assumes the deploy role
   via OIDC. No static AWS keys stored in GitHub.
2. `curl -sfS https://secretenv.io/install.sh | sh` installs the binary
   (or use `cargo install secretenv` or the prebuilt tarball from the
   GH Release).
3. `SECRETENV_REGISTRY: aws-ssm:///secretenv/registry` tells SecretEnv
   where the alias registry lives — no `config.toml` needed.
4. `secretenv run -- ./deploy.sh` executes your command with secrets
   injected as env vars from resolved aliases.

## Why not just `secrets.STRIPE_KEY`?

You can — GitHub Actions secrets work. The SecretEnv advantage shows
up when:

- The same secret values are used locally AND in CI (one source of
  truth, not duplicated across GitHub + your laptop).
- You have three deploy jobs that all need the same 8 secrets (no more
  `env:` block copy-paste).
- Rotation happens in AWS/1Password — no GitHub secret updates needed.

## What the deploy role needs

The IAM role `github-actions-deploy` needs:

- `ssm:GetParameter` / `ssm:GetParameters` on
  `arn:aws:ssm:*:*:parameter/secretenv/*` + the prod paths your aliases
  point to.
- Whatever your actual deploy script needs (ECS task registration,
  S3 upload, etc.).

No SecretEnv-specific IAM — the permissions are just "can this role
read the parameters the registry aliases to?".
