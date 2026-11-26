# Deployment

- [Docker](#docker)
- [Helm](#helm)
- [Background service](#background-service)
- [Health checks](#health-checks)
- [ASGI](#asgi)
- [Upgrading from PromptCloak](#upgrading-from-promptcloak)

## Docker

Create an environment file for the published image at `~/.config/promptlatch/provider.env`
with mode `0600`:

```text
PROMPTLATCH_TARGET_BASE_URL=https://api.openai.com/v1
PROMPTLATCH_TARGET_API_KEY=<openai-upstream-key>
```

```bash
docker run -d --name promptlatch --rm \
  -p 127.0.0.1:8000:8000 \
  --env-file "$HOME/.config/promptlatch/provider.env" \
  ghcr.io/bvolpato/promptlatch:0.3.0

curl --retry 10 --retry-all-errors --retry-delay 1 \
  -fsS http://127.0.0.1:8000/healthz
docker stop promptlatch
```

Build current checkout:

```bash
docker build -t promptlatch:local .
```

Compose:

```bash
export OPENAI_API_KEY="<openai-upstream-key>"
docker compose up --build
```

## Helm

Local chart:

```bash
kubectl create secret generic promptlatch-env \
  --from-env-file="$HOME/.config/promptlatch/kubernetes.env"

helm install promptlatch ./charts/promptlatch \
  --set env.PROMPTLATCH_TARGET_DEFAULT_BASE_URL=https://api.openai.com/v1 \
  --set existingSecret=promptlatch-env

kubectl wait deployment/promptlatch --for=condition=Available --timeout=90s
export PROMPTLATCH_SERVER_API_KEY="$(
  kubectl get secret promptlatch-env \
    -o jsonpath='{.data.PROMPTLATCH_SERVER_API_KEY}' | base64 --decode
)"
kubectl port-forward svc/promptlatch 8000:8000
```

In another shell:

```bash
curl -fsS http://127.0.0.1:8000/healthz
helm uninstall promptlatch
```

Release asset:

```bash
helm pull https://github.com/bvolpato/promptlatch/releases/download/v0.3.0/promptlatch-0.3.0.tgz
helm install promptlatch ./promptlatch-0.3.0.tgz \
  --set env.PROMPTLATCH_TARGET_DEFAULT_BASE_URL=https://api.openai.com/v1 \
  --set existingSecret=promptlatch-env
```

`kubernetes.env` must contain `PROMPTLATCH_TARGET_API_KEY` and
`PROMPTLATCH_SERVER_API_KEY`; keep the file outside the repository with mode `0600`.
Without `existingSecret`, the chart generates a proxy key and stores `secretEnv` values in
a chart-managed Secret. Send `Authorization: Bearer $PROMPTLATCH_SERVER_API_KEY` on
proxied requests. Health probes remain unauthenticated.

The chart stores request history in an `emptyDir` volume, so history is lost when the pod is replaced.

Services route only to pods from their own release. Connected Helm upgrades preserve
the existing Deployment selector. For offline upgrades of charts through 0.2.2, set
`migration.preserveSelector=true` and retain it on later offline upgrades. Omit it on
fresh installs. Old Deployments keep their broad immutable selectors; replacing them
is required for controller isolation, even though Service routing is isolated.

## Background service

Homebrew users can run PromptLatch as a background service after configuring its
environment:

```bash
brew services start bvolpato/tap/promptlatch
```

## Health checks

`GET /healthz` and `GET /v1/health` return local status with `"service": "promptlatch"`. They do not contact an upstream provider or enter request history.

## ASGI

ASGI servers can load `promptlatch.asgi:app` directly. Importing CLI or proxy
helpers does not load user config until a command or app requests it.

## Upgrading from PromptCloak

Version 0.2 renamed the package, command, environment variables, config directory,
container image, and Helm chart. Old Python imports, environment variables, and the old
default config path still work in 0.3 and emit migration warnings. A later release can
remove them.

Remove the old uv tool so a stale `promptcloak` command cannot shadow the new install:

```bash
uv tool uninstall promptcloak
```

Move local config before switching services. If `~/.config/promptlatch` already exists, move
the files one by one instead:

```bash
mv ~/.config/promptcloak ~/.config/promptlatch
```

Existing Helm releases can upgrade in place without changing immutable selectors or
rotating the chart-managed proxy key:

```bash
helm upgrade <existing-release-name> ./charts/promptlatch \
  --set migration.preserveLegacyNames=true
```

Keep the migration flag on later upgrades for that release. Fresh installs should omit it
and use release name `promptlatch`. Existing external Secrets may keep
`PROMPTCLOAK_SERVER_API_KEY` for this upgrade, then rename the key to
`PROMPTLATCH_SERVER_API_KEY`.
