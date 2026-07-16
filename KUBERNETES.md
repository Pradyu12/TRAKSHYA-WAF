# Kubernetes Deployment Guide

TRAKSHYA-WAF ships with raw Kubernetes manifests under `k8s/` and a Helm chart under `helm/trakshya-waf/`.

## Prerequisites

- Kubernetes 1.24+
- Container registry (Docker Hub, GHCR, etc.) with images built
- Optional: Helm 3.12+ for chart-based deployment
- Optional: `kubectl` configured for your cluster

## Option A: Helm Chart

```bash
helm install trakshya-waf ./helm/trakshya-waf \
  --namespace trakshya-waf --create-namespace \
  --set image.dashboard.repository=ghcr.io/Pradyu12/trakshya-waf-dashboard \
  --set image.proxy.repository=ghcr.io/Pradyu12/trakshya-waf-proxy \
  --set image.api.repository=ghcr.io/Pradyu12/trakshya-waf-api \
  --set secrets.apiKey=$(openssl rand -hex 32)
```

Upgrade:
```bash
helm upgrade trakshya-waf ./helm/trakshya-waf \
  --namespace trakshya-waf \
  --set image.tag=newtag
```

## Option B: kubectl

```bash
kubectl apply -f k8s/
```

## How Users Get Updates

### 1. Image-based updates (recommended for Kubernetes)

When you change WAF rules, proxy behavior, or dashboard code:

```bash
# Rebuild and push new images
docker compose -f docker-compose.stack.yml build
docker push ghcr.io/Pradyu12/trakshya-waf-proxy:v2.4.0
docker push ghcr.io/Pradyu12/trakshya-waf-api:v2.4.0
docker push ghcr.io/Pradyu12/trakshya-waf-dashboard:v2.4.0

# Roll the proxy deployment
kubectl set image deployment/trakshya-proxy \
  proxy=ghcr.io/Pradyu12/trakshya-waf-proxy:v2.4.0 \
  -n trakshya-waf

kubectl rollout status deployment/trakshya-proxy -n trakshya-waf
```

### 2. Config-only updates via ConfigMap

For config changes that don't require rebuilding the proxy binary:

```bash
# Update config/trakshya.yaml and re-apply
kubectl apply -f k8s/01-configmap.yaml

# Rolling restart to pick up new config
kubectl rollout restart deployment/trakshya-proxy deployment/trakshya-api -n trakshya-waf
```

### 3. Automated updates with ArgoCD / Flux

For GitOps-based updates:

1. Push ConfigMap changes to Git
2. ArgoCD/Flux syncs the cluster
3. For image updates, update the tag in `helm/trakshya-waf/values.yaml` and commit

## CI/CD: Automatic Image Builds on Push

`.github/workflows/docker-publish.yml` automatically builds and pushes images to GHCR when you push to main or create a tag.

## CI/CD: Deploy to Kubernetes on Tag

Create a workflow that deploys on tag push:

```yaml
name: Deploy to Kubernetes

on:
  push:
    tags:
      - 'v*'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/k8s-set-context@v4
        with:
          kubeconfig: ${{ secrets.KUBECONFIG }}
      - run: helm upgrade --install trakshya-waf ./helm/trakshya-waf --namespace trakshya-waf --set image.tag=${{ github.ref_name }}
```

## Monitoring Updates

```bash
# Watch rollout
kubectl rollout status deployment/trakshya-proxy -n trakshya-waf --watch

# Check image version
kubectl get deployment trakshya-proxy -n trakshya-waf -o jsonpath='{.spec.template.spec.containers[0].image}'

# Roll back if needed
kubectl rollout undo deployment/trakshya-proxy -n trakshya-waf

# View events
kubectl get events --sort-by='.lastTimestamp' -n trakshya-waf
```
