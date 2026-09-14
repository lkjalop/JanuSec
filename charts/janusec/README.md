# JanuSec Helm Chart

## What this chart provides
- API Deployment + Service
- Optional oauth2-proxy guard in front of the API (Ingress auth)
- NGINX Ingress with TLS
- Optional HPA

## Prereqs
- NGINX Ingress Controller
- cert-manager installed cluster-wide

## Configure
Edit `values.yaml` or create `values-production.yaml`:
- ingress.host: your FQDN (e.g., janusec.acme.com)
- ingress.tls.secretName: TLS secret name (created by cert-manager Certificate)
- oauth2Proxy: set issuerURL, clientID, clientSecret, cookieSecret, redirectURL

## Install
```sh
helm upgrade --install janusec ./charts/janusec -f charts/janusec/values.yaml
```

## TLS
Apply cert-manager issuer and certificate (edit email/host first):
```sh
kubectl apply -f cert-manager/cluster-issuer-letsencrypt.yaml
kubectl apply -f cert-manager/certificate.yaml
```

## Notes
- To disable oauth2-proxy (for internal/testing), set `oauth2Proxy.enabled=false`.
- Add environment variables to `.Values.env` as needed.