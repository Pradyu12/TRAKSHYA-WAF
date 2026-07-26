FROM nginx:1.27-alpine
ENV TRAKSHYA_API_UPSTREAM=trakshya-api.trakshya-waf.svc.cluster.local:8000
COPY frontend /usr/share/nginx/html
COPY deploy/nginx/k8s-dashboard.conf.template /etc/nginx/templates/default.conf.template
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8000/healthz || exit 1
