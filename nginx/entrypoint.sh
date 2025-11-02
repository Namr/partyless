#!/bin/sh
set -eu

CONF_DIR="/etc/nginx/conf.d"
TEMPLATE_DIR="/etc/nginx/templates"
CERT_DIR="/etc/nginx/certs"

export NGINX_UPSTREAM_HOST="${NGINX_UPSTREAM_HOST:-127.0.0.1}"
export NGINX_UPSTREAM_PORT="${NGINX_UPSTREAM_PORT:-3000}"
export NGINX_STATIC_ROOT="${NGINX_STATIC_ROOT:-/usr/share/nginx/html}"

mkdir -p "${CONF_DIR}"

if [ "${ENABLE_TLS:-0}" = "1" ]; then
    if [ ! -f "${CERT_DIR}/tls.crt" ] || [ ! -f "${CERT_DIR}/tls.key" ]; then
        if [ "${GENERATE_SELF_SIGNED:-1}" = "1" ]; then
            mkdir -p "${CERT_DIR}"
            openssl req -x509 -nodes \
                -days "${SELF_SIGNED_DAYS:-5}" \
                -newkey rsa:2048 \
                -keyout "${CERT_DIR}/tls.key" \
                -out "${CERT_DIR}/tls.crt" \
                -subj "${SELF_SIGNED_SUBJECT:-/CN=localhost}"
        else
            echo "TLS is enabled but certificates are missing at ${CERT_DIR}." >&2
            exit 1
        fi
    fi
    envsubst '${NGINX_UPSTREAM_HOST} ${NGINX_UPSTREAM_PORT} ${NGINX_STATIC_ROOT}' \
        < "${TEMPLATE_DIR}/default-ssl.conf.template" > "${CONF_DIR}/default.conf"
else
    envsubst '${NGINX_UPSTREAM_HOST} ${NGINX_UPSTREAM_PORT} ${NGINX_STATIC_ROOT}' \
        < "${TEMPLATE_DIR}/default.conf.template" > "${CONF_DIR}/default.conf"
fi

exec nginx -g "daemon off;"
