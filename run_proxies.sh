#!/bin/bash

# Directorio del script para rutas dinámicas
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROXY_EXE="$SCRIPT_DIR/../coap-http-reverseproxy/coap-http-reverseproxy"

echo "=== INICIANDO PROXIES INVERSOS COAP ==="

# Detener cualquier instancia existente
echo "Deteniendo instancias anteriores del proxy..."
killall coap-http-reverseproxy 2>/dev/null
sleep 1

# Determinar IP del backend (detectar la IP del host de Windows desde WSL)
# Probamos primero con el nameserver de resolv.conf (muy confiable en WSL2) y luego con ip route
BACKEND_IP=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
if [ -z "$BACKEND_IP" ]; then
  BACKEND_IP=$(ip route | grep default | awk '{print $3}')
fi
if [ -z "$BACKEND_IP" ]; then
  BACKEND_IP="127.0.0.1"
fi
echo "IP del Host Windows detectada desde WSL: $BACKEND_IP"

# 1. Proxy para el Servidor de Autorización (Puerto 3001)
echo "Lanzando proxy CoAP en puerto UDP 5683 -> http://$BACKEND_IP:3001..."
"$PROXY_EXE" --port 5683 http://$BACKEND_IP:3001 > /tmp/proxy_oauth_auth.log 2>&1 &

# 2. Proxy para el Servidor de Recursos (Puerto 3002)
echo "Lanzando proxy CoAP en puerto UDP 5685 -> http://$BACKEND_IP:3002..."
"$PROXY_EXE" --port 5685 http://$BACKEND_IP:3002 > /tmp/proxy_oauth_resource.log 2>&1 &

sleep 1
echo "¡Todos los proxies CoAP iniciados en segundo plano!"
echo "Usa killall coap-http-reverseproxy para detenerlos."
echo "======================================"

# Mantener el script vivo esperando a los subprocesos para que concurrently no detenga los otros servidores
wait
