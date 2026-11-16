#!/bin/sh
# Sobe o túnel WireGuard da borda (RT-06) e inicia o agente.
set -e
if [ "${WG_ENABLE:-1}" = "1" ]; then
  wg-quick up wg0
  wg show wg0
fi
exec python /app/agent.py
