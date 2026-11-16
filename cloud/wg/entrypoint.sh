#!/bin/bash
# Gateway WireGuard da nuvem (RT-06). A ingestão compartilha esta interface
# de rede, então só é alcançável pelo túnel (10.13.13.1).
set -e
wg-quick up wg0
echo "$(date -u +%FT%TZ) WireGuard ativo em $(ip -4 -o addr show wg0 | awk '{print $4}')"
while true; do
  # registro periódico dos pares (handshake e endpoint atual) para auditoria/SIEM
  wg show wg0 dump | tail -n +2 | while read -r pub _psk endpoint allowed handshake rx tx _ka; do
    echo "$(date -u +%FT%TZ) peer=${pub:0:8} allowed=$allowed endpoint=$endpoint ultimo_handshake=$handshake rx=$rx tx=$tx"
  done
  sleep 60
done
