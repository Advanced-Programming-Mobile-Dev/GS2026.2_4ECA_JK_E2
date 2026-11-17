FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 TZ=UTC
RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools iproute2 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py send_command.py entrypoint.sh ./
# Remove CR (caso o arquivo tenha passado por um editor do Windows)
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh
# Roda como root com a capability NET_ADMIN (necessária para o wg-quick e
# para trocar o endpoint da VPN no failover). Nenhuma porta é exposta.
ENTRYPOINT ["/app/entrypoint.sh"]
