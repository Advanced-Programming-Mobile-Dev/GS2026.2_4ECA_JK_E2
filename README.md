# Rede Comunitária Vila Aurora - Resilient Community Infrastructure

Global Solution 2026.2 · Cybersecurity · FIAP
Integrantes: Júlia Santos (RM 97897) · Kauê Miziara (RM 55045)

Protótipo de uma infraestrutura segura e resiliente em quatro camadas para os cinco espaços da Rede Vila Aurora. Tudo é **simulado** e usa **apenas dados sintéticos**.

## Pré-requisitos

- Linux com Docker Engine e o plugin `docker compose` (v2)
- Python 3.10+ com `venv`

```bash
timedatectl
sudo timedatectl set-ntp true
```

Todos os containers usam `TZ=UTC` e o relógio do host; todos os logs saem em UTC, formato ISO 8601.

## Etapa 1 — PKI, broker da borda com mTLS e primeiro sensor

Atende: RT-04 (identidade única por dispositivo + mTLS), RT-05 (revogação e rotação),
início de RT-07 (segmento IoT isolado) e RT-12 (relógio/UTC).

### 1. Configurar o usuário dos containers

```bash
printf "HOST_UID=%s\nHOST_GID=%s\n" "$(id -u)" "$(id -g)" > .env
```

### 2. Criar a CA e emitir os certificados

A senha da chave da CA é pedida no terminal.

```bash
pip install cryptography

python pki/pki.py init
python pki/pki.py issue-all
python pki/pki.py list
```

### 3. Subir o broker e o sensor da câmara fria

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f edge-ubs-broker ubs-camara-fria-01
```

### 4. Evidência automática de mTLS e ACL

```bash
docker compose --profile tools run --rm tools python mtls_check.py
```

| Teste | Cenário | Esperado |
|---|---|---|
| T1 | Cliente sem certificado | recusado |
| T2 | Certificado de uma CA falsa | recusado |
| T4 | Certificado válido da CA do projeto | aceito |
| T5 | Dispositivo publica na própria telemetria | entregue |
| T6 | Dispositivo tenta publicar como outro dispositivo | bloqueado pela ACL |

### Limitações conhecidas (laboratório)

- A chave do broker é gravada com modo `0644` para o usuário `mosquitto` do container
  conseguir lê-la. Em produção, ela teria dono `mosquitto` e modo `0600`.
- O Mosquitto só relê a CRL quando reinicia; por isso a revogação inclui um restart.

## Uso de IA

Ferramentas de IA generativa foram usadas como apoio na estruturação do código e da
documentação. A equipe revisou, executou e é responsável por todo o conteúdo.
