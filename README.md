# Rede Comunitária Vila Aurora — Resilient Community Infrastructure

Global Solution 2026.2 · Cybersecurity · FIAP
Integrantes: Júlia Santos (RM 97897) · Kauê Miziara (RM 55045)

Protótipo de uma infraestrutura segura e resiliente em quatro camadas (campo, borda,
nuvem e supervisão) para os cinco espaços da Rede Vila Aurora: Centro Comunitário,
Escola, UBS, Horta/Cozinha Solidária e Abrigo de Emergência. Tudo é **simulado**
(containers Python e um ESP32 no Wokwi) e usa **apenas dados sintéticos**.

---

## Estrutura do repositório

```
.
├── docker-compose.yml          # orquestração do laboratório
├── .env.example                # UID/GID do usuário host (só Linux)
├── data/
│   ├── generate_synthetic.py   # pessoas e crachás fictícios (seed fixa)
│   └── synthetic/              # CSVs gerados (versionados: são sintéticos)
├── pki/
│   ├── pki.py                  # CA, certificados, CRL, rotação e chave HMAC do ESP32
│   ├── inventory.json          # identidades (1 certificado por broker/dispositivo/serviço)
│   └── out/                    # GERADO: chaves e certificados (fora do git)
├── edge/mosquitto/
│   ├── mosquitto.conf          # broker da borda: só TLS 8883, mTLS obrigatório, CRL
│   └── acl/<espaco>.acl        # ACL por identidade, uma por espaço
├── field/
│   ├── field_sim.py            # sensores simulados de um espaço (1 thread e 1 certificado por dispositivo)
│   └── devices.json            # dispositivos de cada espaço
├── wokwi/
│   ├── main.py                 # ESP32 (MicroPython): nível do reservatório, assinado com HMAC
│   └── diagram.json            # circuito: ESP32 + potenciômetro + LED de alarme
├── bridge/
│   └── wokwi_bridge.py         # ponte broker público -> borda da escola (valida HMAC e replay)
├── edge/agent/
│   ├── agent.py                # agente da borda: regras locais, buffer SQLite, uplink com failover
│   └── entrypoint.sh           # sobe o túnel WireGuard e inicia o agente
├── cloud/
│   ├── wg/                     # gateway WireGuard da nuvem (10.13.13.1)
│   ├── ingest/ingest.py        # ingestão HTTPS+mTLS, idempotente, só pelo túnel
│   └── db/init/01-schema.sh    # tabela events e papéis de privilégio mínimo
├── tools/
│   ├── mtls_check.py           # evidência de mTLS, CRL e ACL
│   ├── wokwi_attack.py         # forja, adulteração e replay contra a ponte
│   └── inject_reading.py       # injeta uma leitura (ex.: câmara fria a 12 °C)
└── docs/evidencias/            # saídas dos testes (JSON com hash)
```

## Arquitetura do protótipo (até a etapa 3)

```
 CAMPO              BORDA (1 por espaço)                         WAN simulada          NUVEM
 field-<espaco> ─mTLS─▶ edge-<espaco>-broker ◀─mTLS─ edge-<espaco>-agent ══ WireGuard ══▶ cloud-wg (10.13.13.1)
   [seg-iot-<espaco>, interno]                 regras locais     fibra (principal)        └ cloud-ingest (HTTPS+mTLS)
                                               buffer SQLite     4G (alternativo)              └ postgres [seg-servicos]

 ESP32 (Wokwi) ─TLS+HMAC─▶ broker.hivemq.com ◀─TLS─ escola-wokwi-bridge ─mTLS─▶ edge-escola-broker
```

- Cada segmento IoT é uma rede Docker **interna**: sem internet e sem rota para os outros espaços.
- Os agentes de borda só alcançam a nuvem pelo túnel WireGuard, cada um só com rota para `10.13.13.1`.
- A ingestão escuta **só** no IP da VPN, e o banco fica num segmento que nenhuma borda alcança.
- A ponte do Wokwi é o **único** serviço com acesso à internet (`seg-wan`).
- Nenhuma porta é publicada no host.

---

## Pré-requisitos

- Docker Desktop (Windows) ou Docker Engine + plugin `docker compose` v2 (Linux)
- Python 3.10+ no host (só para a PKI e os dados sintéticos)
- Relógio sincronizado por NTP (base da linha do tempo forense):
  - Windows: `w32tm /query /status`
  - Linux: `timedatectl` → `System clock synchronized: yes`

Todos os containers usam `TZ=UTC`; todos os logs saem em UTC, formato ISO 8601.

Os comandos abaixo funcionam no `cmd` do Windows e no Linux (use `/` nos caminhos).

**Somente Linux:** crie o `.env` com o seu UID/GID, para os containers lerem as chaves privadas:
```bash
printf "HOST_UID=%s\nHOST_GID=%s\n" "$(id -u)" "$(id -g)" > .env
```

---

## Etapa 1 — PKI e broker da borda com mTLS

Atende: RT-04 (identidade única por dispositivo + mTLS) e RT-05 (revogação e rotação).

### Criar a CA e emitir os certificados

A senha da chave da CA é pedida no terminal. **Guarde-a e não a versione.**

```bash
pip install --user cryptography
python pki/pki.py init
python pki/pki.py issue-all
python pki/pki.py list
```

### Evidência de mTLS e ACL

```bash
docker compose up -d --build
docker compose --profile tools run --rm --user root tools python mtls_check.py
```

| Teste | Cenário | Esperado |
|---|---|---|
| T1 | Cliente sem certificado | recusado |
| T2 | Certificado de uma CA falsa | recusado |
| T3 | Certificado revogado (`--revoked <nome>`) | recusado |
| T4 | Certificado válido da CA do projeto | aceito |
| T5 | Dispositivo publica na própria telemetria | entregue |
| T6 | Dispositivo tenta publicar como outro dispositivo | bloqueado pela ACL |

Para outro espaço: `python mtls_check.py --broker edge-escola-broker --space escola --victim escola-turbidez-01`

### Evidências manuais

```bash
docker compose --profile tools run --rm --user root tools bash
```

Dentro do container:

```bash
# Um certificado por dispositivo
ls -la /pki/certs/
openssl x509 -in /pki/certs/ubs-camara-fria-01/ubs-camara-fria-01.crt -noout -subject -issuer -serial -enddate

# Telemetria ao vivo como auditor (somente leitura)
mosquitto_sub -h edge-ubs-broker -p 8883 \
  --cafile /pki/certs/lab-auditor/ca.crt \
  --cert /pki/certs/lab-auditor/lab-auditor.crt \
  --key  /pki/certs/lab-auditor/lab-auditor.key \
  -t 'va/#' -v

# Sem certificado de cliente -> recusado
mosquitto_sub -h edge-ubs-broker -p 8883 --cafile /pki/certs/lab-auditor/ca.crt -t 'va/#' -v

# TLS negociado e certificado do broker
openssl s_client -connect edge-ubs-broker:8883 \
  -CAfile /pki/certs/lab-auditor/ca.crt \
  -cert /pki/certs/lab-auditor/lab-auditor.crt \
  -key  /pki/certs/lab-auditor/lab-auditor.key -brief </dev/null
```

No host:
- Windows: `docker compose logs edge-ubs-broker | findstr /C:"did not return" /C:"verify failed"`
- Linux: `docker compose logs edge-ubs-broker | grep -E "did not return|verify failed"`
- Portas expostas (nenhuma saída esperada): `netstat -ano | findstr ":1883 :8883"` (Windows) ou `ss -tlnp | grep -E ':1883|:8883'` (Linux)

### Revogação e reemissão (RT-05)

```bash
python pki/pki.py revoke ubs-camara-fria-01 --reason key_compromise
docker compose restart edge-ubs-broker
docker compose --profile tools run --rm --user root tools openssl crl -in /pki/crl/crl.pem -noout -text
docker compose --profile tools run --rm --user root tools python mtls_check.py --revoked ubs-camara-fria-01
docker compose logs --tail 10 field-ubs

python pki/pki.py issue-all          # emite certificado novo (serial novo) para o revogado
docker compose restart field-ubs
python pki/pki.py list

python pki/pki.py rotate lab-tester-01   # rotação planejada (antigo vira "superseded")
docker compose restart edge-ubs-broker
```

---

## Etapa 2 — Campo completo: 5 espaços, dados sintéticos e ESP32 no Wokwi

Atende: RT-01 (nó de borda por espaço), RT-04 (identidade por dispositivo), RT-07
(segmento IoT isolado por espaço) e RT-19 (dados sintéticos).

### 1. Dados sintéticos

```bash
python data/generate_synthetic.py
```

Gera `data/synthetic/pessoas.csv` e `data/synthetic/crachas.csv`: 200 pessoas fictícias,
com nomes marcados "(fictício)" e telefones `(00) 0000-xxxx`, seus papéis e crachás RFID,
dos quais ~5% estão bloqueados. A seed é fixa, então o resultado é sempre o mesmo.
Os leitores RFID da UBS e do Abrigo leem esses crachás; ~10% das leituras são de crachás desconhecidos.

### 2. Certificados dos novos dispositivos e chave do ESP32

```bash
python pki/pki.py issue-all
```

Os certificados que já existem são mantidos. Os novos brokers, sensores e a ponte recebem
os seus, e o ESP32 recebe uma **chave HMAC exclusiva**. O comando imprime três linhas para
colar no `main.py` do Wokwi. Para mostrá-las de novo:

```bash
python pki/pki.py hmac-show escola-nivel-01
```

### 3. Subir os 5 espaços

```bash
docker compose up -d --build --remove-orphans
docker compose ps
```

Esperado: 5 brokers (`edge-*-broker`), 5 simuladores de campo (`field-*`) e a ponte
(`escola-wokwi-bridge`). A opção `--remove-orphans` remove o container antigo da etapa 1.

| Espaço | Dispositivos simulados |
|---|---|
| Centro | bateria (SoC), geração solar (curva diária), CO₂ |
| Escola | turbidez, cloro residual, **nível do reservatório (ESP32 no Wokwi)** |
| UBS | câmara fria de vacinas, leitor RFID |
| Horta | umidade do solo, nível da cisterna |
| Abrigo | alagamento, umidade do ar, leitor RFID |

As leituras seguem um processo de reversão à média, `x ← x + θ(base − x) + σ·N(0,1)`, sem saltos irreais.

### 4. ESP32 no Wokwi

1. Abra [wokwi.com](https://wokwi.com) → **New Project** → **ESP32** → **MicroPython** (o template oficial).
2. Na aba `diagram.json`, mantenha a linha do ESP32 do template (ela define a versão do
   MicroPython) e copie as demais `parts` e as `connections` de `wokwi/diagram.json`:
   potenciômetro deslizante no GPIO34 e LED vermelho com resistor no GPIO2.
3. Substitua o `main.py` pelo `wokwi/main.py` e cole `DEVICE_ID`, `TOPIC_PREFIX` e `HMAC_KEY_HEX`.
4. Clique em **Start**. No monitor serial aparecem WiFi, NTP, MQTT e as leituras.
5. Mova o potenciômetro para baixo de 20 %: o **LED acende** (alarme local, independe da rede).

> **Não salve nem compartilhe o projeto no Wokwi com a chave preenchida**: no plano
> gratuito os projetos salvos são públicos. Se isso acontecer, rotacione a chave:
> `python pki/pki.py hmac-rotate escola-nivel-01` e `docker compose restart escola-wokwi-bridge`.

Se a conexão TLS falhar no simulador, mude `USE_TLS = False` no `main.py` (porta 1883).
A assinatura HMAC continua protegendo a integridade, mas registre isso como limitação.

### 5. Ver os dados chegando

```bash
docker compose logs -f escola-wokwi-bridge
```

Esperado: `ACEITA seq=... nivel=...% -> va/escola/telemetry/escola-nivel-01`.

Dentro do container de ferramentas (`docker compose --profile tools run --rm --user root tools bash`):

```bash
mosquitto_sub -h edge-escola-broker -p 8883 \
  --cafile /pki/certs/lab-auditor/ca.crt \
  --cert /pki/certs/lab-auditor/lab-auditor.crt \
  --key  /pki/certs/lab-auditor/lab-auditor.key \
  -t 'va/#' -v
```

As mensagens do ESP32 chegam com `"via": "wokwi-bridge", "auth": "hmac-sha256"`.
Troque `edge-escola-broker` por `edge-centro-broker`, `edge-ubs-broker`,
`edge-horta-broker` ou `edge-abrigo-broker` para ver os outros espaços.

### 6. Ataques contra o trecho público (a ponte deve rejeitar)

Com o ESP32 rodando no Wokwi:

```bash
docker compose --profile tools run --rm --user root tools python wokwi_attack.py forge
docker compose --profile tools run --rm --user root tools python wokwi_attack.py tamper
docker compose --profile tools run --rm --user root tools python wokwi_attack.py replay
docker compose logs --tail 20 escola-wokwi-bridge
```

| Ataque | O que o atacante faz | Resultado esperado na ponte |
|---|---|---|
| forge | inventa uma leitura "nível 0 %" sem ter a chave | `REJEITADA motivo="assinatura HMAC invalida"` |
| tamper | captura uma leitura real e altera o valor | `REJEITADA motivo="assinatura HMAC invalida"` |
| replay | captura uma leitura real e reenvia igual | `REJEITADA motivo="replay detectado (...)"` |

### 7. Segmentação entre espaços

```bash
# UBS não alcança o broker da escola (segmentos isolados)
docker compose exec field-ubs python -c "import socket; socket.create_connection(('edge-escola-broker', 8883), 3)"

# Sensores não alcançam a internet
docker compose exec field-ubs python -c "import socket; socket.create_connection(('broker.hivemq.com', 8883), 3)"
```

Esperado: os dois comandos falham com erro de resolução de nome ou de conexão.

---

## Etapa 3 — Borda autônoma, store-and-forward, VPN WireGuard e nuvem

Atende: RT-01 (nó de borda por espaço), RT-02 (operação local, buffer e reconciliação),
RT-03 (link alternativo e modo degradado), RT-06 (VPN WireGuard), RT-07 (segmentação),
RT-08 (banco com privilégio mínimo e consultas parametrizadas) e RT-19 (pseudonimização).

### O que roda em cada borda (`edge-<espaco>-agent`)

| Função | Comportamento |
|---|---|
| Alarme da câmara fria (UBS) | fora de 2–8 °C → `ALARME LOCAL ATIVO`, sem depender da nuvem |
| Alagamento (abrigo) | acima de 10 cm → alarme local |
| Reservatório (escola, ESP32) | < 20 % → **liga a bomba**; ≥ 95 % → desliga. Vale mesmo se o agendamento remoto for adulterado (INC-VA-0712) |
| Acesso por crachá (UBS, abrigo) | libera ou nega pela lista sintética (crachá desconhecido, bloqueado ou sem autorização no espaço) |
| Buffer store-and-forward | todo evento vai para o SQLite **antes** de ser enviado; só sai do buffer com o "ok" da nuvem |
| Failover | nuvem sem resposta por 30 s → troca o endpoint da VPN da fibra para o 4G; sem nenhum link → **modo degradado** |
| Reconciliação | ao voltar, reenvia o buffer; a nuvem descarta duplicados pelo `msg_id` |
| LGPD | o UID do crachá nunca sai da borda; vai para a nuvem só `HMAC-SHA256(pepper, uid)` |

### 1. Preparar

Crie o `.env` a partir do exemplo e **troque todos os valores**:

```bat
copy .env.example .env
notepad .env
```

Confira se o Docker suporta WireGuard (deve imprimir `WIREGUARD_OK`):

```bat
docker run --rm --cap-add NET_ADMIN alpine sh -c "ip link add wg0 type wireguard && echo WIREGUARD_OK"
```

### 2. Identidades novas (sempre **antes** do `up`)

```bat
docker compose down
python pki/pki.py issue-all
python pki/pki.py wg-show
```

O `issue-all` cria os certificados dos 5 agentes, da bomba e da ingestão (com o IP
`10.13.13.1` no SAN), e as chaves e configurações WireGuard (`pki/out/wg/`), com
PresharedKey por borda.

### 3. Subir tudo

```bat
docker compose up -d --build --remove-orphans
docker compose --profile tools build tools
docker compose ps
```

Esperado: os 5 brokers, os 5 simuladores, os 5 agentes, a ponte, `cloud-wg`,
`cloud-ingest` e `postgres` com status `running`.

### 4. Evidências da VPN e da segmentação

```bat
docker compose exec cloud-wg wg show
docker compose exec edge-ubs-agent wg show
docker compose logs --tail 5 cloud-ingest
```

Esperado:
- a nuvem mostra os 5 peers com `latest handshake` recente e tráfego (`transfer`);
- as chaves privadas e a PresharedKey não aparecem;
- a ingestão registra lotes `lote agente=edge-...-agent novas=...`.

Testes que devem falhar:

```bat
docker compose exec edge-ubs-agent python -c "import socket; socket.create_connection(('cloud-fibra', 8443), 3)"
docker compose exec edge-ubs-agent python -c "import socket; socket.create_connection(('postgres', 5432), 3)"
```

O primeiro mostra que a ingestão não é alcançável **fora** do túnel (conexão recusada).
O segundo mostra que a borda não enxerga o banco.

### 5. Dados na nuvem, privilégio mínimo e pseudonimização

```bat
docker compose exec postgres psql -U postgres -d vilaaurora -c "select space, kind, count(*) from events group by 1,2 order by 1,2;"
docker compose exec postgres psql -U ingest_writer -d vilaaurora -c "select value from events limit 1;"
docker compose exec postgres psql -U postgres -d vilaaurora -c "select space, data->>'badge_hash' as cracha, data->>'decision' as decisao, data->>'reason' as motivo from events where kind='access' order by ts desc limit 5;"
```

Esperado:
- contagens por espaço e tipo;
- `permission denied` para o `ingest_writer`, que só pode inserir;
- crachás aparecem só como pseudônimo, nunca com o UID.

### 6. Regras locais

Deixe os logs abertos:

```bat
docker compose logs -f edge-escola-agent edge-ubs-agent field-escola
```

- **Bomba** (ela começa ligada): no Wokwi, suba o potenciômetro até 95 % ou mais. Aparecem
  `REGRA LOCAL: bomba DESLIGADA (... nivel_alto_evitar_transbordo)` e
  `BOMBA DESLIGADA por edge-escola-agent`. Depois desça abaixo de 20 %: aparecem
  `ALARME LOCAL ATIVO`, `REGRA LOCAL: bomba LIGADA (... nivel_baixo_reabastecer)` e
  `BOMBA LIGADA`, e o LED do ESP32 acende.
- **Câmara fria:** em outro terminal,
  ```bat
  docker compose --profile tools run --rm --user root tools python inject_reading.py ubs-camara-fria-01 camara_fria 12 C
  ```
  Esperado: `ALARME LOCAL ATIVO sensor=camara_fria ... valor=12.0C`.
- **Acesso:** `docker compose logs --tail 20 edge-ubs-agent field-ubs` mostra `ACESSO LIBERADO/NEGADO`
  e `porta LIBERADA/MANTIDA FECHADA`.

### 7. Queda da fibra, modo degradado e reconciliação (UBS)

Os nomes das redes começam com o nome do projeto. Confira:

```bat
docker network ls | findstr seg-wan
```

Deixe um terminal com `docker compose logs -f edge-ubs-agent` e use outro para os comandos.

**1) A fibra cai.** Em ~30–40 s, a borda troca para o 4G (o `wg show` mostra o endpoint novo):

```bat
docker network disconnect vila-aurora_seg-wan-fibra edge-ubs-agent
docker compose exec edge-ubs-agent wg show
```

**2) O 4G também cai.** A borda entra em MODO DEGRADADO, e o alarme local continua funcionando:

```bat
docker network disconnect vila-aurora_seg-wan-4g edge-ubs-agent
docker compose --profile tools run --rm --user root tools python inject_reading.py ubs-camara-fria-01 camara_fria 12 C
docker compose exec edge-ubs-agent python -c "import sqlite3; print('pendentes no buffer:', sqlite3.connect('/var/lib/agent/outbox.db').execute('select count(*) from outbox where sent_at is null').fetchone()[0])"
```

**3) Os links voltam.** Aparecem `LINK RESTABELECIDO` e a reconciliação do buffer:

```bat
docker network connect vila-aurora_seg-wan-fibra edge-ubs-agent
docker network connect vila-aurora_seg-wan-4g edge-ubs-agent
```

| Momento | Linha esperada no log do `edge-ubs-agent` |
|---|---|
| fibra cai | `nuvem inacessivel via fibra` → `WAN: fibra -> 4g` |
| 4G cai | `MODO DEGRADADO: nenhum link WAN responde; borda segue autonoma` |
| câmara fria a 12 °C | `ALARME LOCAL ATIVO` (mesmo sem nuvem) |
| links voltam | `LINK RESTABELECIDO` → `RECONCILIACAO ... duplicados=0` → `RECONCILIACAO concluida: buffer vazio, nenhum evento perdido` |

Para provar que nada se perdeu nem duplicou:

```bat
docker compose exec postgres psql -U postgres -d vilaaurora -c "select count(*) - count(distinct msg_id) as duplicados from events;"
```

---

## Limitações conhecidas

- **ESP32 no Wokwi (plano gratuito):** sem o Private IoT Gateway (pago), o ESP32 não
  alcança o broker local e, por isso, não usa mTLS. Controles compensatórios adotados:
  - TLS até o broker público;
  - tópico aleatório;
  - assinatura HMAC-SHA256 por mensagem, com chave exclusiva do dispositivo;
  - contador anti-replay e janela de tempo de 5 min;
  - uma única ponte autorizada pela ACL a escrever só a telemetria desse dispositivo.

  Riscos residuais:
  - o broker público vê o conteúdo das mensagens (sem confidencialidade nesse trecho, aceitável por ser só o nível do reservatório);
  - o ESP32 não verifica o certificado do broker público;
  - se a ponte reiniciar, ela esquece os contadores, e a janela de tempo passa a ser a única proteção contra replay.
- A chave do broker é gravada com modo `0644` para o usuário `mosquitto` do container
  conseguir lê-la. Em produção, ela teria dono `mosquitto` e modo `0600`.
- O Mosquitto só relê a CRL quando reinicia; por isso a revogação inclui um restart.
- Os agentes de borda rodam como root com a capability `NET_ADMIN`, necessária para o WireGuard
  e para trocar o endpoint no failover. Em produção, o túnel ficaria num serviço separado.
- A troca fibra → 4G é feita pelo agente (endpoint da VPN), não por roteamento dinâmico.
- O buffer não apaga eventos já enviados; em produção, haveria limpeza por retenção.

---

## Uso de IA

Ferramentas de IA generativa foram usadas como apoio na estruturação do código e da
documentação. A equipe revisou, executou e é responsável por todo o conteúdo.
