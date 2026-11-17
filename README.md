# Rede Comunitária Vila Aurora — Resilient Community Infrastructure

Global Solution 2026.2 · Cybersecurity · FIAP
Integrantes: Júlia Santos (RM 97897) · Kauê Miziara (RM 55045)

Protótipo de uma infraestrutura segura e resiliente em quatro camadas (campo, borda,
nuvem e supervisão) para os cinco espaços da Rede Vila Aurora: Centro Comunitário,
Escola, UBS, Horta/Cozinha Solidária e Abrigo de Emergência. Tudo é **simulado** e usa **apenas dados sintéticos**.

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
│   ├── painel/                 # painel Flask: MFA, RBAC, consultas parametrizadas, auditoria
│   └── db/init/01-schema.sh    # tabela events e papéis de privilégio mínimo
├── siem/
│   ├── siem.py                 # mini-SIEM: coleta logs de todos os containers, 4 regras, retenção 30 dias
│   └── soar.py                 # respostas por risco: automáticas (baixo) e com aprovação (alto)
├── forense/coletar.py          # coleta forense: linha do tempo, SHA-256, cadeia de custódia
├── ia/detector.py              # Isolation Forest na telemetria + precisão/revocação/falsos positivos
├── metricas/
│   ├── caos.py                 # teste de caos: derruba fibra e 4G de uma borda por N minutos
│   └── relatorio.py            # disponibilidade, autonomia, perda de dados, MTTD/MTTR, recursos
├── tools/
│   ├── mtls_check.py           # evidência de mTLS, CRL e ACL
│   ├── wokwi_attack.py         # forja, adulteração e replay contra a ponte
│   └── inject_reading.py       # injeta uma leitura (ex.: câmara fria a 12 °C)
└── docs/evidencias/            # saídas dos testes (JSON com hash)
```

## Pré-requisitos

- Docker Desktop (Windows) ou Docker Engine + plugin `docker compose` v2 (Linux)
- Python 3.10+ no host (PKI, dados sintéticos, SIEM/SOAR, forense, IA e métricas)
- Relógio sincronizado por NTP (base da linha do tempo forense):
  - Windows: `w32tm /query /status`
  - Linux: `timedatectl` → `System clock synchronized: yes`

Todos os containers usam `TZ=UTC`; todos os logs saem em UTC, formato ISO 8601.

Os comandos abaixo funcionam no `cmd` do Windows e no Linux (use `/` nos caminhos).

**Somente Linux:** crie o `.env` com o seu UID/GID, para os containers lerem as chaves privadas:
```bash
printf "HOST_UID=%s\nHOST_GID=%s\n" "$(id -u)" "$(id -g)" > .env
```

## Reprodução

Uma rodada completa, do zero até as evidências finais, cobrindo todos os testes. Os passos
manuais estão marcados nos comentários. Use **dois terminais**: o terminal A
roda o SIEM o tempo todo; o terminal B roda o resto.

Valores que mudam a cada execução aparecem entre `< >`:
- o `<id>` das ações do SOAR sai de `soar.py list` ou `soar.py pending`;
- a `<data>` da pasta da coleta sai da própria saída do `coletar.py`.

### Linux (bash)

```bash
# ---------------------------------------------------------------- preparação
python3 -m venv .venv && . .venv/bin/activate
pip install cryptography scikit-learn numpy
cp .env.example .env
sed -i "s/^HOST_UID=.*/HOST_UID=$(id -u)/; s/^HOST_GID=.*/HOST_GID=$(id -g)/" .env
nano .env                                   # troque todas as senhas, BADGE_PEPPER e PAINEL_SECRET_KEY
timedatectl                                 # "System clock synchronized: yes"
docker run --rm --cap-add NET_ADMIN alpine sh -c "ip link add wg0 type wireguard && echo WIREGUARD_OK"

# ------------------------------------------- dados sintéticos e identidades (PKI)
python3 data/generate_synthetic.py
python3 pki/pki.py init                     # pede a senha da CA
python3 pki/pki.py issue-all                # certificados, chaves WireGuard e chave HMAC do ESP32
python3 pki/pki.py list
python3 pki/pki.py wg-show
python3 pki/pki.py hmac-show escola-nivel-01   # 3 linhas para colar no wokwi/main.py

# ------------------------------------------------------------- subir o ambiente
docker compose up -d --build --remove-orphans
docker compose --profile tools build tools
docker compose ps

# --------------------------------------------- terminal A: SIEM (deixar aberto)
python3 siem/siem.py

# ---------------------------------------------- terminal B: mTLS, CRL e ACL
docker compose --profile tools run --rm --user root tools python mtls_check.py
docker compose --profile tools run --rm --user root tools python mtls_check.py --broker edge-escola-broker --space escola --victim escola-turbidez-01
docker compose --profile tools run --rm --user root tools openssl s_client -connect edge-ubs-broker:8883 -CAfile /pki/certs/lab-auditor/ca.crt -cert /pki/certs/lab-auditor/lab-auditor.crt -key /pki/certs/lab-auditor/lab-auditor.key -brief </dev/null
docker compose logs edge-ubs-broker | grep -E "did not return|verify failed"
ss -tlnp | grep -E ':1883|:8883|:8443'      # só 127.0.0.1:8443 (painel)

# revogação e reemissão
python3 pki/pki.py revoke ubs-camara-fria-01 --reason key_compromise
docker compose restart edge-ubs-broker
docker compose --profile tools run --rm --user root tools openssl crl -in /pki/crl/crl.pem -noout -text
docker compose --profile tools run --rm --user root tools python mtls_check.py --revoked ubs-camara-fria-01
docker compose logs --tail 10 field-ubs
python3 pki/pki.py issue-all
docker compose restart field-ubs edge-ubs-broker
python3 pki/pki.py rotate lab-tester-01
docker compose restart edge-ubs-broker

# --------------------------------------------- ESP32 (Wokwi) e ponte com HMAC
# [manual] wokwi.com > New Project > ESP32 > MicroPython; copiar wokwi/diagram.json e wokwi/main.py,
#          colar as 3 linhas do hmac-show e clicar em Start
docker compose logs --tail 20 escola-wokwi-bridge                  # "ACEITA seq=..."
docker compose --profile tools run --rm --user root tools python wokwi_attack.py forge
docker compose --profile tools run --rm --user root tools python wokwi_attack.py tamper
docker compose --profile tools run --rm --user root tools python wokwi_attack.py replay
docker compose logs --tail 20 escola-wokwi-bridge                  # "REJEITADA motivo=..."

# ------------------------------------------------------ VPN e segmentação
docker compose exec cloud-wg wg show
docker compose exec edge-ubs-agent wg show
docker compose exec field-ubs python -c "import socket; socket.create_connection(('edge-escola-broker', 8883), 3)"      # deve falhar
docker compose exec field-ubs python -c "import socket; socket.create_connection(('broker.hivemq.com', 8883), 3)"       # deve falhar
docker compose exec edge-ubs-agent python -c "import socket; socket.create_connection(('cloud-fibra', 8443), 3)"       # deve falhar
docker compose exec edge-ubs-agent python -c "import socket; socket.create_connection(('postgres', 5432), 3)"          # deve falhar

# ---------------------------------------- banco: dados, privilégio mínimo e LGPD
docker compose exec postgres psql -U postgres -d vilaaurora -c "select space, kind, count(*) from events group by 1,2 order by 1,2;"
docker compose exec postgres psql -U ingest_writer -d vilaaurora -c "select value from events limit 1;"       # permission denied
docker compose exec postgres psql -U painel_reader -d vilaaurora -c "delete from events;"                     # permission denied
docker compose exec postgres psql -U postgres -d vilaaurora -c "select space, data->>'badge_hash', data->>'decision', data->>'reason' from events where kind='access' order by ts desc limit 5;"

# ---------------------------------------------------- regras locais da borda
docker compose --profile tools run --rm --user root tools python inject_reading.py ubs-camara-fria-01 camara_fria 12 C
docker compose logs --tail 20 edge-ubs-agent edge-escola-agent field-escola field-ubs
# [manual] no Wokwi: potenciômetro >= 95 % (bomba desliga) e depois < 20 % (alarme e bomba liga)

# ----------------------------------------------- painel (MFA, RBAC, SQL Injection)
docker compose exec painel python manage.py create-user ana.op operador
docker compose exec painel python manage.py create-user beto.tec tecnico
docker compose exec painel python manage.py create-user carla.coord coordenacao
docker compose exec painel python manage.py create-user davi.aud auditor
# [manual] abrir https://localhost:8443 (aceitar o certificado ou importar pki/out/ca/ca.crt no navegador)
#          ana.op: cadastrar MFA; abrir /acessos (403); no Histórico buscar  x' OR '1'='1  (rejeitado)
#          beto.tec: errar a senha 5 vezes (bloqueio); carla.coord: páginas Acessos e Auditoria
docker compose logs painel | grep -E "result=(negado|falha|bloqueado|entrada_invalida)"

# ------------------------------------- reprodução do INC-VA-0712 (SIEM no terminal A)
docker run --rm --cap-add NET_ADMIN --network vila-aurora_seg-wan-fibra -v "$(pwd)/pki/out/wg/edge-horta-agent.conf:/etc/wireguard/wg0.conf:ro" --entrypoint bash vila-aurora-edge-horta-agent -c "wg-quick up wg0 && sleep 90"
docker compose exec edge-escola-agent python send_command.py escola-bomba-01 off --by painel:ana.op --reason agendamento_alterado
python3 siem/soar.py pending
python3 siem/soar.py reject <id>
python3 metricas/caos.py --borda ubs --minutos 5 --injetar-alarme
python3 siem/soar.py list
python3 siem/soar.py restore <id>            # encerrar_sessao_vpn e bloquear_usuario_painel

# ---------------------------------------------- forense, IA e métricas
python3 forense/coletar.py --incidente INC-VA-LAB-01 --desde 30 --responsavel "Julia Santos"
python3 forense/coletar.py --verificar docs/forense/INC-VA-LAB-01_<data>
python3 ia/detector.py
python3 metricas/relatorio.py --desde 60
docker compose exec postgres psql -U postgres -d vilaaurora -c "select count(*) - count(distinct msg_id) as duplicados from events;"
```

### Windows (cmd)

```bat
REM ---------------------------------------------------------------- preparação
python -m venv .venv && .venv\Scripts\activate
pip install cryptography scikit-learn numpy
copy .env.example .env
notepad .env
REM   troque todas as senhas, BADGE_PEPPER e PAINEL_SECRET_KEY (HOST_UID/GID podem ficar 1000)
w32tm /query /status
docker run --rm --cap-add NET_ADMIN alpine sh -c "ip link add wg0 type wireguard && echo WIREGUARD_OK"

REM ------------------------------------------- dados sintéticos e identidades (PKI)
python data/generate_synthetic.py
python pki/pki.py init
python pki/pki.py issue-all
python pki/pki.py list
python pki/pki.py wg-show
python pki/pki.py hmac-show escola-nivel-01

REM ------------------------------------------------------------- subir o ambiente
docker compose up -d --build --remove-orphans
docker compose --profile tools build tools
docker compose ps

REM --------------------------------------------- terminal A: SIEM (deixar aberto)
python siem/siem.py

REM ---------------------------------------------- terminal B: mTLS, CRL e ACL
docker compose --profile tools run --rm --user root tools python mtls_check.py
docker compose --profile tools run --rm --user root tools python mtls_check.py --broker edge-escola-broker --space escola --victim escola-turbidez-01
docker compose --profile tools run --rm --user root tools sh -c "openssl s_client -connect edge-ubs-broker:8883 -CAfile /pki/certs/lab-auditor/ca.crt -cert /pki/certs/lab-auditor/lab-auditor.crt -key /pki/certs/lab-auditor/lab-auditor.key -brief </dev/null"
docker compose logs edge-ubs-broker | findstr /C:"did not return" /C:"verify failed"
netstat -ano | findstr ":1883 :8883 :8443"

REM revogação e reemissão
python pki/pki.py revoke ubs-camara-fria-01 --reason key_compromise
docker compose restart edge-ubs-broker
docker compose --profile tools run --rm --user root tools openssl crl -in /pki/crl/crl.pem -noout -text
docker compose --profile tools run --rm --user root tools python mtls_check.py --revoked ubs-camara-fria-01
docker compose logs --tail 10 field-ubs
python pki/pki.py issue-all
docker compose restart field-ubs edge-ubs-broker
python pki/pki.py rotate lab-tester-01
docker compose restart edge-ubs-broker

REM --------------------------------------------- ESP32 (Wokwi) e ponte com HMAC
REM [manual] wokwi.com > New Project > ESP32 > MicroPython; copiar wokwi\diagram.json e wokwi\main.py,
REM          colar as 3 linhas do hmac-show e clicar em Start
docker compose logs --tail 20 escola-wokwi-bridge
docker compose --profile tools run --rm --user root tools python wokwi_attack.py forge
docker compose --profile tools run --rm --user root tools python wokwi_attack.py tamper
docker compose --profile tools run --rm --user root tools python wokwi_attack.py replay
docker compose logs --tail 20 escola-wokwi-bridge

REM ------------------------------------------------------ VPN e segmentação
docker compose exec cloud-wg wg show
docker compose exec edge-ubs-agent wg show
docker compose exec field-ubs python -c "import socket; socket.create_connection(('edge-escola-broker', 8883), 3)"
docker compose exec field-ubs python -c "import socket; socket.create_connection(('broker.hivemq.com', 8883), 3)"
docker compose exec edge-ubs-agent python -c "import socket; socket.create_connection(('cloud-fibra', 8443), 3)"
docker compose exec edge-ubs-agent python -c "import socket; socket.create_connection(('postgres', 5432), 3)"

REM ---------------------------------------- banco: dados, privilégio mínimo e LGPD
docker compose exec postgres psql -U postgres -d vilaaurora -c "select space, kind, count(*) from events group by 1,2 order by 1,2;"
docker compose exec postgres psql -U ingest_writer -d vilaaurora -c "select value from events limit 1;"
docker compose exec postgres psql -U painel_reader -d vilaaurora -c "delete from events;"
docker compose exec postgres psql -U postgres -d vilaaurora -c "select space, data->>'badge_hash', data->>'decision', data->>'reason' from events where kind='access' order by ts desc limit 5;"

REM ---------------------------------------------------- regras locais da borda
docker compose --profile tools run --rm --user root tools python inject_reading.py ubs-camara-fria-01 camara_fria 12 C
docker compose logs --tail 20 edge-ubs-agent edge-escola-agent field-escola field-ubs
REM [manual] no Wokwi: potenciômetro >= 95 % (bomba desliga) e depois < 20 % (alarme e bomba liga)

REM ----------------------------------------------- painel (MFA, RBAC, SQL Injection)
docker compose exec painel python manage.py create-user ana.op operador
docker compose exec painel python manage.py create-user beto.tec tecnico
docker compose exec painel python manage.py create-user carla.coord coordenacao
docker compose exec painel python manage.py create-user davi.aud auditor
certutil -user -addstore Root pki\out\ca\ca.crt
REM [manual] abrir https://localhost:8443
REM          ana.op: cadastrar MFA; abrir /acessos (403); no Histórico buscar  x' OR '1'='1  (rejeitado)
REM          beto.tec: errar a senha 5 vezes (bloqueio); carla.coord: páginas Acessos e Auditoria
docker compose logs painel | findstr "result=negado result=falha result=bloqueado result=entrada_invalida"

REM ------------------------------------- reprodução do INC-VA-0712 (SIEM no terminal A)
docker run --rm --cap-add NET_ADMIN --network vila-aurora_seg-wan-fibra -v "%cd%\pki\out\wg\edge-horta-agent.conf:/etc/wireguard/wg0.conf:ro" --entrypoint bash vila-aurora-edge-horta-agent -c "wg-quick up wg0 && sleep 90"
docker compose exec edge-escola-agent python send_command.py escola-bomba-01 off --by painel:ana.op --reason agendamento_alterado
python siem/soar.py pending
python siem/soar.py reject <id>
python metricas/caos.py --borda ubs --minutos 5 --injetar-alarme
python siem/soar.py list
python siem/soar.py restore <id>

REM ---------------------------------------------- forense, IA e métricas
python forense/coletar.py --incidente INC-VA-LAB-01 --desde 30 --responsavel "Julia Santos"
python forense/coletar.py --verificar docs\forense\INC-VA-LAB-01_<data>
python ia/detector.py
python metricas/relatorio.py --desde 60
docker compose exec postgres psql -U postgres -d vilaaurora -c "select count(*) - count(distinct msg_id) as duplicados from events;"
```

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
- O painel é acessado em `127.0.0.1` do host, para o vídeo. Em produção, operadores remotos
  entrariam pela VPN WireGuard (mais um peer por operador) antes do login com MFA.
- Os usuários do painel ficam num SQLite local (`data/painel/`, fora do git); senhas só como hash scrypt.
- O SIEM é um mini-SIEM próprio (sem dashboard gráfico), rodando no computador do operador. Em
  produção: Wazuh ou similar, com agentes em cada nó e armazenamento à prova de adulteração.
- **Teste de caos de 5 minutos**, e não de 30: o RT-23 pede pelo menos 30 minutos. O script
  aceita `--minutos 30` e o comportamento é o mesmo (o buffer só cresce mais). A versão curta
  foi uma escolha da equipe para caber no tempo do vídeo.
- Energia do nó de borda **estimada** por modelo (Raspberry Pi 4), não medida.
- A IA foi avaliada com anomalias injetadas nos dados sintéticos, não com incidentes reais.
- A regra (d) confia no campo `by` declarado no comando. Como só o agente da borda pode publicar
  comandos (ACL), um emissor estranho indica agente comprometido; daí a revogação proposta.

---

## Uso de IA

Ferramentas de IA generativa foram usadas como apoio na estruturação do código e da
documentação. A equipe revisou, executou e é responsável por todo o conteúdo.