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
