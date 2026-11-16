#!/bin/sh
# =====================================================================
#  Banco da nuvem (Rede Vila Aurora) - roda só na primeira inicialização
#  do volume do PostgreSQL. Papéis com privilégio mínimo (RT-08):
#    ingest_writer : INSERT em events + leitura só da coluna msg_id (idempotência)
#    painel_reader : só SELECT (painel; usado na etapa do SQL Injection)
# =====================================================================
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
-- ninguém cria objetos no schema public além do dono
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE ${POSTGRES_DB} FROM PUBLIC;

CREATE TABLE events (
    msg_id      uuid PRIMARY KEY,                 -- chave de idempotência
    kind        text        NOT NULL CHECK (kind IN ('telemetry','alarm','command','access')),
    space       text        NOT NULL,
    device_id   text        NOT NULL,
    sensor      text,
    value       double precision,
    unit        text,
    ts          timestamptz NOT NULL,             -- horário do evento (UTC, na borda)
    received_at timestamptz NOT NULL DEFAULT now(),
    agent       text        NOT NULL,             -- CN do certificado que enviou
    data        jsonb       NOT NULL
);
CREATE INDEX idx_events_space_ts ON events (space, ts DESC);
CREATE INDEX idx_events_kind ON events (kind);

CREATE ROLE ingest_writer LOGIN PASSWORD '${INGEST_DB_PASSWORD}';
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ingest_writer;
GRANT USAGE ON SCHEMA public TO ingest_writer;
GRANT INSERT ON events TO ingest_writer;
-- ON CONFLICT (msg_id) exige ler a coluna-árbitro; liberamos SÓ essa coluna
GRANT SELECT (msg_id) ON events TO ingest_writer;

CREATE ROLE painel_reader LOGIN PASSWORD '${PAINEL_DB_PASSWORD}';
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO painel_reader;
GRANT USAGE ON SCHEMA public TO painel_reader;
GRANT SELECT ON events TO painel_reader;
EOSQL

echo "Esquema e papeis criados (ingest_writer: INSERT + SELECT(msg_id); painel_reader: SELECT)."
