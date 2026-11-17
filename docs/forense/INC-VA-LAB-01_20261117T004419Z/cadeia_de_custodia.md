# Cadeia de custódia — INC-VA-LAB-01

| Campo | Valor |
|---|---|
| Responsável pela coleta | Julia Santos |
| Data/hora da coleta (UTC) | 2026-11-17T00:44:19+00:00 |
| Janela coletada (UTC) | 2026-11-17T00:14:19+00:00 a 2026-11-17T00:44:19+00:00 |
| Local / estação | jubs (Windows 11) |
| Método | exportacao somente-leitura do banco do SIEM (SQLite, mode=ro) e COPY do PostgreSQL; SHA-256 calculado imediatamente apos a escrita de cada arquivo |
| Hash do manifesto (SHA-256) | `6389b003404f6126557528eb01e77fea71f47970d3e86f25af827ef4ba0d9a37` |

## Arquivos coletados

| Arquivo | Bytes | Registros | SHA-256 |
|---|---|---|---|
| acoes_soar.csv | 1330 | 6 | `7aef45df5a5247a1f02e2cb68a30f82ac9438aa6a6a3eec050bdc7a181525a8a` |
| alertas.csv | 2261 | 7 | `77b8fad83455fc02b5e0e2493ad55927f6329d244d53eb9f5b5d22647b93ce14` |
| crl.pem | 422 | - | `0ba6dc3c97f24a28cc884583aef7b87b7fac57e9b4fdf7ee06c768a97ef3553e` |
| eventos_nuvem.csv | 1353031 | 3309 | `eb1a3d6403fb072be0b442b80c0c519b191daf2e1e9b23bbaccdfd8d6e372de4` |
| linha_do_tempo.csv | 125261 | 752 | `f80f82fc758114c87fc932e5ce096ca3eb9e5e6025281cfcd0448e3f32841878` |
| logs.csv | 358438 | 2379 | `6e03fc0fa58189fa12aaa57d092911d1856efe5065f10bb1f52e158686c4f271` |

## Registro de transferências

| Data/hora (UTC) | De | Para | Motivo | Hash do manifesto conferido? |
|---|---|---|---|---|
| 2026-11-17T00:44:19+00:00 | ambiente de laboratório | Julia Santos | coleta inicial | sim |
| | | | | |

Para verificar a integridade: `python forense/coletar.py --verificar <esta pasta>`
