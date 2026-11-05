
# netsentry

> Auditor de sockets em tempo real para Windows. Lista cada endpoint ativo da sua máquina, identifica o processo dono, checa assinatura Authenticode, resolve reverse DNS e pontua o risco por heurística.

`netsentry` responde uma pergunta simples: **tem algo estranho falando com a internet agora?** Em vez de abrir o Resource Monitor e caçar processo por processo, você roda um comando e vê tudo classificado em `LOW` / `MED` / `HIGH`, com o motivo ao lado de cada linha.

![netsentry rodando]
<img width="1170" height="772" alt="{4D28B2F7-E6D8-4DA4-8A8F-8D8AB0F140FE}" src="https://github.com/user-attachments/assets/b3e828d8-dda0-4708-92e2-008b214a78b3" />


---

## O que faz

- Coleta **TCP e UDP, IPv4 e IPv6** direto da tabela de sockets do Windows (`GetExtendedTcpTable` / `GetExtendedUdpTable`).
- Resolve o **caminho completo do processo** dono de cada endpoint (`QueryFullProcessImageNameW`).
- Verifica **assinatura Authenticode** de cada binário (`WinVerifyTrust`).
- Faz **reverse DNS** com timeout de 800 ms, limitado a 64 consultas por execução pra não travar o scan.
- Aplica **heurística de risco** — porta, caminho, assinatura, processo de sistema, rDNS ausente, UDP suspeito.
- Mostra **resultado ao vivo**, com spinner por endpoint e motivos indentados abaixo das linhas `MED` / `HIGH`.
- Fecha com **summary** (contagem por faixa, tempo) e **top offenders** (os 8 piores acima do threshold).
- Exporta **JSON limpo** pra pipeline (`--json`).

---

## Build

Requer **Visual Studio 2022+** com toolchain C++ (`cl.exe` no PATH — Developer Command Prompt).

```bat
cl /std:c++20 /EHsc netsentry.cpp
```

O source usa `#pragma comment(lib, ...)` pra `iphlpapi`, `ws2_32`, `wintrust` e `crypt32`, então não precisa listar libs manualmente.

---

## Uso

```bat
netsentry.exe               :: modo live, spinner + streaming
netsentry.exe --fast        :: sem spinner, mesmo output
netsentry.exe --json        :: dump JSON puro, sem UI
netsentry.exe --json > audit.json
```

Roda sem privilégio de administrador. Alguns PIDs de sistema não permitem abrir o caminho do executável — nesses casos o processo aparece como `<pid N>` e o score de assinatura simplesmente não dispara.

---

## Scoring

Cada endpoint começa em 0 e soma pontos conforme os sinais abaixo:

| sinal | peso |
|---|---|
| porta remota na lista de C2/backdoor (`4444`, `1337`, `31337`, `6667`, `2222`, `51820`, `1080`, `9001`, `9050`, `8888`) | **+40** |
| processo em `Temp` / `Downloads` / `AppData` / `ProgramData` falando com IP público | **+30** |
| processo não assinado com saída pra IP público | **+25** |
| processo de sistema (`svchost`, `explorer`, `lsass`) falando com porta remota > 10000 | **+20** |
| UDP pra IP público fora de DNS (53) ou NTP (123) | **+15** |
| sem reverse DNS e porta remota alta (> 1024) | **+15** |

Faixas:

| score | label | cor |
|---|---|---|
| `>= 50` | `HIGH` | vermelho |
| `>= 25` | `MED` | amarelo |
| `< 25` | `LOW` | verde |

IPs privados e loopback (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `100.64/10`, `fc00::/7`, `fe80::/10`, `::1`) não somam pontos — só tráfego pra IP público conta.

---

## JSON

`--json` entrega o mesmo conjunto sem a camada visual:

```json
[
  {
    "proto": "TCP",
    "remote": "45.155.205.233",
    "port": 4444,
    "pid": 8872,
    "process": "updater32.exe",
    "path": "C:\\Users\\spek\\AppData\\Local\\Temp\\updater32.exe",
    "signed": false,
    "rdns": "",
    "score": 95,
    "reasons": [
      "remote port 4444 matches C2/backdoor list",
      "process in temp/download path talking to public IP",
      "unsigned process outbound to public IP"
    ]
  }
]
```
