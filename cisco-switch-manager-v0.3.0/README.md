# Cisco Switch Manager v0.3.0

Web app para inventario, monitoramento e operacao de switches Cisco IOS/IOS-XE.

A v0.3 continua orientada a ambientes em que **SNMPv2c e Telnet sao os protocolos principais**, permitindo configurar **SNMPv3 e SSH individualmente por switch**.

## Principais recursos

- Inventario por hostname, IP, localidade, modelo, serial e IOS/IOS-XE.
- CLI por Telnet ou SSH.
- Monitoramento por SNMPv2c ou SNMPv3.
- Credenciais criptografadas em repouso com Fernet.
- Dashboard geral online/offline e por localidade.
- Historico de disponibilidade.
- Descoberta automatica de switches Cisco via CIDR/SNMP.
- CPU, memoria, temperatura, uptime e PoE quando suportados pelas MIBs do equipamento.
- Topologia grafica CDP/LLDP.
- Localizacao de MAC.
- Banner MOTD em lote.
- Terminal persistente.
- Atalhos de comandos.
- Backup manual e automatico de `running-config`.
- Download e diff de configuracoes.
- Auditoria de operacoes.

## Novidades da v0.3

### Mapa logico de portas

O dashboard individual representa as interfaces como um chassi logico:

```text
Gi1/0
+--------+--------+--------+--------+--------+
| Gi1/0/1| Gi1/0/2| Gi1/0/3| Gi1/0/4|  ...   |
|   UP   |  DOWN  |   UP   | ERRORS |        |
+--------+--------+--------+--------+--------+
```

Estados visuais:

- verde: connected;
- cinza: desconectada/inativa;
- vermelho: interface com erros;
- azul: porta selecionada.

A tela permite filtrar portas conectadas, desconectadas, com erros e pesquisar por interface/descricao/VLAN.

### Drill-down de interface

Ao clicar em uma porta, a aplicacao abre uma unica sessao Telnet/SSH e consulta:

```text
show interfaces <PORTA>
show mac address-table interface <PORTA>
show interfaces <PORTA> switchport
show power inline <PORTA>
show cdp neighbors <PORTA> detail
show lldp neighbors <PORTA> detail
```

O painel mostra:

- interface status e line protocol;
- descricao;
- input/output errors;
- trafego medio de 5 minutos quando fornecido pelo IOS;
- modo access/trunk;
- VLAN de acesso;
- native VLAN;
- VLANs permitidas no trunk;
- MACs aprendidos;
- vizinho CDP/LLDP;
- informacao PoE;
- saida CLI completa para diagnostico.

Os botoes **Show interface**, **MAC table**, **Switchport** e **PoE** preparam o comando correspondente no Terminal.

### Historico por interface

A v0.3 cria a tabela `interface_samples` automaticamente no SQLite.

A coleta usa SNMP para registrar:

- operational status;
- administrative status;
- velocidade;
- descricao;
- input errors;
- output errors.

Para evitar crescimento excessivo do banco, o sistema grava:

1. alteracoes de estado ou contadores; e
2. um heartbeat aproximadamente a cada hora mesmo sem mudanca.

Existe tambem o botao **Registrar snapshot**, que dispara uma coleta sob demanda.

## Arquitetura

```text
Browser
   |
 HTTPS recomendado
   |
 Caddy / Nginx
   |
 FastAPI - Cisco Switch Manager
   |
   +-- SQLite
   |    +-- inventario
   |    +-- auditoria
   |    +-- disponibilidade
   |    +-- historico de interfaces
   |
   +-- data/backups -> running-config
   |
   +-- UDP/161 -> SNMPv2c ou SNMPv3
   |
   +-- TCP/23  -> Telnet
   +-- TCP/22  -> SSH
          |
       Switches Cisco
```

O navegador nunca acessa Telnet, SSH ou SNMP diretamente. As conexoes partem do servidor do Cisco Switch Manager.

## Instalacao com Docker

```bash
cp .env.example .env
```

Edite pelo menos:

```text
CSM_ADMIN_USER=admin
CSM_ADMIN_PASSWORD=uma-senha-forte
```

Suba a aplicacao:

```bash
docker compose up -d --build
```

Acesse:

```text
http://IP_DO_SERVIDOR:8080
```

Para producao, publique a aplicacao em HTTPS usando Caddy ou Nginx.

## Atualizacao da v0.2 para v0.3

Preserve **todo o diretorio `data/`** da instalacao anterior. Principalmente:

```text
data/csm.db
data/secret.key
data/backups/
```

Exemplo:

```bash
docker compose down
cp -a ../cisco-switch-manager-v0.2.0/data ./data
docker compose up -d --build
```

Nao perca `data/secret.key`: ela e necessaria para descriptografar as credenciais existentes.

Nao e necessario criar a tabela de historico manualmente. `interface_samples` e criada automaticamente no primeiro start da v0.3.

## Configuracoes automaticas

`.env`:

```text
# Online/offline
CSM_STATUS_INTERVAL_SECONDS=300

# Backup automatico de running-config
CSM_BACKUP_INTERVAL_HOURS=24

# Retencao de disponibilidade
CSM_AVAILABILITY_RETENTION_DAYS=30

# Coleta de interfaces; minimo aceito: 300 segundos
CSM_PORT_POLL_INTERVAL_SECONDS=900

# Retencao do historico de interfaces
CSM_PORT_HISTORY_RETENTION_DAYS=30
```

Para um ambiente com muitos switches, comece com `900` ou `1800` segundos para a coleta de interfaces.

## SNMPv2c

Exemplo Cisco conceitual:

```text
conf t
access-list 20 permit IP_DO_SERVIDOR_CSM
snmp-server community SUA_COMMUNITY RO 20
end
write memory
```

Restrinja a community ao endereco do servidor CSM e a rede de gerenciamento.

## Telnet legado

Exemplo conceitual:

```text
conf t
username csm privilege 15 secret SENHA_FORTE
line vty 0 15
 login local
 transport input telnet
end
write memory
```

Se o ambiente usa AAA/TACACS+/RADIUS, mantenha o padrao corporativo existente.

## Seguranca

Telnet e SNMPv2c nao oferecem a mesma protecao criptografica de SSH/SNMPv3. Para o ambiente atual:

- mantenha o servidor CSM na rede de gerenciamento;
- use ACLs para restringir TCP/23 e UDP/161;
- nao exponha Telnet/SNMP na Internet;
- use HTTPS no portal;
- mantenha backup de `data/csm.db` e `data/secret.key`;
- use uma conta operacional dedicada ou AAA corporativo;
- migre gradualmente equipamentos compativeis para SSH/SNMPv3 quando oportuno.

## Arquivos principais

```text
backend/main.py         API, schedulers, dashboards e historicos
backend/network.py      Telnet/SSH, terminal, CDP/LLDP e backups
backend/port_detail.py  drill-down de interface em uma sessao CLI
backend/snmp.py         SNMPv2c/v3, interfaces e telemetria
backend/models.py       modelos SQLite/SQLAlchemy
static/index.html       interface web
static/app.js           comportamento do frontend
static/styles.css       layout e mapa de portas
```

## Compatibilidade Cisco

A coleta depende dos comandos e MIBs disponiveis no modelo/IOS. Campos nao suportados aparecem como `N/D` ou mantem a saida bruta para diagnostico. Antes de liberar para todo o parque, valide a v0.3 em alguns modelos representativos, por exemplo Catalyst 2960/3560/3750/9200/9300 existentes no ambiente.
