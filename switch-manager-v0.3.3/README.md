# Switch Manager v0.3.3

Web app para inventario, monitoramento e operacao de switches IOS/IOS-XE.

A v0.3.3 e uma versao **white-label**: a identidade do fabricante foi removida da interface, titulo, pacote, container e documentacao. O backend preserva apenas identificadores tecnicos indispensaveis aos drivers e MIBs usados para interoperabilidade.

## Principais recursos

- Inventario por hostname, IP, localidade, modelo, serial e versao de software.
- Importacao e exportacao do inventario em `.txt`.
- CLI por Telnet ou SSH com credencial administrativa individual `adm-`.
- Monitoramento por SNMPv2c ou SNMPv3.
- Dashboard geral online/offline e por localidade.
- Historico de disponibilidade e interfaces.
- Descoberta automatica via CIDR/SNMP.
- Topologia CDP/LLDP.
- Localizacao de MAC.
- Gerador de Banner MOTD com hostname, IP, e-mail, telefone e mensagem de acesso restrito.
- Terminal persistente, atalhos e auditoria.
- Backup de `running-config`.

## Inventario TXT

Na tela **Inventario** existem tres controles:

- **Modelo TXT**: baixa somente o cabecalho aceito pelo importador.
- **Exportar TXT**: baixa o inventario atual.
- **Importar TXT**: cria novos switches e atualiza os existentes quando hostname ou IP ja existem.

Formato UTF-8, separado por ponto e virgula:

```text
hostname;management_ip;site;platform;protocol;port;snmp_version;snmp_port;monitor_method;model;serial;software_version;notes
SW-CORE-01;10.10.10.10;Macae;ios;telnet;23;v2c;161;snmp;C9200;ABC123;17.x;Core principal
```

Campos obrigatorios: `hostname`, `management_ip` (ou `ip`) e `site`/`localidade`.

**Seguranca:** community SNMP, chaves SNMPv3, senhas CLI e enable secret nao sao exportados nem importados pelo TXT. O objetivo do arquivo e transportar a lista de inventario, nao credenciais.

## Sessao CLI individual

Cada integrante informa seu usuario `adm-`, senha e, opcionalmente, enable secret. A senha permanece apenas em memoria durante a sessao operacional e nao e gravada no SQLite.

## Instalacao Docker

```bash
cp .env.example .env
nano .env
docker compose up -d --build
```

Acesso padrao:

```text
http://IP_DO_SERVIDOR:8086
```

O container da v0.3.3 se chama:

```text
switch-manager
```

## Atualizacao da v0.3.2

Pare a versao anterior e preserve todo o diretorio `data/`:

```bash
docker compose down
cp -a /CAMINHO/DA/VERSAO_ANTERIOR/data/. ./data/
cp /CAMINHO/DA/VERSAO_ANTERIOR/.env ./.env
docker compose up -d --build
```

Nao perca `data/csm.db` nem `data/secret.key`.

## Variaveis principais

```text
CSM_ADMIN_USER=admin
CSM_ADMIN_PASSWORD=troque-esta-senha
CSM_STATUS_INTERVAL_SECONDS=300
CSM_BACKUP_INTERVAL_HOURS=24
CSM_AVAILABILITY_RETENTION_DAYS=30
CSM_PORT_POLL_INTERVAL_SECONDS=900
CSM_PORT_HISTORY_RETENTION_DAYS=30
CSM_OPERATOR_USERNAME_PREFIX=adm-
CSM_OPERATOR_SESSION_MINUTES=30
CSM_SESSION_COOKIE_SECURE=false
CSM_PURGE_LEGACY_CLI_CREDENTIALS=true
CSM_AUTOMATIC_CLI_BACKUP_ENABLED=false
```

Para publicacao por HTTPS, altere `CSM_SESSION_COOKIE_SECURE=true`.
