# Cisco Switch Manager v0.3.2

Web app para inventario, monitoramento e operacao de switches Cisco IOS/IOS-XE.

A v0.3.2 continua orientada a ambientes em que **SNMPv2c e Telnet sao os protocolos principais**, com suporte a **SNMPv3 e SSH por switch**. Ela preserva a Sessao Cisco individual da v0.3.1 e adiciona um gerador de Banner MOTD por equipamento.

## Principais recursos

- Inventario por hostname, IP, localidade, modelo, serial e IOS/IOS-XE.
- CLI por Telnet ou SSH.
- Monitoramento por SNMPv2c ou SNMPv3.
- Credenciais SNMP criptografadas em repouso com Fernet.
- Credencial Cisco individual `adm-` mantida somente em memoria durante a sessao operacional.
- Dashboard geral online/offline e por localidade.
- Historico de disponibilidade.
- Descoberta automatica de switches Cisco via CIDR/SNMP.
- CPU, memoria, temperatura, uptime e PoE quando suportados pelas MIBs do equipamento.
- Topologia grafica CDP/LLDP.
- Localizacao de MAC.
- Gerador de Banner MOTD em lote com hostname/IP automaticos, e-mail, telefone, mensagem e previa.
- Terminal persistente.
- Atalhos de comandos.
- Backup manual de `running-config` com identidade individual.
- Backup automatico opcional somente com conta tecnica explicitamente configurada.
- Download e diff de configuracoes.
- Auditoria com usuario do portal e usuario Cisco.

## Novidades da v0.3.2

### Gerador de Banner MOTD

A tela **Banner MOTD** agora gera o conteudo automaticamente a partir dos switches selecionados. Para cada equipamento, o sistema usa o **hostname** e o **IP de gerenciamento** cadastrados no inventario e combina esses dados com:

- e-mail de contato;
- telefone de contato;
- mensagem de acesso restrito;
- opcao de salvar a configuracao apos aplicar.

Antes da aplicacao, a interface mostra uma previa individual para cada switch. Em uma aplicacao em lote, hostname e IP sao recalculados para cada equipamento; e-mail, telefone e mensagem sao comuns ao lote.

Exemplo de banner gerado:

```text
============================================================
                    ACESSO RESTRITO
============================================================
Equipamento : br-macae01-ds15
IP          : 10.0.0.15
------------------------------------------------------------
ACESSO RESTRITO. O acesso a este equipamento e permitido
somente a usuarios autorizados.
------------------------------------------------------------
E-mail      : suporte.rede@empresa.com
Telefone    : +55 22 0000-0000
============================================================
```

A aplicacao do MOTD continua exigindo uma **Sessao Cisco** ativa com o usuario individual `adm-`. O backend monta novamente o banner a partir do inventario no momento da aplicacao, evitando depender apenas da previa criada no navegador.

## Novidades da v0.3.1

### Credencial Cisco individual por integrante

O inventario nao armazena mais usuario, senha ou enable password pessoal por switch.

O fluxo operacional passa a ser:

```text
Integrante acessa o portal
        |
        v
Ativa a Sessao Cisco
usuario: adm-integrante
senha: ********
enable: opcional
        |
        v
Credencial fica somente na memoria do backend
        |
        +---- Switch 01 - Telnet/SSH
        +---- Switch 02 - Telnet/SSH
        +---- Switch 03 - Telnet/SSH
        |
        v
Logout / expiracao -> credencial removida
```

Por padrao:

- o usuario Cisco deve iniciar com `adm-`;
- a sessao dura 30 minutos;
- a senha e o enable secret nao sao gravados no SQLite;
- o navegador recebe apenas um cookie de sessao `HttpOnly`;
- o nome do usuario pode ser lembrado no navegador para facilitar o proximo login;
- cada comando CLI auditado registra o usuario Cisco que executou a operacao.

Operacoes que exigem uma Sessao Cisco ativa incluem:

- Terminal Telnet/SSH;
- comandos `show` executados via CLI;
- drill-down de interface quando houver consulta CLI;
- CDP/LLDP via CLI;
- localizacao de MAC via CLI;
- aplicacao de banner MOTD;
- backup manual de `running-config`;
- demais operacoes de configuracao.

O SNMP continua independente e utiliza a credencial tecnica cadastrada no switch para monitoramento automatico.

### Backup automatico

O backup automatico por CLI fica **desativado por padrao** na v0.3.1, porque um processo agendado nao deve reutilizar a senha pessoal de um integrante.

Se a empresa possuir uma conta tecnica exclusiva para backup, ela pode ser configurada explicitamente no `.env`:

```text
CSM_AUTOMATIC_CLI_BACKUP_ENABLED=true
CSM_BACKUP_CLI_USER=svc-csm-backup
CSM_BACKUP_CLI_PASSWORD=SENHA_DA_CONTA_TECNICA
CSM_BACKUP_CLI_SECRET=
```

Se essa conta nao existir, mantenha `CSM_AUTOMATIC_CLI_BACKUP_ENABLED=false` e utilize backup manual com a Sessao Cisco individual.

### Porta externa 8086

A aplicacao continua escutando na porta `8080` dentro do container, mas o Docker publica a porta **8086** no servidor:

```text
8086:8080
```

Acesso:

```text
http://IP_DO_SERVIDOR:8086
```

Para producao, publique a aplicacao em HTTPS usando Caddy ou Nginx.

## Mapa logico de portas

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

## Drill-down de interface

Ao clicar em uma porta, a aplicacao pode abrir uma unica sessao Telnet/SSH usando a Sessao Cisco do integrante e consultar:

```text
show interfaces <PORTA>
show mac address-table interface <PORTA>
show interfaces <PORTA> switchport
show power inline <PORTA>
show cdp neighbors <PORTA> detail
show lldp neighbors <PORTA> detail
```

O painel mostra, conforme disponibilidade do IOS/modelo:

- interface status e line protocol;
- descricao;
- input/output errors;
- trafego medio de 5 minutos;
- modo access/trunk;
- VLAN de acesso;
- native VLAN;
- VLANs permitidas no trunk;
- MACs aprendidos;
- vizinho CDP/LLDP;
- informacao PoE;
- saida CLI completa para diagnostico.

## Historico por interface

A coleta SNMP registra:

- operational status;
- administrative status;
- velocidade;
- descricao;
- input errors;
- output errors.

Para evitar crescimento excessivo do banco, o sistema grava alteracoes relevantes e um heartbeat aproximadamente a cada hora, alem do snapshot sob demanda.

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
   +-- Sessao Cisco em memoria
   |     +-- adm-integrante / senha temporaria
   |
   +-- SQLite
   |     +-- inventario
   |     +-- auditoria
   |     +-- disponibilidade
   |     +-- historico de interfaces
   |     +-- credenciais SNMP criptografadas
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
http://IP_DO_SERVIDOR:8086
```

## `.env` da v0.3.2

```text
# Login do portal
CSM_ADMIN_USER=admin
CSM_ADMIN_PASSWORD=troque-esta-senha

# Online/offline
CSM_STATUS_INTERVAL_SECONDS=300

# Retencao de disponibilidade
CSM_AVAILABILITY_RETENTION_DAYS=30

# Coleta de interfaces; minimo aceito: 300 segundos
CSM_PORT_POLL_INTERVAL_SECONDS=900

# Retencao do historico de interfaces
CSM_PORT_HISTORY_RETENTION_DAYS=30

# Sessao Cisco individual
CSM_OPERATOR_USERNAME_PREFIX=adm-
CSM_OPERATOR_SESSION_MINUTES=30

# false para acesso HTTP direto em :8086
# true quando o portal estiver publicado exclusivamente em HTTPS
CSM_SESSION_COOKIE_SECURE=false

# Remove usuario/senha/secret CLI legados salvos por switch
CSM_PURGE_LEGACY_CLI_CREDENTIALS=true

# Backup
CSM_BACKUP_INTERVAL_HOURS=24
CSM_AUTOMATIC_CLI_BACKUP_ENABLED=false

# Somente se existir conta tecnica exclusiva para backup automatico
# CSM_BACKUP_CLI_USER=svc-csm-backup
# CSM_BACKUP_CLI_PASSWORD=
# CSM_BACKUP_CLI_SECRET=
```

Para um ambiente com muitos switches, comece com `900` ou `1800` segundos para a coleta de interfaces.

## Atualizacao da v0.3.0 para v0.3.1

Antes de atualizar, preserve **todo o diretorio `data/`**:

```text
data/csm.db
data/secret.key
data/backups/
```

Exemplo:

```bash
docker compose down
cp -a cisco-switch-manager-v0.3.0/data cisco-switch-manager-v0.3.0-data-backup
cp -a cisco-switch-manager-v0.3.0/data/. cisco-switch-manager-v0.3.1/data/
cd cisco-switch-manager-v0.3.1
cp .env.example .env
nano .env
docker compose up -d --build
```

### Atencao: credenciais CLI legadas

Com `CSM_PURGE_LEGACY_CLI_CREDENTIALS=true`, no primeiro start a v0.3.1 limpa os campos legados `username_enc`, `password_enc` e `secret_enc` de todos os switches. Isso e intencional para que senhas pessoais nao continuem armazenadas por equipamento.

Se voce precisar apenas testar a migracao sem apagar imediatamente esses campos, use temporariamente:

```text
CSM_PURGE_LEGACY_CLI_CREDENTIALS=false
```

Depois de validar a nova Sessao Cisco, altere para `true` e reinicie a aplicacao.

Nao perca `data/secret.key`: ela continua necessaria para descriptografar as credenciais SNMP existentes.

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

A aplicacao usa a credencial individual informada pelo integrante na Sessao Cisco. Mantenha o modelo AAA/TACACS+/RADIUS existente sempre que aplicavel.

Exemplo de fluxo:

```text
Usuario Cisco: adm-integrante
Senha: ********
Switch>
enable            # somente quando necessario
Switch#
```

## Seguranca

Telnet e SNMPv2c nao oferecem a mesma protecao criptografica de SSH/SNMPv3. Para o ambiente atual:

- mantenha o servidor CSM na rede de gerenciamento;
- use ACLs para restringir TCP/23 e UDP/161;
- nao exponha Telnet/SNMP na Internet;
- use HTTPS no portal sempre que possivel;
- ao usar HTTPS, configure `CSM_SESSION_COOKIE_SECURE=true`;
- mantenha backup de `data/csm.db` e `data/secret.key`;
- nao configure contas pessoais `adm-` no `.env`;
- use conta tecnica de backup somente se ela existir formalmente e tiver escopo adequado;
- migre gradualmente equipamentos compativeis para SSH/SNMPv3 quando oportuno.

## Arquivos principais

```text
backend/main.py              API, schedulers, dashboards e historicos
backend/operator_session.py  sessao temporaria da credencial Cisco individual
backend/network.py           Telnet/SSH, terminal, CDP/LLDP e backups
backend/port_detail.py       drill-down de interface em uma sessao CLI
backend/snmp.py              SNMPv2c/v3, interfaces e telemetria
backend/models.py            modelos SQLite/SQLAlchemy
backend/migrate.py           migracoes e limpeza opcional das credenciais CLI legadas
static/index.html            interface web
static/app.js                comportamento do frontend
static/styles.css            layout e mapa de portas
```

## Compatibilidade Cisco

A coleta depende dos comandos e MIBs disponiveis no modelo/IOS. Campos nao suportados aparecem como `N/D` ou mantem a saida bruta para diagnostico. Antes de liberar para todo o parque, valide a v0.3.2 em alguns modelos representativos, por exemplo Catalyst 2960/3560/3750/9200/9300 existentes no ambiente.
