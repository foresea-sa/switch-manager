# Changelog

## v0.3.2

- Novo **Gerador de Banner MOTD**.
- Hostname e IP de gerenciamento sao preenchidos automaticamente a partir do inventario.
- Campos obrigatorios de e-mail, telefone e mensagem de acesso restrito.
- Previa individual do banner antes da aplicacao.
- Aplicacao em lote gera um banner diferente para cada switch, mantendo hostname/IP corretos.
- Backend reconstrui o banner usando os dados reais do inventario no momento da aplicacao.
- E-mail e telefone ficam lembrados localmente no navegador para agilizar operacoes futuras.
- Mantida a Sessao Cisco individual `adm-` e a auditoria da operacao.
- Porta externa permanece **8086**.

## v0.3.1

- Nova **Sessao Cisco individual** para credenciais `adm-` de cada integrante.
- Senha e enable secret pessoais permanecem somente em memoria durante a sessao e nao sao persistidos no SQLite.
- Removidos usuario/senha/enable pessoal dos formularios de cadastro e descoberta de switches.
- Terminal, comandos CLI, CDP/LLDP, busca de MAC, MOTD, drill-down CLI e backup manual usam a credencial individual ativa.
- Auditoria passa a registrar `portal_user` e `operator_user`.
- Migracao adiciona os novos campos de auditoria e pode limpar credenciais CLI legadas por switch.
- `CSM_PURGE_LEGACY_CLI_CREDENTIALS=true` por padrao.
- Backup CLI automatico desativado por padrao; pode ser ativado somente com conta tecnica explicitamente configurada.
- Porta publicada pelo Docker alterada de `8080` para **`8086`**; a porta interna do container permanece `8080`.
- Novo `.env.example` completo para a v0.3.1.
- Pacote novo nao distribui uma `data/secret.key` precriada; novas instalacoes geram sua propria chave no primeiro start.

## v0.3.0

- Mantidos **SNMPv2c + Telnet** como padroes operacionais do cadastro.
- Mantido suporte opcional a SNMPv3 e SSH por equipamento.
- Novo **mapa logico de interfaces** no dashboard individual do switch.
- Filtros por portas conectadas, desconectadas, com erros e busca por nome/descricao/VLAN.
- Drill-down ao clicar em uma interface.
- Detalhe por porta via uma unica sessao Telnet/SSH:
  - estado da interface e line protocol;
  - descricao;
  - taxa de entrada/saida de 5 minutos quando fornecida pelo IOS;
  - input/output errors;
  - switchport, modo operacional, VLAN de acesso, native VLAN e VLANs de trunk;
  - MAC addresses aprendidos naquela interface;
  - CDP/LLDP da interface;
  - saida PoE;
  - saidas CLI completas para diagnostico.
- Novos atalhos do detalhe da porta para preparar comandos no Terminal.
- Novo historico por interface usando SNMP.
- Coleta otimizada: grava alteracoes de estado/contadores e heartbeat horario, reduzindo crescimento do SQLite.
- Botao para registrar snapshot SNMP de portas sob demanda.
- Retencao configuravel do historico de interfaces.
- Topologia CDP/LLDP agora permite clicar em switches cadastrados e abrir diretamente o dashboard do equipamento.
- Nova tabela SQLite `interface_samples`, criada automaticamente no primeiro start da v0.3.
- Compatibilidade preservada com banco e `secret.key` da v0.2.

## v0.2.0

- SNMPv2c/SNMPv3 por equipamento.
- Telnet/SSH por equipamento.
- Descoberta automatica SNMP.
- Dashboard de CPU, memoria, temperatura, PoE e uptime.
- Status e erros de interfaces.
- Historico de disponibilidade.
- Topologia CDP/LLDP.
- Terminal persistente.
- Backup e diff de running-config.
