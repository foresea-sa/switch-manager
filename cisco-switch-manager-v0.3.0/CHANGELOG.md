# Changelog

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
