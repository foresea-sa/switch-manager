# Changelog

## v0.3.3

- Interface, titulo, pacote e container renomeados para **Switch Manager**.
- Removida a identidade nominal do fabricante das areas visiveis da aplicacao.
- Container padrao renomeado para `switch-manager`.
- Plataforma exibida como `IOS / IOS-XE`; o identificador tecnico do driver fica restrito ao backend.
- Adicionados **Importar TXT**, **Exportar TXT** e **Modelo TXT** no Inventario.
- Importacao em modo upsert: mesmo hostname ou IP atualiza o cadastro; item novo cria um switch.
- Exportacao TXT exclui credenciais e segredos.
- Importacao aceita hostname, IP, localidade, plataforma, protocolo, portas, SNMP, modelo, serial, versao e observacoes.
- Mantidos Banner MOTD, sessao CLI individual, SNMP, dashboards, topologia, MAC, terminal, backups e auditoria.
