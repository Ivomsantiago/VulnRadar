# Auditoria V3

Base: main b075aab (PR #2 integrado, CI Linux/Windows aprovados).

Prioridade 1: identidade SAST depende da linha; correções SCA agregam pacotes não correspondentes; nested node_modules recebe classificação direta incorreta; aceites sem validade; comparação não registra recorrência separadamente.
Prioridade 2: consultas OSV sequenciais; leitura de manifests sem proteção equivalente ao snapshot SAST; relatórios limitados à base global; UI com textos abaixo de 12px.
Prioridade 3: OCI opcional, parsers históricos, filtros CPE/fornecedor, fontes conflitantes e jornadas adicionais. Preservar contratos e dados por migrações aditivas.

Execução: correções com regressões → remediação e relatórios conectados → legibilidade/navegação → testes completos e registro das limitações. Não expor API remotamente nem executar código dos alvos.
