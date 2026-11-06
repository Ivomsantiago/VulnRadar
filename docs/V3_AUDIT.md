# Auditoria V3

Base: main b075aab (PR #2 integrado, CI Linux/Windows aprovados).

Prioridade 1: identidade SAST depende da linha; correções SCA agregam pacotes não correspondentes; nested node_modules recebe classificação direta incorreta; aceites sem validade; comparação não registra recorrência separadamente.
Prioridade 2: consultas OSV sequenciais; leitura de manifests sem proteção equivalente ao snapshot SAST; relatórios limitados à base global; UI com textos abaixo de 12px.
Prioridade 3: OCI opcional, parsers históricos, filtros CPE/fornecedor, fontes conflitantes e jornadas adicionais. Preservar contratos e dados por migrações aditivas.

Execução: correções com regressões → remediação e relatórios conectados → legibilidade/navegação → testes completos e registro das limitações. Não expor API remotamente nem executar código dos alvos.

## Fechamento da auditoria

As três prioridades foram implementadas e conectadas. A V3 agora inclui OCI opcional com dois scanners reais, índice CPE e monitoramento de runtimes, oito jornadas, batch OSV remoto, histórico imutável e PDF servidor. Novas regressões cobrem aliases/versões de lockfile, cancelamento de processo por PID, checkpoint NVD atrasado, distinção entre publicação/coleta/descoberta e preservação dos campos de remediação na migração 0006.

Falhas detectadas durante validação foram corrigidas: envio dos campos de atribuição; comparação de datas com offset; seletor acessível dos motores OCI; metadados de validade da base Grype; região de histórico rolável acessível por teclado. Os resultados e os limites intrínsecos estão em V3_ACCEPTANCE.md e V3_STATUS.md.
