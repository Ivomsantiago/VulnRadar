# Auditoria e arquitetura da informação V2

Base auditada: main 3395cc4, PR #1 integrado. CI Linux e build Windows aprovados no GitHub; executar um binário Windows continua diferente de somente compilar.

## Problemas encontrados
- Dashboard apresenta volume global como informação principal, sem exposição de aplicações.
- Achados e inventários existem somente no JSON de scans. Não há fila de remediação por achado.
- Resultados de scan mostram JSON bruto; faltam etapas, pré-requisitos e tabelas de evidências.
- Busca global só redireciona ao feed; não pesquisa projetos ou agrupa tecnologias.
- Feed usa filtros inline, sem favoritos, colunas/densidade ou tabs de investigação.
- Sidebar não representa as jornadas V2; mobile apenas oculta rótulos.
- Cores estão repetidas no CSS; dialogs têm comportamentos diferentes.
- Source registra último resultado, mas não duração, paginação, novos/atualizados ou histórico de execução próprio.

## Mapa de jornadas

Overview → exposição dos projetos → prioridade → finding → evidência/versão → triagem com justificativa → reanálise.
Inteligência → feed filtrado → vulnerabilidade → componentes/exploração/projetos/histórico.
Repositórios → selecionar diretório autorizado → detectar tecnologias/pré-requisitos → SCA/SAST/combinado → etapas → resultados/inventário/histórico.
Tecnologias → pacote estruturado → advisories → monitorar → watchlist → alertas.
Ctrl+K → resultados agrupados → investigação sem trocar sucessivamente de telas.

## Contratos e preservação
- Nova migração aditiva; scans e triagens existentes permanecem.
- Inventários por execução, achados por projeto/motor/identidade e observações por scan.
- Correspondência SCA é evidência de pacote/versão, não explorabilidade ou alcance.
- Resolver automaticamente somente com comparação completa e escopo compatível; partial nunca resolve por ausência.
- KPIs de exposição usam achados persistidos, jamais contagens globais como substitutos.
- Links antigos continuam válidos por redirects/rotas compatíveis.
- Tokens de tema e componentes Drawer/Dialog/Tabs/KPI/Paginação compartilhados.
- Não há dados fictícios no banco operacional. Testes e capturas com fixtures são identificados.
