# Radar de publicações por período

O fluxo principal agora começa pela inteligência de vulnerabilidades, conforme a orientação do usuário: escolher período, puxar publicações e organizar a investigação das críticas/altas. O dashboard de exposição local continua disponível em `/exposure`; não mistura seus achados com CVEs globais.

## Como usar

1. Abra a página inicial e escolha **Últimas 24h**, **7 dias**, **1 mês** (30 dias), **3 meses** (90 dias) ou **Escolher datas**.
2. Escolha **Publicadas no período** ou **Atualizadas no período**. Uma CVE antiga atualizada hoje não é tratada como nova publicação.
3. Clique em **Buscar vulnerabilidades**. NVD e GitHub são consultados para o intervalo selecionado, com paginação e progresso por fonte. KEV/EPSS podem enriquecer os registros retornados.
4. Use a lista inicial **Críticas e altas**, ordenada por severidade, depois KEV/EPSS/CVSS e data. A maior severidade informada nos advisories atuais é priorizada; a nota CVSS pertence à mesma avaliação. Divergências ficam no detalhe por fonte.
5. Selecione publicações e clique em **Adicionar à investigação**. A fila persiste ao recarregar. Isso organiza a investigação e não confirma aplicabilidade a um repositório.
6. Exporte CSV/JSON com os filtros atuais. A exportação tem limite de 5000 linhas, com sinalização de truncamento no JSON e headers do CSV; refine o período quando necessário.

## Comportamento e precisão

- O período filtra a data da publicação/atualização informada pela fonte, não o momento em que o navegador abriu a tela ou em que a coleta foi iniciada. Datas sem informação verificável não são inventadas.
- O filtro de tela trabalha com a base local. O botão de busca é que traz páginas remotas daquele período. Trocar o filtro não faz chamadas remotas silenciosas.
- Intervalos personalizados aceitam até 366 dias. Janelas NVD maiores são divididas em segmentos de até 119 dias. A coleta não avança nem sobrescreve os checkpoints incrementais existentes.
- O GitHub pagina por cursor `after` extraído do Link. Cursores repetidos são erro de consulta incompleta; não repetimos a primeira página usando `page=N`. A API recebe timestamps UTC sem microssegundos e a aplicação também confere o limite exato de cada registro.
- Falhas parciais, cancelamento ou reinício preservam as páginas já salvas. A última coleta e seu intervalo continuam visíveis. Erros não são apresentados como conclusão bem-sucedida.
- Mirrors sem classificação não apagam uma severidade crítica conhecida. A correção de cache preserva as evidências originais e a triagem. Alterações posteriores das avaliações das fontes continuam sendo aplicadas.
- KEV/EPSS ausentes não são pontuações zero. O radar não afirma ausência de exploração quando não houve consulta KEV. Uma publicação não comprova exploração ou exposição local.
- A interface móvel apresenta os registros em cartões, com seleção por página, e evita rolagem horizontal global. O desktop usa tabela com seleção, filtros e paginação.

## Implementação

- `frontend/src/Radar.tsx` e `radar.css`: página inicial e apresentação desktop/móvel.
- `backend/app/radar.py`: consultas por janela, coleta paginada, cancelamento, fila e exportação.
- `RadarCollection` e migração aditiva `0007`: janela, estado, páginas recebidas e progresso por fonte.
- `services/intelligence.py`: cursor GitHub compartilhado com a coleta incremental e preservação de classificação conhecida.
- URLs, análise de repositórios, OCI, monitoramento e relatórios anteriores preservados.

## Validação

Regressões cobrem janelas exatas de 24h/mês/datas personalizadas, offsets de timezone, críticas antes de altas, fila persistida, exportação filtrada, aliases entre NVD/GitHub, falhas após página salva, cancelamento, recuperação de reinício, paginação por cursor e classificação não apagada por mirrors sem nota.

Playwright exercita o fluxo de 24h → um mês → coleta → críticas/altas → fila → recarga → CSV, além de responsividade e acessibilidade. A suíte reproduzível usa fixtures claramente identificadas em banco descartável. A coleta real de um mês foi executada separadamente contra NVD/GitHub, também em banco descartável, e está ilustrada nas capturas `screenshots/radar/1440/radar-real-month.png`.

O modo operacional não carrega fixtures. Servidores de teste desativam webhooks para impedir notificações externas. Fontes continuam sujeitas a atualização, limites e disponibilidade próprios; chaves opcionais aumentam as cotas.

Resultados de 06/11/2026: 112 testes backend passaram, incluindo 9 verificações externas; 7 testes frontend e o build passaram. A suíte de navegador passou em 15 cenários, com 1 cenário OCI opcional desativado, incluindo 19 rotas em 6 larguras e verificação automatizada de acessibilidade. A migração operacional `0006 → 0007` preservou integralmente os registros das 18 tabelas anteriores, com backup SQLite consistente e integridade conferida.

Na coleta mensal real, NVD retornou 17.605 registros em 9 páginas e GitHub retornou 18.692 advisories em 187 páginas: 36.297 registros recebidos, consolidados em 20.173 vulnerabilidades. Após reconciliar avaliações sem nota, a janela continha 1.541 críticas e 7.012 altas. Essa execução não solicitou KEV/EPSS; a tela sinaliza a ausência de consulta. Números são evidência daquela execução, não valores fixos do produto.
