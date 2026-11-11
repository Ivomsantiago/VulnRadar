# Branches permanentes

Política confirmada em 11/11/2026: **trabalhar sempre na `main`**, sem criar branches por tarefa. Existem somente três branches permanentes:

| Branch | Finalidade e estado na reorganização |
| --- | --- |
| `main` | Trabalho solicitado pelo usuário e linha principal. O remoto permanece em `79eff96`; o checkout local contém os commits V4 já revisados e correções em andamento, ainda sem publicação de código |
| `dev` | Preserva a linha de radar por período anteriormente em `feat/intelligence-period-radar`, commit `eb85e52`. Contém trabalho não integrado; precisa de conciliação com a main antes de promoção |
| `homologue` | Preserva a candidata V4 anteriormente em `v4/revisao`, commit `c1ce55d`, para homologação. Não representa aprovação automática de produção |

As branches representam estágios diferentes, não cópias sincronizadas automaticamente. A reorganização não resolve divergências de funcionalidades ou migrações entre elas, não altera o banco operacional e não promove versões para produção.

O GitHub encerrou automaticamente o PR #5 ao remover seu nome de branch antigo. Seu commit `eb85e52` permanece intacto na `dev`; não houve descarte do trabalho nem novo PR/commentário enviado nesta operação.

## Preservação e migração

As pontas anteriores foram salvas em bundle Git completo em `.git/branch-backups/before-main-dev-homologue-20261111.bundle`, validado por `git bundle verify`. O commit exclusivo `d33d67d` permanece também na tag remota `archive/vulnradar-v3-20261111`. Os demais commits das branches antigas permanecem alcançáveis por main, dev ou homologue.

Refs antigas: `feat/vulnradar-platform`, `feat/vulnradar-v2`, `feat/vulnradar-v3`, `feat/vulnradar-v3-complete`, `feat/intelligence-period-radar` e `v4/revisao`. A migração cria os destinos e remove esses nomes em um push atômico, com leases para rejeitar alterações concorrentes. `origin/main` não é atualizado nessa operação.

Verificação: `git branch -vv`, `git ls-remote --heads origin` e comparação dos SHAs com as pontas preservadas. O backup permite recuperar refs antigas localmente; não há reescrita de histórico ou force-push sobre main/dev/homologue.

A autorização para reorganizar essas refs não publica as correções de aplicação em andamento, não cria releases e não altera permissões ou proteção de branch. Não há promoção automática entre ambientes.
