# ADR 0001 — SQLite oficial, PostgreSQL experimental

Data: 09/11/2026. Estado: adotado para a implementação V4; decisão reversível.

SQLite WAL permanece o banco oficialmente suportado, com um processo/worker por instalação e diretório persistente com permissões restritas. As migrações e testes existentes usam SQLite e preservam triagem, inventários e observações; não há evidência de execução da aplicação sobre PostgreSQL nesta revisão.

PostgreSQL permanece **experimental / NÃO VALIDADO**. Suporte nominal do SQLAlchemy não comprova comportamento equivalente para JSON, datas, migrações, consultas e concorrência. Não serão feitas promessas de múltiplos workers, alta disponibilidade ou isolamento entre organizações com base nessa configuração.

Para promover PostgreSQL: teste de upgrade V2→atual com preservação, suíte de integração e relatórios completa, concorrência dos jobs, cancelamento, backup/restauração e job de CI específico. Até isso ocorrer, dimensionar uma instância do VulnRadar por workspace, com autenticação da equipe e volumes protegidos.
