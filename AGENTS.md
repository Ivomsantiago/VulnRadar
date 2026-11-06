# VulnRadar

Leia docs/PRODUCT_SPEC.md, docs/PRODUCT_SPEC_V2.md, docs/V2_AUDIT.md e docs/IMPLEMENTATION_STATUS.md antes de alterar o projeto.
KPIs de exposição devem usar achados observados em projetos; nunca substituir por contagens de CVEs globais.
Preserve inventários e achados por migrações aditivas. Scans parciais não podem resolver achados por ausência.
Use scripts/start_test_server.py para testes de navegador com banco descartável; não misture fixtures com o banco operacional.
Use o checkout existente; cada tarefa de nuvem já é isolada. Não crie worktrees sem pedido explícito.
Nunca use dados fictícios em produção, execute scripts de repositórios analisados ou declare ausência de resultados como prova de segurança.
Execute testes de backend e frontend ao alterar os respectivos componentes. Não faça push sem autorização.
