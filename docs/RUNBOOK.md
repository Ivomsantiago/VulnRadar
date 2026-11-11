# Operação V4

Leia primeiro o [estado verificável](IMPLEMENTATION_STATUS.md). Este runbook descreve configuração implementada; homologação no servidor privado, carga concorrente, restauração operacional e infraestrutura ainda precisam ser executadas nesse ambiente.

## Equipe em servidor privado

Use uma conta de serviço sem privilégios administrativos, volume local persistente com ACL restrita, backup externo criptografado e um processo/worker. O workspace é compartilhado: viewer pode ler/exportar todos os projetos. Não há separação entre organizações ou autorização por projeto. Restrinja o acesso à rede privada/VPN e desative SAST local no servidor compartilhado; importe SARIF do executor isolado.

1. Instale com `scripts/install.ps1` ou `scripts/install.sh`; revise o backup criado se já houver banco. Nunca execute o launcher de testes neste serviço.
2. Gere uma chave por pessoa: `.venv/Scripts/python.exe scripts/create_access_key.py analyst-01 --role analyst --days 30`. Guarde/transmita a chave por canal seguro. Mescle somente os objetos de configuração/hash em `VULNRADAR_ACCESS_KEYS`. O helper aceita até 90 dias. Não reutilize chaves nem use senhas humanas.
3. Configure `.env`, certificado/chave TLS e permissões. Exemplo sem credenciais reais:

```dotenv
VULNRADAR_ACCESS_MODE=team
VULNRADAR_ALLOWED_HOSTS=["radar.interno.example","127.0.0.1"]
VULNRADAR_ORIGINS=["https://radar.interno.example:8443"]
VULNRADAR_ALLOWED_ROOTS=[]
VULNRADAR_DATABASE_URL=sqlite:///./data/vulnradar.db
VULNRADAR_ACCESS_KEYS={}
VULNRADAR_OSV_QUERIES_ENABLED=false
VULNRADAR_STORE_CODE_SNIPPETS=false
VULNRADAR_ALLOW_LOCAL_SAST_IN_TEAM=false
VULNRADAR_AUTO_SYNC=false
```

`ACCESS_KEYS={}` é deliberadamente incompleto: substitua pelos hashes gerados; modo equipe recusa inicialização sem contas. Host não inclui porta; a origem inclui a porta efetiva. Certificado precisa corresponder ao hostname e a cadeia deve ser confiável nos clientes. Não desabilite verificação TLS.

```powershell
.venv/Scripts/python.exe scripts/migrate.py
.venv/Scripts/python.exe scripts/start_team.py --certificate .secrets/tls/tls.crt --private-key .secrets/tls/tls.key --host 127.0.0.1 --port 8443
```

O bind permanece loopback. Para acesso por VPN/interface privada, configure `--host` com o IP privado e aplique firewall. O launcher serve TLS diretamente, sem confiar em `X-Forwarded-*`. Reverse proxy/SSO não foram homologados. Garanta que o serviço use a raiz do checkout como diretório de trabalho e configure reinício pelo gerenciador de serviços do host.

## Perfis e sessão

| Perfil | Permissões |
| --- | --- |
| viewer | Ler as APIs explicitamente permitidas, investigar e exportar todo o workspace |
| analyst | viewer + triagem, scans de projetos existentes, watchlists, consultas por pacote e importação SARIF/VEX |
| admin | Todas as rotas, cadastro de projetos, exposição declarada, configurações, scheduler, retenção e sincronização |

Logout revoga o cookie. Sessões ficam em memória (até 256 no total, quatro por chave por padrão), expiram após 480 min absolutos e 30 min sem requisições autenticadas; polling pode contar como atividade. Ao exceder `MAX_SESSIONS_PER_KEY`, o login revoga a sessão mais antiga da própria conta. Reinício revoga todas. Alterar/remover chave/perfil no `.env` exige reiniciar. A API aceita `Authorization: Bearer <chave>`; nunca coloque a chave na URL. Mutações também precisam de `X-VulnRadar-Client: web` e JSON quando houver corpo. Não há MFA/SSO.

Orçamentos padrão: 600 requisições/min e 60 mutações/min por identidade, cinco tentativas de login/min por origem de conexão, quatro operações caras simultâneas, quatro SSE por usuário/32 globais. SQLite e limites são de um processo. O prazo HTTP é 30 s; jobs têm seu prazo separado e podem continuar após timeout da resposta. Antes de reenviar, consulte o histórico.

## Análises e integrações

Autorize somente raízes necessárias por lista JSON em `ALLOWED_ROOTS`. Monte-as somente leitura e não analise árvores alteradas por adversários durante a leitura. Limites padrão: 2000 arquivos, 5 MB por arquivo, 100 MB agregados, 20 mil componentes e 120 s por scan. Cobertura parcial e erros permanecem visíveis.

SCA pode inventariar sem OSV, porém a consulta de vulnerabilidades precisa de `OSV_QUERIES_ENABLED=true`. Isso transmite ecossistema/nome/versão ao serviço público. `STORE_CODE_SNIPPETS=false` evita novos trechos SAST, mas preserva evidências antigas. Consultas públicas NVD/GitHub/KEV/EPSS são separadas dessa opção. NVD backfill aceita 7/30/90 dias; chaves opcionais de NVD/GitHub ficam apenas no servidor.

Semgrep opcional, em ambiente separado:

```powershell
py -3.12 -m venv .semgrep-venv
.semgrep-venv/Scripts/python.exe -m pip install semgrep==1.184.0
```

Linux usa `.semgrep-venv/bin/python`. Scripts de start/teste adicionam esse diretório ao PATH. No modo equipe, a instalação do binário não remove o bloqueio de política. Habilite `ALLOW_LOCAL_SAST_IN_TEAM=true` apenas com executor/conta/filesystem/egress isolados; os controles de subprocesso implementados não são sandbox forte. Windows nativo foi exercitado localmente com as regras do projeto, sem garantir toda versão/distribuição do Semgrep.

SARIF: upload pela página de aplicações para projeto existente. Perfil 2.1.0 autocontido, 1–10 runs, até 2000 resultados e limite de corpo de 5 MB. Exige ruleId; propriedades externas, traversal e URIs remotos são recusados. Conserva evidência normalizada e hash, sem armazenar o documento bruto completo. Importação permanece parcial e não resolve por ausência. Trate artefatos recebidos como confidenciais e confira a origem fora da aplicação.

Importações e manifests têm limite de 32 níveis e 200 mil nós de estrutura. Lockfiles YAML com aliases ou merges são recusados; forneça o documento expandido. Excesso de componentes interrompe o parser, preserva o inventário observado até o limite e mantém a análise parcial. Linhas pip não interpretadas não são exibidas integralmente nos avisos, para proteger credenciais.

VEX: importe na investigação do achado. OpenVEX 0.2 e CycloneDX 1.5, somente `not_affected`, correspondência exata de vulnerabilidade/alias e PURL/versão instalada, uma declaração aplicável, timestamp com fuso e justificativa suportada. A importação isolada não aplica triagem; marque a aplicação e informe motivo. Exportação exige declaração aplicada e achado ainda não aplicável. Perfis amplos, assinatura/autenticidade, outros estados VEX e conversões sem equivalência são recusados/não implementados.

Notificações começam desabilitadas. Webhook: `WEBHOOK_URL`, `WEBHOOK_ALLOWED_HOSTS` e formato `generic`, `slack` ou `teams`, somente HTTPS público. SMTP: `NOTIFICATION_CHANNEL=smtp`, `SMTP_HOST`, allowlist, remetente, 1–10 destinatários e par usuário/SecretStr de senha quando necessário; TLS implícito 465 com cadeia verificada. É um canal por instalação. Entregas têm histórico, intervalo e até três tentativas; o receptor deve deduplicar pela referência/chave. Não há exactly-once. Nenhum envio real foi feito durante a revisão.

## Migração, backup e restauração

`scripts/migrate.py` usa o wrapper oficial: para SQLite existente com revisão diferente, cria backup consistente via `sqlite3.backup` em `backups/` ao lado do banco antes do upgrade. Migrações 0001–0006 não foram reescritas; 0007 é aditiva. Invocar Alembic diretamente ignora esse backup automático.

Backup manual, para destino novo:

```powershell
.venv/Scripts/python.exe scripts/backup.py data/vulnradar.db D:/Backups/vulnradar-20261109.db
```

Proteja o destino e teste restauração regularmente. Para restaurar: pare o serviço, preserve banco atual e arquivos WAL/SHM juntos em local separado, valide `PRAGMA integrity_check` do backup, coloque uma cópia do backup no caminho configurado sem reutilizar WAL/SHM antigos e inicie um único worker. Confira `/ready`, inventários, contagens e uma triagem conhecida. O teste automatizado valida backup/upgrade de fixture V2; **restauração no servidor operacional é NÃO VALIDADA**. Não use downgrade destrutivo como rollback de evidências.

No reinício, jobs interrompidos são marcados como falha e podem ser reenviados. Checkpoints/evidências permanecem; não há retomada automática de scanner. Falha/cancelamento/ausência de resultados não comprovam segurança.

## Retenção e diagnóstico

`RETENTION_PROGRESS_DAYS` e `RETENTION_DELIVERY_DAYS` começam em zero (desabilitados). Excluem somente eventos transitórios `scan.progress` e metadados de entregas terminais anteriores ao prazo. Scans, achados, inventários, observações, VEX, triagem e estados permanecem. A limpeza cria piso persistente para não reenviar alertas antigos após remover metadados. Admin consulta `GET /api/retention`; `POST /api/retention` com `{}` apenas simula; `{"apply":true}` aplica. Agendador verifica diariamente quando habilitado. Defina também retenção/criptografia de backups e logs no host.

`/health` verifica acesso ao banco; `/ready` verifica chaves ativas e schema necessário. São endpoints mínimos públicos, sem inventário/segredos. Logs JSON usam nível `VULNRADAR_LOG_LEVEL`, request-id e conta quando disponível. Use o identificador exibido no erro para correlacionar; não habilite logs de corpos/Authorization/cookies em proxy. Não há métricas distribuídas/alertas de infraestrutura implementados.

## Docker e Windows empacotado

Compose usa TLS nativo, bind loopback em 8443, usuário 10001, filesystem somente leitura, tmpfs, capabilities removidas e diretório de projetos somente leitura. Prepare `.env` com hashes/origens, `.secrets/tls/{tls.crt,tls.key,ca.crt}`, diretório `projects/` e permissões legíveis pela conta do container. Ajuste hostname/origem de acordo com `compose.yaml`; o healthcheck verifica TLS com `ca.crt`. Não inclua segredos na imagem.

```powershell
docker compose build
docker compose up -d
```

`INCLUDE_SAST=1` é argumento de build opcional para instalar Semgrep em `/opt/semgrep`; ajuste também a política de equipe somente após isolamento. A imagem padrão não inclui SAST. **Build/run Docker NÃO VALIDADO:** o comando `docker` não existe neste ambiente. Não publique essa configuração sem executá-la e homologar volumes, TLS e healthcheck.

O workflow Windows prepara PyInstaller onedir. Build e smoke local do executável foram exercitados com banco temporário; a interface interativa do binário não foi exercitada. Dados ficam em `%LOCALAPPDATA%/VulnRadar`; crie ali `.env` com hashes antes de operar. Sem chaves, a API protege dados e `/ready` responde 503. O binário não incorpora credenciais nem Semgrep.
