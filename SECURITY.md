# Segurança

Relate falhas em canal privado ao mantenedor. Não inclua tokens, bancos, caminhos privados ou código confidencial em issues. O projeto não declara certificação OWASP nem substitui uma avaliação independente no ambiente de implantação.

## Fronteira de confiança

O suporte oficial usa SQLite WAL e **um processo/worker**, com um workspace compartilhado pela equipe. Todos os leitores autorizados podem acessar seus projetos e exportações. Não use esta instalação para separar clientes ou organizações. O modo local exige conexão loopback; equipe exige HTTPS e hosts/origens explícitos. O launcher de equipe não confia em cabeçalhos de proxy. Não exponha diretamente à internet.

Chaves pessoais têm 256 bits aleatórios, validade e perfil; só o digest SHA-256 fica no servidor. Não são senhas humanas. Cookies opacos usam HttpOnly/SameSite Strict e Secure no modo equipe; sessões são limitadas, expiram e são invalidadas ao reiniciar. Retirar/rotacionar uma chave exige atualizar a configuração e reiniciar. Não há SSO/MFA ou recuperação de senha. A identificação da auditoria é a conta configurada no servidor, não um campo enviado pelo cliente.

As APIs têm autenticação e autorização centrais, negação de rotas desconhecidas para viewer/analyst, limites por identidade e por operações caras, limite de corpo e streams SSE. Mutações exigem JSON quando há corpo, origem autorizada e `X-VulnRadar-Client: web`. Esse cabeçalho não é uma credencial. CSP, no-store nas APIs, nosniff, restrição de frames, request-id e erros mínimos também cobrem rejeições. Limites de requisição não equivalem a limites de CPU do sistema operacional.

## Dados, scanners e integrações

- `ALLOWED_ROOTS=[]` até autorização explícita. Leitura por handles, rejeição de links/junctions, validação do destino final no Windows e snapshots limitados reduzem traversal e trocas de caminho. Árvores que terceiros possam modificar durante a leitura exigem isolamento adicional.
- Nenhum instalador, build, gerenciador de pacotes ou script do repositório analisado é executado. Semgrep é externo, opcional, usa regras locais, argumentos sem shell, ambiente mínimo sem credenciais do servidor, saída limitada e timeout. Job Object no Windows/grupo POSIX controla encerramento. Isso não é sandbox forte.
- No modo equipe, SAST local é bloqueado por padrão. Prefira SARIF produzido em executor isolado. Habilitar `ALLOW_LOCAL_SAST_IN_TEAM=true` exige preparar esse isolamento no host. Importação não atesta autenticidade da ferramenta nem completude da análise.
- Egress OSV e snippets começam desabilitados. Dados antigos são preservados; desabilitar snippets não apaga evidências históricas. Quando habilitados, a redação cobre padrões comuns, sem promessa de DLP.
- Webhook exige HTTPS, allowlist e DNS público; conecta ao IP previamente validado com Host/SNI original, sem proxies do ambiente ou redirects. Testes verificam esse contrato em transporte simulado; TLS real do destino precisa de homologação.
- SMTP é opcional, exclusivo em relação ao canal webhook, com TLS implícito na porta 465 e certificado verificado. O corpo contém referência genérica ao alerta. Nenhuma notificação real foi enviada nesta revisão.
- SARIF/CycloneDX são validados com schemas oficiais vendorizados sem carregamento remoto. VEX suporta somente o perfil documentado; não altera triagem sem confirmação explícita e justificativa. Exportação não gera declarações sem evidência aplicada.
- CSV neutraliza fórmulas, PDF escapa texto, React não renderiza HTML arbitrário das fontes e links são limitados a HTTP(S). Revise exportações antes de compartilhar.

## Operação

Proteja `.env`, certificados, volumes e backups por permissões/ACL e criptografia do host; não há criptografia transparente do banco implementada. Use contas pseudônimas, egress restrito e logs sem corpos/cookies/tokens. Proxies e infraestrutura devem seguir a mesma política. Retenção é opt-in e preserva evidências/triagem; o [documento de privacidade](docs/PRIVACY.md) descreve os limites.

Leia [achados, regressões e pendências](docs/REVIEW_V4.md), [estado executado](docs/IMPLEMENTATION_STATUS.md) e [runbook](docs/RUNBOOK.md). Scans vazios, coletas sem correspondência e testes verdes não demonstram ausência de vulnerabilidades.

## Revisão de 11/11/2026

[Auditoria atual e evidências](docs/SECURITY_REVIEW_2026-11-11.md). Novos controles limitam documentos a 32 níveis/200 mil nós antes da validação de domínio, recusam aliases/merges YAML em lockfiles e aplicam o limite de componentes durante o parsing. Documentos fora do perfil produzem cobertura parcial, preservando inventários anteriores e os componentes já observados.

Linhas pip sem versão/opções não são copiadas para avisos de scan, pois podem conter credenciais de índices privados. A correção protege novas análises; registros e exportações antigos permanecem sujeitos à revisão administrativa, sem alteração automática do banco operacional. Cada chave tem até quatro sessões por padrão, com rotação da mais antiga da mesma conta; o limite global permanece independente.

O entrypoint de navegador descartável desabilita destinos de notificação e credenciais de fontes herdados. Ele não deve ser usado para operar o serviço real. Capturas de documentação usam raízes neutras e uma conta de teste; o capturador recusa servidores sem a identificação explícita da fixture.
