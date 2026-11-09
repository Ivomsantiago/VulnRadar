# Privacidade por padrão

A V4 aplica minimização e controle técnico de egress; não declara adequação jurídica automática. A organização deve definir finalidade, base legal aplicável, responsáveis, acesso, retenção e procedimento de resposta a incidentes conforme seu contexto.

| Dados | Finalidade e destino | Padrão e controle |
| --- | --- | --- |
| Conta pseudônima, perfil, digest e validade | Acesso no servidor; conta em auditoria/logs | Sem nome/email obrigatório; chaves pessoais não persistidas; rotação/revogação por configuração |
| Sessão opaca | Cookie HttpOnly e mapa em memória | Sem token em localStorage; expiração absoluta/inatividade e revogação no reinício |
| IP de conexão | Limite temporário de login | Hash em memória, sem persistência da aplicação; revisar logs do host/proxy |
| Caminhos, inventário, versões e achados | Investigação no banco e exportações autorizadas | Workspace compartilhado; acesso a todos os projetos para leitores permitidos; volume protegido pelo host |
| Código/evidência | Resultado SAST local | Novos snippets desabilitados; habilitação explícita; redação básica sem garantia de DLP; dados antigos preservados |
| Coordenadas de pacotes | Consulta OSV externa | Desabilitada por padrão; habilitação transmite ecossistema/nome/versão; código não é enviado pelo conector |
| Consultas/credenciais de fontes | NVD/GitHub/KEV/EPSS e OSV | Credenciais só no servidor, excluídas de subprocessos e erros; consultas públicas separadas da política de pacotes |
| SARIF/VEX importado | Evidência normalizada, hash e decisão | Limites/schema offline; bruto completo não persistido; campos de mensagem/justificativa podem conter informação sensível enviada pelo operador |
| Notificações | Destino configurado pelo admin | Desabilitadas sem configuração; payload webhook limitado; SMTP genérico; revisar a confidencialidade do destino |
| Preferências de UI | Tema, favoritos e colunas no navegador | Chaves `vr-` e cache de consultas limpos no login/logout; não usar navegador compartilhado sem encerrar a sessão |

Serviços públicos podem registrar consultas, IP e metadados segundo suas próprias políticas. Egress deve ser autorizado no firewall. `OSV_QUERIES_ENABLED=false` bloqueia consultas de pacote inclusive em cache; não desabilita a coleta de inteligência pública. Não ative logs HTTP detalhados de terceiros com credenciais reais.

## Conservação e direitos

Histórico de segurança não é excluído automaticamente: preserva decisões, inventários, observações, triagem e VEX para rastreabilidade. A retenção opt-in remove apenas progresso transitório e metadados de entregas terminais; veja [runbook](RUNBOOK.md). Logs, volumes, exportações e backups requerem política própria. Reduzir retenção da aplicação não elimina cópias anteriores.

Não há endpoint de exclusão integral de conta/projeto ou anonimização retroativa de auditoria. Solicitações de acesso/correção/exclusão precisam de procedimento administrativo que considere obrigações de retenção e integridade de evidências. **Esse processo e a criptografia em repouso do host são NÃO VALIDADOS nesta revisão.** Não apagar dados operacionais para simular atendimento ou aplicar migração destrutiva.

Recomendações operacionais: contas pseudônimas individuais, mínimo privilégio, expiração curta, servidor privado com TLS, revisão dos destinatários de alertas, backups criptografados e revisão humana de exportações. [Segurança](../SECURITY.md) e [achados/limites](REVIEW_V4.md).
