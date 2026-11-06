# Segurança

Esta versão é exclusivamente local. Não a exponha publicamente: autenticação multiusuário, isolamento de workers e autorização remota ainda não estão implementados.

Comunique problemas em canal privado ao mantenedor antes de publicar detalhes ou dados confidenciais. Não envie tokens, repositórios privados ou bancos de produção em issues.

A API exige Host permitido, origem permitida e cabeçalho explícito para mutações. O bind padrão é loopback. Raízes de scan ficam vazias até configuração explícita. Scans não executam instaladores ou código dos alvos. Semgrep usa regras locais e snapshot limitado. Consultas OSV enviam nomes e versões de dependências ao serviço público; considere isso antes de analisar software confidencial.

A leitura V3 ancora diretórios por handles em POSIX e verifica o caminho final do handle no Windows, além de rejeitar links/junctions. Árvores adversariais, permissões do usuário local e políticas de egress continuam exigindo isolamento do sistema operacional. Não analise árvores que adversários possam modificar simultaneamente. Arquivos de dados locais dependem das permissões do usuário do sistema operacional. TLS e validação de artefatos não devem ser desabilitados.

## Controles adicionais V2

Inventários, achados e observações são separados por projeto/scan. Uma coleta global não vira achado local sem evidência SCA. Triagem exige justificativa e scans parciais não resolvem achados automaticamente.

Semgrep lê um snapshot limitado, exclui symlinks/junctions, limita stdout/stderr e tem cancelamento/timeout. Evidências exibem pequenos trechos locais com redação de padrões comuns de credenciais; revise relatórios antes de compartilhá-los. Isso não equivale a DLP.

Webhooks ficam desabilitados sem configuração do servidor. Destinos exigem HTTPS e hostname explicitamente permitido; IPs/DNS privados e redirects são recusados. O corpo tem whitelist e não inclui código, caminhos ou campos arbitrários. URLs, tokens e corpos de resposta não são retornados pela API de entregas nem registrados nos logs da aplicação. Use políticas de egress para proteção adicional contra rebinding e destinos comprometidos.

Preferências editáveis não permitem ampliar raízes, Host/CORS, secrets ou limites de recursos. O endpoint de navegação por pastas também valida as raízes e não concede acesso irrestrito ao filesystem.

`browser_test_app.py` é exclusivamente de testes, com dados fictícios identificados e banco temporário. Não deve ser usado como launcher de produção.

## Controles adicionais V3

OCI aceita somente registros autorizados, sem URLs arbitrários, caminhos locais, shell ou Docker daemon. CLIs oficiais opcionais têm instalação com SHA256 verificado, timeout, saída limitada e cancelamento; scans OCI são separados de SCA/SAST. Ausência de scanner não vira análise concluída.

Datas de remediação são normalizadas para UTC; aceites expirados reabrem e geram auditoria. Histórico de estados é imutável; relatórios não alteram decisões anteriores. CSV protege contra fórmulas e PDF escapa campos de texto. CPEs condicionais e versões sem comparação verificável permanecem desconhecidos.
