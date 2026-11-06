# Segurança

Esta versão é exclusivamente local. Não a exponha publicamente: autenticação multiusuário, isolamento de workers e autorização remota ainda não estão implementados.

Comunique problemas em canal privado ao mantenedor antes de publicar detalhes ou dados confidenciais. Não envie tokens, repositórios privados ou bancos de produção em issues.

A API exige Host permitido, origem permitida e cabeçalho explícito para mutações. O bind padrão é loopback. Raízes de scan ficam vazias até configuração explícita. Scans não executam instaladores ou código dos alvos. Semgrep usa regras locais e snapshot limitado. Consultas OSV enviam nomes e versões de dependências ao serviço público; considere isso antes de analisar software confidencial.

Limitações: corrida entre validação e acesso em sistemas de arquivos mutáveis, especialmente junctions no Windows, exige isolamento adicional. Não analise árvores que adversários possam modificar simultaneamente. Arquivos de dados locais dependem das permissões do usuário do sistema operacional. TLS e validação de artefatos não devem ser desabilitados.
