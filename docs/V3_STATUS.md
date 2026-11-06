# VulnRadar V3 — implementação e validação

A V3 conecta inteligência, análise local, OCI, investigação, remediação, monitoramento e relatórios. Migrações 0005/0006 são aditivas; não removem dados existentes. Os critérios e evidências estão em [V3_ACCEPTANCE.md](V3_ACCEPTANCE.md).

## Funcionalidades entregues

- Sidebar com as oito jornadas solicitadas, abas contextuais, navegação por teclado, responsividade e compatibilidade com URLs e filtros antigos. Tema escuro padrão e tema claro.
- SCA com OSV querybatch real, hidratação deduplicada de advisories, cache TTL limitado, quatro consultas simultâneas, retry para rate limits e fallback paginado. Falhas individuais continuam parciais.
- Parsers de npm, Yarn Classic/Berry, pnpm antigo/atual, Maven, Gradle, requirements, Poetry, uv, Pipfile, Go, NuGet/assets, Composer, Cargo, RubyGems e CycloneDX. Nomes normalizados somente quando o ecossistema define equivalência. Versões flutuantes/locais desconhecidas não viram vulnerabilidades confirmadas.
- Fingerprints SAST independentes de deslocamentos de linha, ocorrências duplicadas separadas e atualização conservadora de identidades legadas. Versão do Semgrep participa da comparação; ignores/inline nosemgrep dos alvos não removem silenciosamente a cobertura. Evidência por execução preservada; comparações completas identificam novos, persistentes, resolvidos e reabertos. Parcial não resolve por ausência.
- Trivy e Grype opcionais: análise remota de camadas OCI, sem Docker daemon e sem executar imagens. Fonte/digest, componentes, correções e achados persistidos como motor OCI separado. Ausência dos binários não prejudica SCA/SAST. Cancelamento mata o subprocesso; timeouts, limites de saída, concorrência única, GOMAXPROCS e orçamento de heap Go são aplicados.
- Índice estruturado de CPEs NVD por fornecedor/produto, versões e limites, incluindo runtimes. Condições de plataforma e ordenações não verificáveis aparecem como desconhecidas. Pacotes npm/Maven não são confundidos com Node.js/Java runtime.
- Monitoramento persistido de produtos/versões e pacotes, verificação manual e após coleta incremental; alertas deduplicados. Histórico distingue publicação informada pela fonte, primeira coleta, atualização de advisory e descoberta local. NVD atrasado recupera janelas paginadas de até 119 dias.
- Avaliações de severidade/CVSS por fonte e divergências explícitas na investigação, com data da fonte quando disponível. KEV e EPSS permanecem evidências de inteligência, não prova de exploração local.
- Remediação com justificativa, FP, responsável, prazo/SLA, plano e aceite com validade futura. Datas normalizadas para UTC. Aceite expirado reabre automaticamente, mesmo sem novo scan.
- Histórico imutável dos estados dos achados. Relatórios de exposição diária, resoluções, recorrências e pendências usam os estados registrados, sem reescrever o passado após triagem.
- Relatórios por projeto/período/severidade/estado/tecnologia/motor e mudanças novas/resolvidas/reabertas. Paginação da visualização; exportações JSON/CSV/PDF no servidor usam os mesmos filtros. Histórico também exporta JSON/CSV/PDF. SARIF e CycloneDX ficam disponíveis por execução aplicável.
- Leitura limitada por handles: POSIX ancora cada diretório com O_NOFOLLOW; Windows rejeita symlinks/junctions e verifica o caminho final do handle antes de ler. Arquivos não regulares são rejeitados. Registros OCI têm allowlist de host; chamadas externas não recebem shell nem scripts de alvos.

## Validação

- Backend: 97 aprovados, incluindo sete integrações oficiais reais; evidências em V3_ACCEPTANCE.md.
- Frontend: sete testes, TypeScript/build e auditoria npm. Sem novas dependências de produção.
- Navegador: jornada de cadastro → análise combinada → evidência → triagem/FP → correção real dos arquivos da fixture → reanálise → resolução → recorrência/reabertura; CPE/monitoramento, PDF e navegação.
- Trivy 0.76.2 e Grype 0.121.2 oficiais, instalados com SHA256 verificado, executados sobre imagens públicas reais; teste dedicado pelo navegador persiste e abre suas evidências em banco descartável.
- Galeria Chromium atualizada em screenshots/v3; 18 rotas em seis larguras (1920/1440/1366/1024/768/390), com Axe em páginas operacionais e temas claro/escuro. A galeria V2 foi preservada.
- PDF servidor validado também com Poppler (pdfinfo/pdftotext), A4 e texto extraível. Backup SQLite e preservação de migrações são verificados separadamente.

## Cobertura e limites de operação

Estes limites descrevem o escopo real dos mecanismos e da instalação local; não são botões simulados:

- A aplicação inicia somente em loopback. Uso público/multiusuário exige autenticação, autorização, TLS e isolamento adicionais. Não foi publicada nem exposta remotamente.
- Scanners não comprovam ausência universal de vulnerabilidades ou explorabilidade. SAST cobre regras/linguagens instaladas. Bases de advisories e registros OCI podem falhar ou omitir informações; cobertura é exibida.
- Parsers não executam gerenciadores, builds, perfis ou resoluções remotas de projetos. Herança/BOM Maven externos, ambientes Python, condicionais/fechamento transitivo Go e variantes desconhecidas exigem um lockfile/SBOM apropriado; as limitações são reportadas.
- CPEs condicionais não são reduzidos a prova de aplicabilidade. Datas da fonte ausentes continuam ausentes. Não são inventados CVSS, correções, tendências ou zero-days.
- Histórico exato começa nos estados/baselines efetivamente registrados. Períodos anteriores ficam desconhecidos. Encerramento por triagem difere de comprovação técnica de correção; resoluções/reaberturas são eventos. Não há como reconstruir decisões que nunca foram registradas.
- Uma instância/worker local por banco. SQLite não coordena workers distribuídos. Após reinício, tarefas interrompidas são falhas reenviáveis, sem retomada parcial automática.
- PDF servidor usa fontes padrão WinAnsi para texto técnico/português; JSON/CSV e impressão do navegador preservam texto Unicode completo. Exportação de achados tem limite explícito de 5000; histórico tem limite explícito de eventos e marca exposição desconhecida ao truncar.
- Redação de snippets cobre padrões comuns de credenciais e não é DLP. Scanners rodam como o usuário local; árvores adversariais exigem isolamento do sistema operacional. Axe automatizado não é certificação WCAG.

## Execução local

```bash
bash scripts/install.sh
# Opcional: instalar os scanners oficiais com checksum verificado
.venv/bin/python scripts/install_engines.py all
bash scripts/start.sh
```

Windows: scripts/install.ps1 e scripts/start.ps1; OCI também aceita binários oficiais no PATH. Os binários opcionais ficam em .engines/bin, ignorados pelo Git. Somente registros definidos em VULNRADAR_OCI_REGISTRIES são aceitos. Semgrep deve ser instalado separadamente conforme README.

Faça backup antes de atualizar o banco operacional: `.venv/bin/python scripts/backup.py data/vulnradar.db /caminho/novo/backup.db`. Testes usam banco descartável; nunca executar fixtures contra o banco operacional.
