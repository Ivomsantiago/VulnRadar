# Capturas do radar

- `1440/radar-real-month.png` e `390/radar-real-month.png`: coleta real em banco descartável, capturada em 06/11/2026 no fuso America/Sao_Paulo. Janela de 30 dias, 20.173 vulnerabilidades consolidadas de NVD/GitHub, com críticas/altas primeiro. KEV/EPSS não foram solicitados nessa coleta.
- `1440/investigation-workflow.png`: teste automatizado com CVEs fictícias identificadas como fixtures; demonstra seleção, fila persistida e filtro por atualização.
- Demais capturas: suíte reproduzível com fixtures e banco descartável, 19 rotas nas larguras 1920, 1440, 1366, 1024, 768 e 390. O Git guarda todas as rotas em 1440 e a página inicial em cada largura; CI pode guardar a galeria completa.

Nenhuma fixture foi inserida no banco operacional. Os números reais mudam conforme publicações, período e horário da consulta.
