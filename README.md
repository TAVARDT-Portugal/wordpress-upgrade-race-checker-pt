# Auditor de Race Condition na Atualização do WordPress & RCE | TAVARDT Portugal

> Auditoria de Resiliência contra Condição de Corrida em Atualizações do WordPress, Exposição de Diretórios Transitórios e Execução Remota de Código (RCE)

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-brasil.github.io/wordpress-upgrade-race-checker-pt/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS WordPress](https://img.shields.io/badge/Security-CIS%20WordPress%20%7C%20OWASP-red.svg)](https://owasp.org/)

## Visão Geral da Vulnerabilidade e Arquitetura Defensiva

O processo padrão de atualização de componentes do WordPress (núcleo, temas e plugins) orquestrado pela classe `class-wp-upgrader.php` realiza o download de pacotes compactados em formato ZIP e sua posterior extração no diretório temporário `wp-content/upgrade/` por meio da função `unzip_file()`.

Durante o intervalo temporal entre a descompactação dos arquivos e a movimentação atômica dos diretórios de destino final, uma janela de corrida (Race Condition) se abre na raiz pública acessível via HTTP. Caso o servidor web não possua regras estritas de negação de acesso ou diretivas perimetrais de Web Application Firewall (WAF), qualquer requisição anônima pode acessar diretamente os arquivos extraídos em `wp-content/upgrade/`. Se o interpretador PHP (FastCGI/PHP-FPM) compilar scripts nessa pasta, atacantes conseguem executar código malicioso arbitrário (Remote Code Execution) com os privilégios do usuário do servidor web.

Este repositório disponibiliza uma ferramenta web interativa de diagnóstico perimetral e um utilitário CLI complementar em Python (sem dependências externas) para auditoria automatizada.

## Aplicação Web Interativa

Acesse a versão interativa hospedada diretamente via GitHub Pages:
[https://tavardt-brasil.github.io/wordpress-upgrade-race-checker-pt/](https://tavardt-brasil.github.io/wordpress-upgrade-race-checker-pt/)

Recursos da aplicação web:
* Verificação em tempo real de acessibilidade perimetral e medição de latência de rede.
* Diagnóstico de exposição do diretório transitório `wp-content/upgrade/` e pasta de uploads.
* Matriz comparativa de topologia arquitetural (WordPress vulnerável vs. Servidor blindado).
* Gerador automático de regras defensivas para Nginx, Apache (.htaccess), wp-config.php e Cloudflare WAF.
* Interface responsiva para dispositivos móveis e desktops.

## Utilização do Scanner CLI (Python)

O script companion `wordpress_upgrade_checker.py` não requer bibliotecas de terceiros e pode ser executado em qualquer ambiente com Python 3.8+:

```bash
# Executar auditoria direta contra um domínio
python wordpress_upgrade_checker.py https://meusite.pt

# Executar auditoria em formato JSON para pipelines de CI/CD e DevSecOps
python wordpress_upgrade_checker.py https://meusite.pt --json

# Exibir diretamente os snippets de código para correção e hardening
python wordpress_upgrade_checker.py --remediate
```

## Controles Arquiteturais e Mitigações Defensivas

Para neutralizar em definitivo a superfície de ataque de condição de corrida e RCE no WordPress, aplique as 4 camadas de defesa em profundidade:

1. **Isolamento de Temporários (wp-config.php):**
   Configure a constante `WP_TEMP_DIR` para apontar para um caminho externo e isolado fora da raiz pública (`DocumentRoot`):
   ```php
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);
   ```

2. **Bloqueio de Borda no Nginx (nginx.conf):**
   Negue qualquer requisição à pasta de upgrade e proíba a compilação de arquivos `.php` em diretórios de conteúdo estático:
   ```nginx
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\.php$ {
       deny all;
       return 403;
   }
   ```

3. **Bloqueio no Apache (.htaccess):**
   Adicione proteção estrita em `wp-content/upgrade/.htaccess`:
   ```apache
   <FilesMatch "\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
   ```

4. **Regra de WAF Perimetral no Cloudflare:**
   Crie uma Custom Rule bloqueando imediatamente requisições para `(http.request.uri.path contains "/wp-content/upgrade/")`.

## Portais Oficiais

* **Portal Corporativo TAVARDT Portugal:** [https://ag.tavardt.com/pt/](https://ag.tavardt.com/pt/)
* **Serviços de Cibersegurança:** [https://ag.tavardt.com/pt/ciberseguranca/](https://ag.tavardt.com/pt/ciberseguranca/)
* **Hub de Ferramentas Defensivas:** [https://tools.tavardt.com/pt/](https://tools.tavardt.com/pt/)
* **Organização GitHub:** [https://github.com/TAVARDT-Portugal](https://github.com/TAVARDT-Portugal)

## Licença

Distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para mais informações.
