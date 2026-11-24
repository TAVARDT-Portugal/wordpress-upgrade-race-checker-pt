# TAVARDT Portugal : Central de Hardening & Auditoria WordPress Upgrade Race Condition

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Repositório oficial e documentação técnica corporativa para mitigação da vulnerabilidade de **Race Condition no Upgrade do WordPress e Execução Remota de Código (RCE)**.

***

## 1. Visão Geral da Vulnerabilidade

Durante atualizações de plugins, temas ou do próprio core do WordPress, o sistema descompacta arquivos temporários no diretório `/wp-content/upgrade/`. Caso o servidor web não possua regras rígidas de restrição de execução, invasores podem disparar requisições concorrentes aos arquivos recém-extraídos antes da conclusão do processo, atingindo execução remota de código (RCE).

***

## 2. Auditoria Ativa via Linha de Comando (CLI)

Para auditar seu servidor de forma determinística, sem restrições de sandbox de navegador ou políticas de CORS, utilize o utilitário oficial em Python incluído neste repositório:

```bash
# 1. Clonar o repositório
git clone https://github.com/TAVARDT-Portugal/wordpress-upgrade-race-checker-pt.git
cd wordpress-upgrade-race-checker-pt

# 2. Executar auditoria direta
python audit_wp_race.py https://seu-dominio.com.br
```

***

## 3. Diretrizes de Hardening Perimetral

### A. Nginx (`nginx.conf`)
```nginx
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### B. Apache (`.htaccess`)
```apache
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>
Options -Indexes
```

### C. WordPress (`wp-config.php`)
```php
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### D. Cloudflare WAF Rule
```cloudflare
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
```

***

## 4. Consulta Online

Acesse o Guia Interativo em produção:  
[https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/](https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/)

***

&copy; 2026 TAVARDT Portugal. Todos os direitos reservados.
