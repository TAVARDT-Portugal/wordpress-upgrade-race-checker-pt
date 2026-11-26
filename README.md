<p align="center">
  <a href="https://ag.tavardt.com/pt/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Central de Hardening e Auditoria contra Condições de Corrida em WordPress

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![W3C](https://img.shields.io/badge/W3C-Standard-blue.svg)](https://www.w3.org/)
[![CVE Defense](https://img.shields.io/badge/Defense-Race%20Condition-green.svg)](https://ag.tavardt.com/pt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Especificação técnica de engenharia defensiva, modelos de configuração para produção e utilitário determinístico em linha de comandos para neutralização de condições de corrida e Execução Remota de Código (RCE) no processo de atualização do WordPress.

***

## Enquadramento Técnico: A Condição de Corrida no Upgrade de WordPress

O WordPress suporta uma percentagem muito expressiva dos sítios web a nível mundial. Durante os procedimentos de atualização do núcleo, temas ou extensões, a plataforma extrai arquivos comprimidos para uma pasta temporária antes de transferir os ficheiros definitivos para os caminhos de produção.

Por omissão, esta extração ocorre na pasta `wp-content/upgrade/`, localizada diretamente na raiz acessível do servidor web (DocumentRoot).

Sempre que a configuração do servidor permite a execução de scripts PHP em pastas de conteúdo, um utilizador mal-intencionado pode solicitar a execução de ficheiros descompactados durante esse intervalo:
* O atacante monitoriza ou desencadeia um ciclo de atualização na plataforma.
* Ficheiros PHP transitórios ficam acessíveis para execução antes da aplicação das permissões finais.
* Pedidos HTTP diretos a estes ficheiros provocam a Execução Remota de Código (RCE) com os privilégios do servidor web (`www-data` ou `nginx`).

Este repositório disponibiliza regras de configuração testadas em produção, modelos de isolamento perimetral e um utilitário determinístico em Python (`audit_wp_race.py`) para validação rigorosa da infraestrutura.

***

## Áreas Críticas de Risco em Diretórios de Conteúdo WordPress

### 1. A Exposição Pública da Pasta `wp-content/upgrade/`
A fragilidade resulta da colocação de pastas transitórias em locais diretamente acessíveis via web:
* **Janela Temporal de Risco:** Em servidores com elevada carga de trabalho, a descompressão de pacotes pode demorar vários segundos.
* **Modo de Exploração:** O atacante envia pedidos HTTP concorrentes para aceder aos ficheiros antes da conclusão da limpeza automática.
* **Diretriz Defensiva:** Rejeitar todo o tráfego HTTP direto para a pasta `wp-content/upgrade/` e transferir a pasta temporária para fora da raiz do servidor.

### 2. Execução Irrestrita de Scripts PHP em Pastas de Conteúdo
Configurações comuns reencaminham qualquer pedido com extensão `.php` para o interpretador FastCGI sem verificar a pasta de origem:
* **Janela Temporal de Risco:** As pastas de carregamento necessitam de permissões de escrita para receber ficheiros e atualizações.
* **Modo de Exploração:** A permissão de escrita combinada com a autorização de execução de scripts cria um risco grave de execução arbitrária.
* **Diretriz Defensiva:** Bloquear a execução de ficheiros PHP nas pastas `uploads`, `upgrade`, `languages` e `mu-plugins` ao nível do servidor web.

### 3. Listagem Automática de Diretórios Ativa (Directory Listing)
Servidores com opções predefinidas que permitem a listagem de pastas revelam os ficheiros aos visitantes:
* **Janela Temporal de Risco:** Permite a terceiros visualizar em tempo real os nomes de ficheiros temporários gerados durante o processo de atualização.
* **Diretriz Defensiva:** Desativar a listagem automática de ficheiros de forma global na configuração do servidor.

***

## Modelos de Mitigação Defensiva em Produção

Aplique estas configurações comprovadas para blindar servidores web em produção:

### 1. Configuração para Nginx (`nginx.conf`)
Bloqueia o acesso direto à pasta temporária e impede a execução de scripts em pastas de conteúdo:

```nginx
# 1. Rejeitar pedidos diretos a pasta de upgrade temporario
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

# 2. Impedir execucao de PHP em pastas de conteudo estatico
location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### 2. Configuração para Apache (`.htaccess`)
Adicione esta regra no ficheiro `.htaccess` das pastas `/wp-content/upgrade/` e `/wp-content/uploads/`:

```apache
# Rejeitar execucao de extensoes executaveis
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>

# Desativar listagem de pastas
Options -Indexes
```

### 3. Configuração no WordPress (`wp-config.php`)
Transfere a pasta temporária para fora da raiz do sítio web e desativa a edição de ficheiros:

```php
/* Transferir a pasta temporaria para fora da raiz publica */
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');

/* Desativar edicao e instalacao direta de ficheiros pelo painel */
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### 4. Regra de Filtragem Perimetral no Cloudflare WAF
Regra de bordadura para bloqueio imediato de pedidos não autorizados:

```text
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
Acao: Block (Rejeitar ligacao imediatamente)
```

***

## Utilitário Determinístico de Auditoria CLI

Os navegadores de internet aplicam restrições de sandbox e regras de CORS que impossibilitam a análise direta de sockets e o exame irrestrito de cabeçalhos HTTP. Por forma a disponibilizar diagnósticos fiáveis e sem envio de dados para o exterior, a TAVARDT desenvolveu uma ferramenta em Python orientada para terminais e esteiras de integração contínua.

### Fases do Mecanismo de Diagnóstico

O utilitário (`audit_wp_race.py`) segue uma sequência estruturada de avaliação:
* **Validação de URL e Acessibilidade:** Verifica a estrutura do endereço, normaliza o protocolo e confirma a ligação com o servidor.
* **Deteção de WordPress:** Confirma a presença da plataforma através de marcadores na API REST, ficheiros canónicos e páginas de autenticação.
* **Identificação de Roteador SPA:** Distingue códigos 403/404 legítimos de redirecionamentos genéricos de Single Page Applications.
* **Sondagem de Pastas Críticas:** Inspeciona `/wp-content/upgrade/` e caminhos de teste PHP para confirmar a rejeição pelo servidor.
* **Classificação Técnica:** Emite uma classificação automatizada de 100 (Protegido) a 25 (Vulnerável).

### Instruções de Utilização

Execute a ferramenta diretamente contra o endereço WordPress visado:

```bash
# 1. Obter o script oficial
curl -sO https://raw.githubusercontent.com/TAVARDT-Portugal/wordpress-upgrade-race-checker-pt/main/audit_wp_race.py

# 2. Executar auditoria direta
python audit_wp_race.py https://seu-dominio.com

# 3. Gerar resultado em formato JSON
python audit_wp_race.py https://seu-dominio.com -j
```

***

## Perguntas Frequentes de Arquitetura (FAQ Técnico)

### 1. O que dá origem à condição de corrida na atualização do WordPress?
Durante as rotinas de atualização, o WordPress descompacta pacotes ZIP na pasta temporária `wp-content/upgrade/` antes de concluir a verificação dos ficheiros. Se a configuração do servidor permitir a execução de scripts nas pastas de conteúdo, terceiros podem solicitar os ficheiros PHP durante este intervalo, obtendo Execução Remota de Código com as permissões do servidor web.

### 2. Por que razão é imperativo bloquear o acesso HTTP à pasta wp-content/upgrade?
A pasta `wp-content/upgrade/` foi desenhada exclusivamente para operações internas locais do interpretador PHP. Os utilizadores externos na internet não possuem qualquer necessidade operacional de consultar esta pasta, pelo que permitir o seu acesso expõe artefactos temporários a tentativas de exploração.

### 3. De que forma a deslocalização da pasta WP_TEMP_DIR impede o ataque?
Ao definir `WP_TEMP_DIR` fora da raiz pública do servidor (por exemplo, em `/var/www/tmp/` em vez de `/wp-content/upgrade/`), os ficheiros descompactados ficam fisicamente inacessíveis através de pedidos web. Mesmo conhecendo os nomes dos ficheiros, o servidor não os pode disponibilizar por se encontrarem fora do DocumentRoot.

### 4. Como é que o Nginx e o Apache neutralizam a execução de scripts em pastas de conteúdo?
O Nginx utiliza diretivas de localização com expressões regulares que retornam o código HTTP 403 para qualquer pedido com extensão `.php` nestas pastas. No Apache, aplicam-se ficheiros `.htaccess` com diretivas `<FilesMatch>` que barram a execução de scripts a par de `Options -Indexes` para impedir a listagem de ficheiros.

### 5. A ferramenta de auditoria em Python interfere com o funcionamento do sítio analisado?
Não. A ferramenta realiza apenas verificações de leitura passivas através de pedidos HTTP GET e HEAD convencionais. Limita-se a verificar se as pastas devolvem HTTP 403 ou 404 em vez de HTTP 200 aberto, avaliando o estado perimetral sem introduzir alterações em ficheiros ou na base de dados.

***

## Enquadramento de Conformidade e Normas de Segurança

Arquitetura técnica alinhada com o Regulamento Geral sobre a Proteção de Dados (RGPD, Regulamento UE 2016/679), com as diretrizes de segurança da CNPD e com as orientações do Centro Nacional de Cibersegurança (CNCS).

***

## Links Úteis

* **Portal Corporativo:** https://ag.tavardt.com/pt/
* **Suíte de Diagnósticos:** https://tools.tavardt.com/pt/
* **Contacto Técnico:** https://ag.tavardt.com/pt/contacto/

***

© 2026 TAVARDT Portugal. Todos os direitos reservados. Soberania e Defesa de Infraestrutura.
