#!/usr/bin/env python3
"""
TAVARDT WordPress Upgrade Race Condition & RCE Auditor (CLI)
Ferramenta de auditoria de segurança para detecção de exposição e execução
em diretórios transitórios de atualização do WordPress (wp-content/upgrade/).
"""

import sys
import json
import urllib.request
import urllib.error
import ssl

def check_route(target_url, path):
    full_url = target_url.rstrip("/") + "/" + path.lstrip("/")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        full_url,
        headers={"User-Agent": "TAVARDT-WordPress-Race-Auditor/1.0 (+https://ag.tavardt.com/pt/ciberseguranca/)"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            status_code = response.getcode()
            body = response.read(2048).decode("utf-8", errors="ignore")
            is_index_of = "Index of" in body or "<title>Index of" in body
            return {
                "path": path,
                "url": full_url,
                "status": status_code,
                "accessible": True,
                "directory_listing": is_index_of,
                "risk": "CRÍTICO" if is_index_of or status_code == 200 else "BAIXO"
            }
    except urllib.error.HTTPError as e:
        return {
            "path": path,
            "url": full_url,
            "status": e.code,
            "accessible": False,
            "directory_listing": False,
            "risk": "PROTEGIDO" if e.code in [403, 404] else "ATENÇÃO"
        }
    except Exception as e:
        return {
            "path": path,
            "url": full_url,
            "status": 0,
            "accessible": False,
            "directory_listing": False,
            "risk": "ERRO_CONEXÃO",
            "error": str(e)
        }

def audit_wordpress(target_url):
    paths = [
        "wp-content/upgrade/",
        "wp-content/upgrade/test.php",
        "wp-content/uploads/",
        "wp-content/uploads/test.php"
    ]
    
    results = []
    for p in paths:
        results.append(check_route(target_url, p))
    
    upgrade_dir = next((r for r in results if r["path"] == "wp-content/upgrade/"), None)
    is_vulnerable = False
    if upgrade_dir and (upgrade_dir["directory_listing"] or upgrade_dir["status"] == 200):
        is_vulnerable = True
        
    assessment = {
        "target": target_url,
        "is_vulnerable": is_vulnerable,
        "posture": "VULNERÁVEL" if is_vulnerable else "PROTEGIDO",
        "routes": results,
        "remediation": [
            "Definir WP_TEMP_DIR fora da raiz web pública no wp-config.php: define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');",
            "Bloquear execução de PHP em wp-content/upgrade/ e wp-content/uploads/ no Nginx ou Apache.",
            "Configurar regra de WAF no Cloudflare descartando requisições para /wp-content/upgrade/.",
            "Ativar DISALLOW_FILE_MODS para forçar atualizações exclusivas via CI/CD e esteira automatizada."
        ]
    }
    return assessment

def print_remediation():
    print("""
================================================================================
  DIRETRIZES DE REMEDIAÇÃO ARQUITETURAL: WORDPRESS UPGRADE RACE CONDITION
================================================================================
1. Configuração no wp-config.php:
   Adicione antes de "/* That's all, stop editing! */":
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);

2. Bloqueio no Nginx (nginx.conf):
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\\.php$ {
       deny all;
       return 403;
   }

3. Bloqueio no Apache (.htaccess em wp-content/upgrade/):
   <FilesMatch "\\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
================================================================================
""")

def main():
    if len(sys.argv) < 2:
        print("Uso: python wordpress_upgrade_checker.py <URL_OU_DOMÍNIO> [--json] [--remediate]")
        print("Exemplo: python wordpress_upgrade_checker.py https://meusite.pt")
        sys.exit(1)
        
    target = sys.argv[1].strip()
    if target in ["--help", "-h"]:
        print("Uso: python wordpress_upgrade_checker.py <URL_OU_DOMÍNIO> [--json] [--remediate]")
        sys.exit(0)
        
    if target == "--remediate":
        print_remediation()
        sys.exit(0)
        
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
        
    is_json = "--json" in sys.argv
    show_remediate = "--remediate" in sys.argv
    
    data = audit_wordpress(target)
    
    if is_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
        
    print("=" * 80)
    print("  TAVARDT PORTUGAL: AUDITOR DE RACE CONDITION NO UPGRADE DO WORDPRESS")
    print("=" * 80)
    print(f"Alvo Auditado: {target}")
    print(f"Postura Geral: {data['posture']}")
    print("-" * 80)
    print("Rotas Inspecionadas:")
    for r in data["routes"]:
        status = r["status"] if r["status"] != 0 else "Falha de Conexão"
        list_flag = " [DIRECTORY LISTING DETETADO]" if r.get("directory_listing") else ""
        print(f" * [{r['risk']}] {r['path']} -> HTTP {status}{list_flag}")
        
    print("-" * 80)
    if data["is_vulnerable"]:
        print("[ALERTA CRÍTICO] O servidor apresenta brechas de exposição em wp-content/upgrade/.")
        print("Atacantes podem explorar janelas de corrida para executar scripts PHP temporários.")
    else:
        print("[CONFORME] Diretório wp-content/upgrade/ devidamente restrito contra acesso direto.")
        
    if show_remediate:
        print_remediation()
    else:
        print("Dica: Execute com --remediate para visualizar os blocos de configuração de correção.")
    print("=" * 80)

if __name__ == "__main__":
    main()
