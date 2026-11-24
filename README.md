# Central de Hardening e Auditoria contra Condições de Corrida em WordPress

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![W3C](https://img.shields.io/badge/W3C-Standard-blue.svg)](https://www.w3.org/)
[![CVE Defense](https://img.shields.io/badge/Defense-Race%20Condition-green.svg)](https://ag.tavardt.com/pt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Diagnóstico de Vulnerabilidades de Concorrência, Proteção de Atualizações de Plugins e Hardening de Servidores Web**

Desenvolvido e mantido pela divisão de cibersegurança web e infraestrutura CMS da TAVARDT Portugal.

***

## Portais e Demonstração Online

Aceda à ferramenta interativa oficial e aos canais soberanos da TAVARDT:

* **Aplicação Web Oficial no GitHub Pages**: [https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/](https://tavardt-portugal.github.io/wordpress-upgrade-race-checker-pt/)
* **Portal Institucional**: [https://ag.tavardt.com/pt/](https://ag.tavardt.com/pt/)
* **Central de Ferramentas**: [https://tools.tavardt.com/pt/](https://tools.tavardt.com/pt/)

***

## Blueprints Técnicos e Recursos Disponíveis

1. **Aplicação Web Interativa**: Diagnóstico determinístico, cálculo de postura defensiva e recomendações imediatas no navegador.
2. **Utilitário CLI Local**: Script Python determinístico executado diretamente no ambiente de produção para auditoria offline.
3. **Especificações de Segurança**: Manifestos e configurações de hardening em conformidade com as normas internacionais.

***

## Uso do Utilitário CLI Determinístico

Para executar a inspeção técnica no ambiente local:

```bash
git clone https://github.com/TAVARDT-Portugal/wordpress-upgrade-race-checker-pt.git
cd wordpress-upgrade-race-checker-pt
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 scanner.py -json
```

***

## Links Úteis

* **Portal Corporativo:** https://ag.tavardt.com/pt/
* **Suíte de Diagnósticos:** https://tools.tavardt.com/pt/
* **Contacto Técnico:** https://ag.tavardt.com/pt/contacto/

***

© 2026 TAVARDT Portugal. Todos os direitos reservados. Soberania e Defesa de Infraestrutura.
