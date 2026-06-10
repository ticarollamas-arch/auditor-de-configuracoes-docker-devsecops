```
=====================================================================
  ____             _               ____               ___        
 |  _ \  ___   ___| | _____ _ __  / ___|  ___  ___   / _ \ _ __  
 | | | |/ _ \ / __| |/ / _ \ '__| \___ \ / _ \/ __| | | | | '_ \ 
 | |_| | (_) | (__|   <  __/ |     ___) |  __/ (__  | |_| | |_) |
 |____/ \___/ \___|_|\_\___|_|    |____/ \___|\___|  \___/| .__/ 
                                                          |_|    
  AUDITOR PASSIVO DE CONFIGURAÇÕES DOCKER - DEVSECOPS v1.0.0
=====================================================================
```

# Auditor de Configurações Docker DevSecOps

> **Objetivo:** Auditar estaticamente arquivos Dockerfile e docker-compose.yml para identificar vulnerabilidades de configuração, privilégios excessivos e desvios de conformidade de segurança.

## Sobre o Projeto
Auditar estaticamente arquivos Dockerfile e docker-compose.yml para identificar vulnerabilidades de configuração, privilégios excessivos e desvios de conformidade de segurança.

## 🛠️ Tecnologias e Módulos

- **Linguagens principais:** Python
- **Banco de dados recomendado:** N/A (Não aplicável para esta ferramenta CLI)
- **Módulos nativos recomendados:** argparse, json, os, re, sys
- **Dependências Externas:**
  - `colorama` (^0.4.6): Colorização de saídas no terminal para facilitar a triagem visual de vulnerabilidades.
  - `PyYAML` (^6.0.1): Análise sintática estruturada de arquivos docker-compose.yml.

## 🔒 Configurações de Segurança & Higiene Digital

- **Abordagem defensiva:** `DEFENSIVO`
- **Práticas de higiene digital:** Análise estática passiva de arquivos de configuração (IaC) para prevenção de vulnerabilidades em tempo de build.
### Medidas de Mitigação Implementadas:
- **Risco / Ameaça:** Execução de processos internos do contêiner como Root → **Plano de Mitigação:** Exigir a instrução 'USER' com UID não-root no Dockerfile.
- **Risco / Ameaça:** Exposição acidental de portas de gerenciamento → **Plano de Mitigação:** Bloquear a exposição de portas como 22 (SSH), 2375 (Docker API) e 3389 (RDP) nas diretivas EXPOSE e ports.

## 💻 Interface de Linha de Comando (CLI)

- **Pre-requisito / Comando:** `auditor_passivo.py`
- **Instruções de Inicialização:** `python auditor_passivo.py --dockerfile <caminho> --compose <caminho> [opções]`
### Argumentos & Flags Configurados:
- `-d, --dockerfile` (string): Caminho para o arquivo Dockerfile a ser analisado. (Exemplo: `./Dockerfile`)
- `-c, --compose` (string): Caminho para o arquivo docker-compose.yml a ser analisado. (Exemplo: `./docker-compose.yml`)
- `-r, --rules-dir` (string): Diretório contendo as regras JSON de validação. (Exemplo: `./rules`)
- `-s, --min-severity` (string): Severidade mínima para reportar (LOW, MEDIUM, HIGH, CRITICAL). (Exemplo: `HIGH`)

## 📂 Estrutura de Arquivos Criada

Este repositório foi construído de forma limpa e descompactada contendo os seguintes módulos funcionais:

- `rules/dockerfile_rules.json`
- `rules/docker_compose_rules.json`
- `auditor_passivo.py`
- `Dockerfile`
- `README.md`

---
*Blueprint gerado com orgulho através do Senior Software Architecture Hub no AI Studio.*