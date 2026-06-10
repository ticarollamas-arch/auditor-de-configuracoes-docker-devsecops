"""
Auditor Passivo de Configurações Docker - DevSecOps
Autor: Arquiteto de Software de Elite & Engenheiro de Prompts Sênior
Descrição: Analisador estático defensivo para Dockerfile e docker-compose.yml.
"""

import os
import sys
import re
import json
import argparse
import yaml
from colorama import init, Fore, Style

# Inicializa o colorama para compatibilidade de cores no terminal
init(autoreset=True)

BANNER = """" + "\033[1;36m" + """
=====================================================================
  ____             _               ____               ___        
 |  _ \  ___   ___| | _____ _ __  / ___|  ___  ___   / _ \ _ __  
 | | | |/ _ \ / __| |/ / _ \ '__| \___ \ / _ \/ __| | | | | '_ \ 
 | |_| | (_) | (__|   <  __/ |     ___) |  __/ (__  | |_| | |_) |
 |____/ \___/ \___|_|\_\___|_|    |____/ \___|\___|  \___/| .__/ 
                                                          |_|    
  AUDITOR PASSIVO DE CONFIGURAÇÕES DOCKER - DEVSECOPS v1.0.0
=====================================================================
""" + Style.RESET_ALL

SEVERITY_COLORS = {
    "LOW": Fore.BLUE + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "HIGH": Fore.RED + Style.BRIGHT,
    "CRITICAL": Fore.RED + Style.BACKGROUND_BLACK + Style.BRIGHT
}

SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def load_rules(rules_path):
    """Carrega as regras de segurança a partir de um arquivo JSON."""
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            return json.load(f).get("rules", [])
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao carregar regras de {rules_path}: {e}{Style.RESET_ALL}")
        return []

def analyze_dockerfile(filepath, rules, min_severity_level):
    """Analisa o Dockerfile linha por linha aplicando as regras de segurança."""
    findings = []
    if not os.path.exists(filepath):
        print(f"{Fore.YELLOW}[!] Dockerfile não encontrado em: {filepath}{Style.RESET_ALL}")
        return findings

    print(f"{Fore.CYAN}[*] Analisando Dockerfile: {filepath}{Style.RESET_ALL}")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao ler Dockerfile: {e}{Style.RESET_ALL}")
        return findings

    # Estado para verificação de regras de fluxo
    has_user = False
    has_healthcheck = False
    
    for idx, line in enumerate(lines):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith('#'):
            continue

        # Regra DF-001: FROM latest ou sem tag
        if clean_line.upper().startswith("FROM"):
            if ":latest" in clean_line.lower() or ":" not in clean_line:
                rule = next((r for r in rules if r["id"] == "DF-001"), None)
                if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
                    findings.append((rule, idx + 1, clean_line))

        # Regra DF-002: Controle de USER
        if clean_line.upper().startswith("USER"):
            if "root" not in clean_line.lower():
                has_user = True

        # Regra DF-003: Exposição de portas perigosas
        if clean_line.upper().startswith("EXPOSE"):
            ports = re.findall(r'\d+', clean_line)
            dangerous_ports = ["22", "3389", "2375", "2376", "5000", "9000"]
            for port in ports:
                if port in dangerous_ports:
                    rule = next((r for r in rules if r["id"] == "DF-003"), None)
                    if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
                        findings.append((rule, idx + 1, f"{clean_line} (Porta de risco: {port})"))

        # Regra DF-004: HEALTHCHECK
        if clean_line.upper().startswith("HEALTHCHECK"):
            has_healthcheck = True

    # Validações de fim de arquivo
    if not has_user:
        rule = next((r for r in rules if r["id"] == "DF-002"), None)
        if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
            findings.append((rule, "N/A", "Nenhum usuário não-root definido via instrução USER."))
            
    if not has_healthcheck:
        rule = next((r for r in rules if r["id"] == "DF-004"), None)
        if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
            findings.append((rule, "N/A", "Instrução HEALTHCHECK ausente no arquivo."))

    return findings

def analyze_compose(filepath, rules, min_severity_level):
    """Analisa o docker-compose.yml utilizando PyYAML."""
    findings = []
    if not os.path.exists(filepath):
        print(f"{Fore.YELLOW}[!] Docker Compose não encontrado em: {filepath}{Style.RESET_ALL}")
        return findings

    print(f"{Fore.CYAN}[*] Analisando Docker Compose: {filepath}{Style.RESET_ALL}")

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao analisar YAML do Docker Compose: {e}{Style.RESET_ALL}")
        return findings

    if not data or 'services' not in data:
        return findings

    services = data.get('services', {})
    for service_name, config in services.items():
        if not config:
            continue
        
        # Regra DC-001: Privileged mode
        if config.get('privileged') is True:
            rule = next((r for r in rules if r["id"] == "DC-001"), None)
            if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
                findings.append((rule, f"services -> {service_name}", "privileged: true"))

        # Regra DC-002: Network Mode Host
        if config.get('network_mode') == 'host':
            rule = next((r for r in rules if r["id"] == "DC-002"), None)
            if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
                findings.append((rule, f"services -> {service_name}", "network_mode: host"))

        # Regra DC-003: Docker Socket Mount
        volumes = config.get('volumes', [])
        for vol in volumes:
            vol_str = vol if isinstance(vol, str) else vol.get('source', '')
            if 'docker.sock' in vol_str:
                rule = next((r for r in rules if r["id"] == "DC-003"), None)
                if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
                    findings.append((rule, f"services -> {service_name} -> volumes", f"Montagem de socket detectada: {vol_str}"))

        # Regra DC-004: Resource Limits
        has_limits = False
        if 'deploy' in config and 'resources' in config['deploy']:
            resources = config['deploy']['resources']
            if 'limits' in resources:
                has_limits = True
        elif 'mem_limit' in config or 'cpus' in config:
            has_limits = True

        if not has_limits:
            rule = next((r for r in rules if r["id"] == "DC-004"), None)
            if rule and SEVERITY_LEVELS.get(rule["severity"], 0) >= min_severity_level:
                findings.append((rule, f"services -> {service_name}", "Limites de CPU/Memória não configurados."))

    return findings

def print_report(findings):
    """Exibe o relatório formatado de vulnerabilidades encontradas."""
    if not findings:
        print(f"\n{Fore.GREEN}[+] Parabéns! Nenhuma inconformidade de segurança foi detectada com os parâmetros atuais.{Style.RESET_ALL}\n")
        return

    print(f"\n{Fore.YELLOW}=== RELATÓRIO DE AUDITORIA DE SEGURANÇA ==={Style.RESET_ALL}\n")
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for rule, location, evidence in findings:
        sev = rule["severity"]
        if sev == "CRITICAL": critical_count += 1
        elif sev == "HIGH": high_count += 1
        elif sev == "MEDIUM": medium_count += 1
        elif sev == "LOW": low_count += 1

        color = SEVERITY_COLORS.get(sev, Fore.WHITE)
        print(f"{color}[{sev}] {rule['id']} - {rule['title']}{Style.RESET_ALL}")
        print(f"  - Localização: Linha/Estrutura {location}")
        print(f"  - Evidência:   {evidence}")
        print(f"  - CVSS Score:  {rule['cvss']}")
        print(f"  - Descrição:   {rule['description']}")
        print(f"  - Correção:    {Fore.GREEN}{rule['remediation']}{Style.RESET_ALL}")
        print("-" * 70)

    print(f"\n{Fore.CYAN}Resumo da Auditoria:{Style.RESET_ALL}")
    print(f"  - {SEVERITY_COLORS['CRITICAL']}CRÍTICA:  {critical_count}{Style.RESET_ALL}")
    print(f"  - {SEVERITY_COLORS['HIGH']}ALTA:      {high_count}{Style.RESET_ALL}")
    print(f"  - {SEVERITY_COLORS['MEDIUM']}MÉDIA:     {medium_count}{Style.RESET_ALL}")
    print(f"  - {SEVERITY_COLORS['LOW']}BAIXA:     {low_count}{Style.RESET_ALL}")
    print(f"Total de inconformidades: {len(findings)}\n")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Auditor Passivo de Segurança para Docker e Docker Compose.")
    parser.add_argument("-d", "--dockerfile", help="Caminho para o Dockerfile", default=None)
    parser.add_argument("-c", "--compose", help="Caminho para o docker-compose.yml", default=None)
    parser.add_argument("-r", "--rules-dir", help="Diretório das regras JSON", default="./rules")
    parser.add_argument("-s", "--min-severity", help="Severidade mínima (LOW, MEDIUM, HIGH, CRITICAL)", default="LOW", choices=SEVERITY_LEVELS.keys())

    args = parser.parse_args()
    min_severity_level = SEVERITY_LEVELS[args.min_severity]

    all_findings = []

    if not args.dockerfile and not args.compose:
        print(f"{Fore.RED}[!] Erro: Você deve especificar ao menos um arquivo para análise (--dockerfile ou --compose).{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)

    if args.dockerfile:
        df_rules_path = os.path.join(args.rules_dir, "dockerfile_rules.json")
        df_rules = load_rules(df_rules_path)
        if df_rules:
            all_findings.extend(analyze_dockerfile(args.dockerfile, df_rules, min_severity_level))

    if args.compose:
        dc_rules_path = os.path.join(args.rules_dir, "docker_compose_rules.json")
        dc_rules = load_rules(dc_rules_path)
        if dc_rules:
            all_findings.extend(analyze_compose(args.compose, dc_rules, min_severity_level))

    print_report(all_findings)

    # Retorna código de saída apropriado para pipelines de CI/CD
    # Se houver falhas HIGH ou CRITICAL, falha o build
    has_critical_or_high = any(f[0]["severity"] in ["HIGH", "CRITICAL"] for f in all_findings)
    if has_critical_or_high:
        print(f"{Fore.RED}[!] Auditoria falhou devido a vulnerabilidades críticas/altas encontradas.{Style.RESET_ALL}")
        sys.exit(1)
    else:
        print(f"{Fore.GREEN}[+] Auditoria concluída com sucesso.{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
"