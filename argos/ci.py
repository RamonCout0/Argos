"""
Argos — gera o workflow do GitHub Actions pro projeto.

A cada push na main (e em todo pull request) o GitHub roda:
  1. o scan do código (gitleaks com histórico, OSV-Scanner, pip-audit, semgrep,
     check --deploy, configuração, detector de IDOR);
  2. o modo ataque no laboratório local do próprio runner (sem tocar produção);
  3. guarda os relatórios (HTML, JSON e o .md pra IA) como artefato;
e o check fica VERMELHO se aparecer brecha alta ou crítica.
"""
from __future__ import annotations

import os

WORKFLOW = """\
# Gerado pelo Argos (python cli.py ci-github). Pode editar à vontade.
# Dica de segurança: troque as tags (@v4) pelo SHA do commit de cada action.
name: Argos (segurança)

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  actions: read   # o Argos confirma pela API que esta execução é deste repositório

jobs:
  argos:
    runs-on: ubuntu-latest
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # o gitleaks também olha o histórico

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Dependências do projeto (venv que o Argos usa no laboratório)
        run: |
          python -m venv venv
          venv/bin/pip install -r {requirements}

      - name: Argos e scanners
        run: |
          git clone --depth 1 https://github.com/RamonCout0/Argos /tmp/argos
          pip install -r /tmp/argos/requirements.txt pip-audit semgrep
          mkdir -p "$HOME/.local/bin" && echo "$HOME/.local/bin" >> "$GITHUB_PATH"
          # opcionais: se o download falhar, o Argos só pula esses scanners
          curl -sSfL -o "$HOME/.local/bin/osv-scanner" https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 && chmod +x "$HOME/.local/bin/osv-scanner" || true
          GL=$(curl -sSfL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | python -c "import json,sys; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${{GL}}/gitleaks_${{GL}}_linux_x64.tar.gz" | tar -xz -C "$HOME/.local/bin" gitleaks || true

      - name: Scan do código
        id: scan
        continue-on-error: true
        run: python /tmp/argos/cli.py scan . --falhar-em {falhar} --html argos-scan.html --saida-json argos-scan.json --prompt-ia argos-scan-pra-ia.md

      - name: Modo ataque (laboratório local, sem tocar produção)
        id: ataque
        continue-on-error: true
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
        run: python /tmp/argos/cli.py atacar . --carga-max {carga} --falhar-em {falhar} --html argos-ataque.html --saida-json argos-ataque.json --prompt-ia argos-ataque-pra-ia.md

      - name: Relatórios
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: relatorios-argos
          path: argos-*

      - name: Veredito
        if: steps.scan.outcome == 'failure' || steps.ataque.outcome == 'failure'
        run: |
          echo "O Argos achou brecha de nível {falhar} ou mais grave. Baixe o artefato 'relatorios-argos'."
          exit 1
"""


def achar_requirements(pasta: str) -> str:
    """requirements.txt mais perto do manage.py (Django + Angular costuma ter o back numa subpasta)."""
    candidatos = []
    base = pasta.rstrip(os.sep).count(os.sep)
    for raiz, dirs, nomes in os.walk(pasta):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "venv", ".venv", "dist", "build"}
                   and not d.startswith(".")]
        if "requirements.txt" in nomes:
            candidatos.append((0 if "manage.py" in nomes else 1, raiz.count(os.sep) - base,
                               os.path.relpath(os.path.join(raiz, "requirements.txt"), pasta)))
        if raiz.count(os.sep) - base >= 3:
            dirs[:] = []
    if not candidatos:
        return "requirements.txt"
    return sorted(candidatos)[0][2].replace("\\\\", "/")


def gerar(pasta: str, falhar: str = "alto", carga: int = 64, sobrescrever: bool = False) -> str:
    destino = os.path.join(pasta, ".github", "workflows", "argos.yml")
    if os.path.exists(destino) and not sobrescrever:
        raise FileExistsError(destino)
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    with open(destino, "w", encoding="utf-8", newline="\n") as fp:
        fp.write(WORKFLOW.format(requirements=achar_requirements(pasta), falhar=falhar, carga=carga))
    return destino
