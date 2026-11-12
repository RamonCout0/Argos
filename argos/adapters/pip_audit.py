"""
Argos — adapter do pip-audit (Fase 2).

pip-audit (da PyPA) olha as dependências Python do projeto e cruza com a
base de vulnerabilidades (OSV/PyPI Advisory). É o nosso scanner de SCA
(Software Composition Analysis) amigo do Windows: instala com `pip install`.

É aqui que o FIX DETERMINÍSTICO brilha: quando existe versão corrigida, a
resposta é exata ("sobe pra versão X") e vem direto do advisory — não passa
pela IA.

Observação de severidade: pip-audit não traz CVSS, então usamos ALTO como
default cauteloso (dependência com CVE conhecido não deveria ir pra prod).
É uma escolha de projeto, fácil de afrouxar depois.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from .base import Adapter, Contexto, achar_executavel
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo


def parse_relatorio(dados: dict, origem_arquivo: str = "requirements.txt") -> list[Finding]:
    """json do pip-audit -> lista de Findings. Função pura (testável sem a ferramenta)."""
    findings: list[Finding] = []
    i = 0
    for dep in dados.get("dependencies", []):
        nome = dep.get("name", "?")
        versao = dep.get("version", "?")
        for vuln in dep.get("vulns", []) or []:
            i += 1
            vid = vuln.get("id", "VULN")
            aliases = vuln.get("aliases", []) or []
            cve = next((a for a in aliases if a.startswith("CVE-")), vid)
            fixes = vuln.get("fix_versions", []) or []
            desc = (vuln.get("description") or "").strip().split("\n")[0][:140]
            if fixes:
                fix = Fix(
                    FixTipo.DETERMINISTICO,
                    f"Subir {nome} para >= {fixes[0]}.",
                    f"{nome}=={fixes[0]}",
                )
            else:
                fix = Fix(
                    FixTipo.IA,
                    f"Sem versao corrigida publicada p/ {nome}. "
                    "Avaliar troca de dependencia ou mitigacao.",
                )
            findings.append(
                Finding(
                    id=f"DEP-{i:03d}",
                    titulo=f"{nome} {versao} vulneravel ({cve})",
                    severidade=Severidade.ALTO,
                    categoria=cve,
                    origem="pip-audit",
                    local=f"{origem_arquivo}:{nome}",
                    evidencia=desc or vid,
                    lentes=[Lente.CRITICO],
                    fix=fix,
                    verificacao="re-rodar pip-audit -> sem vuln nessa dependencia",
                )
            )
    return findings


class PipAuditAdapter(Adapter):
    nome = "pip-audit"

    def _cmd(self) -> list[str] | None:
        """O executavel no PATH, ou o modulo instalado no Python que roda o Argos (venv)."""
        exe = achar_executavel("pip-audit")
        if exe:
            return [exe]
        import importlib.util
        import sys
        if importlib.util.find_spec("pip_audit") is not None:
            return [sys.executable, "-m", "pip_audit"]
        return None

    def disponivel(self) -> bool:
        return self._cmd() is not None

    def como_instalar(self) -> str:
        return "Instale no mesmo Python do Argos: python -m pip install pip-audit  (precisa de internet pra consultar a base de CVEs)."

    def _requirements(self, projeto: str) -> str | None:
        caminho = os.path.join(projeto, "requirements.txt")
        return caminho if os.path.exists(caminho) else None

    def escanear(self, ctx: Contexto) -> list[Finding]:
        if not self.disponivel():
            raise FileNotFoundError("pip-audit nao encontrado. " + self.como_instalar())
        req = self._requirements(ctx.projeto)
        if not req:
            return []  # sem requirements.txt, nada a auditar nesta fase

        cmd = self._cmd() + ["-r", req, "-f", "json", "--progress-spinner", "off"]
        proc = progresso.rodar(cmd)
        # pip-audit: 0 = limpo, 1 = achou vulnerabilidade. O JSON sai no stdout.
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"pip-audit falhou (codigo {proc.returncode}): {proc.stderr.strip()[:300]}"
            )
        saida = proc.stdout.strip()
        if not saida:
            return []
        return parse_relatorio(json.loads(saida))
