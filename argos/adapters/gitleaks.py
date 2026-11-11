"""
Argos — adapter do gitleaks (Fase 1).

gitleaks varre o código atrás de segredos vazados (chaves de API, tokens,
senhas hardcoded). É o primeiro olho do Argos: fácil de rodar, agnóstico
de linguagem (é regex em texto), e muito satisfatório de ver funcionando.

Escrevemos o relatório JSON num arquivo temporário e traduzimos cada
achado num Finding. O segredo em si é SEMPRE mascarado — um tool de
segurança não cospe o segredo de volta.

Robustez de versão: o gitseaks mudou de comando ao longo do tempo. As
versões novas usam `gitleaks dir <pasta>`; as antigas, `gitleaks detect
--source <pasta> --no-git`. Detectamos qual existe e usamos o certo.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from .base import Adapter, Contexto
from ..schema import Finding, Severidade, Lente, Fix, FixTipo


def _mascarar(segredo: str) -> str:
    s = segredo or ""
    if not s:
        return "(oculto)"
    if len(s) <= 8:
        return s[:2] + "***"
    return f"{s[:4]}***{s[-2:]}"


def parse_relatorio(dados: list[dict]) -> list[Finding]:
    """json do gitleaks -> lista de Findings. Função pura (testável sem gitleaks)."""
    findings: list[Finding] = []
    for i, item in enumerate(dados, start=1):
        arquivo = item.get("File", "?")
        linha = item.get("StartLine", item.get("Line", "?"))
        regra = item.get("RuleID") or item.get("Rule") or "segredo"
        desc = item.get("Description") or f"Segredo detectado ({regra})"
        segredo = item.get("Secret", "")
        findings.append(
            Finding(
                id=f"SECRET-{i:03d}",
                titulo=desc,
                severidade=Severidade.CRITICO,
                categoria="CWE-798",
                origem="gitleaks",
                local=f"{arquivo}:{linha}",
                evidencia=f"{regra}: {_mascarar(segredo)}",
                lentes=[Lente.CRITICO, Lente.LGPD],
                fix=Fix(
                    FixTipo.IA,
                    "Remover o segredo do codigo e mover pra variavel de ambiente "
                    "(.env, fora do git). Rotacionar a chave, pois ja foi exposta.",
                    "chave = os.getenv('NOME_DA_CHAVE')",
                ),
                verificacao="re-rodar gitleaks -> 0 ocorrencias nesse arquivo",
            )
        )
    return findings


class GitleaksAdapter(Adapter):
    nome = "gitleaks"

    def disponivel(self) -> bool:
        return shutil.which("gitleaks") is not None

    def como_instalar(self) -> str:
        return (
            "Instale o gitleaks: winget install gitleaks  (ou choco install gitleaks, "
            "brew install gitleaks, ou baixe de github.com/gitleaks/gitleaks/releases)."
        )

    def _suporta_dir(self) -> bool:
        """Versões novas do gitleaks têm o subcomando `dir`. As antigas, não."""
        try:
            p = subprocess.run(
                ["gitleaks", "dir", "--help"], capture_output=True, text=True
            )
            return p.returncode == 0
        except Exception:
            return False

    def _montar_comando(self, projeto: str, relatorio: str) -> list[str]:
        if self._suporta_dir():
            return [
                "gitleaks", "dir", projeto,
                "--report-format", "json",
                "--report-path", relatorio,
            ]
        return [
            "gitleaks", "detect",
            "--source", projeto,
            "--no-git",
            "--report-format", "json",
            "--report-path", relatorio,
        ]

    def escanear(self, ctx: Contexto) -> list[Finding]:
        if not self.disponivel():
            raise FileNotFoundError("gitleaks nao encontrado no PATH. " + self.como_instalar())

        with tempfile.TemporaryDirectory() as tmp:
            relatorio = os.path.join(tmp, "gitleaks.json")
            cmd = self._montar_comando(ctx.projeto, relatorio)
            proc = subprocess.run(cmd, capture_output=True, text=True)
            # gitleaks: 0 = limpo, 1 = achou vazamento. Ambos sao "rodou ok".
            if proc.returncode not in (0, 1):
                raise RuntimeError(
                    f"gitleaks falhou (codigo {proc.returncode}) com o comando "
                    f"{' '.join(cmd[:3])}. stderr: {proc.stderr.strip()[:300]}"
                )
            if not os.path.exists(relatorio):
                return []
            with open(relatorio, encoding="utf-8") as fp:
                conteudo = fp.read().strip()
            if not conteudo or conteudo == "null":
                return []
            return parse_relatorio(json.loads(conteudo))
