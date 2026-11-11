"""
Argos — adapter do bandit (Fase 2).

bandit é o SAST (análise estática) de código Python: acha `eval` em input,
`subprocess` com shell=True, md5/sha1 pra senha, asserts em producao, etc.
Instala com `pip install bandit` — amigo do Windows e do teu stack Django.

(Pra cobrir outras linguagens depois, o Semgrep entra como mais um adapter.)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from .base import Adapter, Contexto
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

_SEV = {
    "HIGH": Severidade.ALTO,
    "MEDIUM": Severidade.MEDIO,
    "LOW": Severidade.BAIXO,
}


def parse_relatorio(dados: dict) -> list[Finding]:
    """json do bandit -> lista de Findings. Função pura (testável sem a ferramenta)."""
    findings: list[Finding] = []
    for i, r in enumerate(dados.get("results", []), start=1):
        sev = _SEV.get((r.get("issue_severity") or "").upper(), Severidade.MEDIO)
        cwe = r.get("issue_cwe") or {}
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
        categoria = f"CWE-{cwe_id}" if cwe_id else (r.get("test_id") or "bandit")
        texto = (r.get("issue_text") or r.get("test_name") or "Problema de codigo").strip()
        findings.append(
            Finding(
                id=f"CODE-{i:03d}",
                titulo=texto.split("\n")[0][:120],
                severidade=sev,
                categoria=categoria,
                origem="bandit",
                local=f"{r.get('filename', '?')}:{r.get('line_number', '?')}",
                evidencia=f"{r.get('test_id', '')} {r.get('test_name', '')}".strip(),
                lentes=[Lente.CRITICO],
                fix=Fix(FixTipo.IA, "Revisar o trecho e aplicar a pratica segura que a regra aponta."),
                verificacao=f"re-rodar bandit -> regra {r.get('test_id', '')} limpa",
            )
        )
    return findings


class BanditAdapter(Adapter):
    nome = "bandit"

    def disponivel(self) -> bool:
        return shutil.which("bandit") is not None

    def como_instalar(self) -> str:
        return "Instale: pip install bandit"

    def escanear(self, ctx: Contexto) -> list[Finding]:
        if not self.disponivel():
            raise FileNotFoundError("bandit nao encontrado. " + self.como_instalar())
        with tempfile.TemporaryDirectory() as tmp:
            rel = os.path.join(tmp, "bandit.json")
            cmd = ["bandit", "-r", ctx.projeto, "-f", "json", "-o", rel, "-q"]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            # bandit: 0 = limpo, 1 = achou problema.
            if proc.returncode not in (0, 1):
                raise RuntimeError(
                    f"bandit falhou (codigo {proc.returncode}): {proc.stderr.strip()[:300]}"
                )
            if not os.path.exists(rel):
                return []
            with open(rel, encoding="utf-8") as fp:
                conteudo = fp.read().strip()
            if not conteudo:
                return []
            return parse_relatorio(json.loads(conteudo))
