"""
Argos — adapter do semgrep (Fase 2), com ponte WSL.

Semgrep é o SAST poliglota: regras pra dezenas de linguagens e frameworks
(Django, Flask, Express, Spring...). É ele que dá alcance ao Argos além do
Python.

No Windows, semgrep é chato de rodar nativo, então usamos o WSL. O adapter
se vira sozinho:
  - se houver `semgrep` nativo no PATH (ex.: rodando dentro do WSL/Linux), usa direto;
  - senão, no Windows, chama `wsl semgrep ...`, convertendo o caminho
    C:\\... -> /mnt/c/... na ida e de volta na exibição.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .base import Adapter, Contexto, achar_executavel, caminho_relativo
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

_SEV = {
    "ERROR": Severidade.ALTO,
    "WARNING": Severidade.MEDIO,
    "INFO": Severidade.BAIXO,
}


def _win_para_wsl(caminho: str) -> str:
    """C:\\Users\\x\\p -> /mnt/c/Users/x/p. Caminho relativo passa só trocando a barra."""
    c = caminho.replace("\\", "/")
    m = re.match(r"^([a-zA-Z]):/(.*)$", c)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return c


def _wsl_para_win(caminho: str) -> str:
    """/mnt/c/Users/x -> C:\\Users\\x. Caminho sem /mnt/ volta igual."""
    m = re.match(r"^/mnt/([a-zA-Z])/(.*)$", caminho)
    if m:
        return f"{m.group(1).upper()}:\\" + m.group(2).replace("/", "\\")
    return caminho


def parse_relatorio(dados: dict, traduzir=None, raiz=None) -> list[Finding]:
    """json do semgrep -> lista de Findings. Função pura (testável sem a ferramenta)."""
    traduzir = traduzir or (lambda p: p)
    findings: list[Finding] = []
    for i, r in enumerate(dados.get("results", []), start=1):
        extra = r.get("extra", {}) or {}
        sev = _SEV.get((extra.get("severity") or "").upper(), Severidade.MEDIO)
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        check_id = r.get("check_id", "semgrep")
        categoria = cwe[0].split(":")[0].strip() if cwe else check_id.split(".")[-1]
        msg = (extra.get("message") or check_id or "Problema de codigo").strip()
        caminho = caminho_relativo(traduzir(r.get("path", "?")), raiz)
        linha = (r.get("start") or {}).get("line", "?")
        findings.append(
            Finding(
                id=f"CODE-S{i:03d}",
                titulo=msg.split("\n")[0][:120],
                severidade=sev,
                categoria=categoria,
                origem="semgrep",
                local=f"{caminho}:{linha}",
                evidencia=check_id[:120],
                lentes=[Lente.CRITICO],
                fix=Fix(FixTipo.IA, "Aplicar a correcao que a regra do Semgrep aponta."),
                verificacao=f"re-rodar semgrep -> regra {check_id.split('.')[-1]} limpa",
            )
        )
    return findings


class SemgrepAdapter(Adapter):
    nome = "semgrep"

    def __init__(self) -> None:
        self._modo: str | None = None  # "native" | "wsl" | None
        self._exe: str | None = None   # caminho do semgrep nativo
        self._detectado = False

    def _detectar(self) -> None:
        if self._detectado:
            return
        self._detectado = True
        self._exe = achar_executavel("semgrep")
        if self._exe:
            self._modo = "native"
            return
        if os.name == "nt" and shutil.which("wsl"):
            try:
                p = subprocess.run(["wsl", "semgrep", "--version"], capture_output=True, text=True)
                if p.returncode == 0:
                    self._modo = "wsl"
                    return
            except Exception:
                pass
        self._modo = None

    def disponivel(self) -> bool:
        self._detectar()
        return self._modo is not None

    def como_instalar(self) -> str:
        if os.name != "nt":
            return "Instale: pip install semgrep"
        return (
            "Instale o semgrep no WSL (Ubuntu): sudo python3 -m venv /opt/semgrep && "
            "sudo /opt/semgrep/bin/pip install semgrep && "
            "sudo ln -sf /opt/semgrep/bin/semgrep /usr/local/bin/semgrep"
        )

    def escanear(self, ctx: Contexto) -> list[Finding]:
        self._detectar()
        if self._modo is None:
            raise FileNotFoundError(
                "semgrep nao encontrado (nem nativo, nem via WSL). " + self.como_instalar()
            )

        # "--config auto" exige telemetria ligada; com --metrics=off usamos regras fixas
        # do registro (precisa de internet): padrao poliglota + Django + segredos.
        regras = []
        for r in ("p/default", "p/django", "p/secrets"):
            regras += ["--config", r]
        base = ["semgrep", "scan", *regras, "--json", "--metrics=off", "--quiet"]
        if self._modo == "wsl":
            alvo = _win_para_wsl(os.path.abspath(ctx.projeto))
            cmd = ["wsl"] + base + [alvo]
            traduzir = _wsl_para_win
        else:
            cmd = [self._exe or "semgrep"] + base[1:] + [ctx.projeto]
            traduzir = None

        proc = progresso.rodar(cmd)
        # semgrep: 0 = ok, 1 = achou algo. >=2 = erro de verdade.
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"semgrep falhou (codigo {proc.returncode}): {proc.stderr.strip()[:300]}"
            )
        saida = proc.stdout.strip()
        if not saida:
            return []
        return parse_relatorio(json.loads(saida), traduzir=traduzir, raiz=os.path.abspath(ctx.projeto))
