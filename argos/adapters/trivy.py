"""
Argos — Trivy: erros de configuração de Docker e afins (v2.2).

`trivy config` lê Dockerfile, docker-compose, Kubernetes e Terraform e aponta
o que está inseguro: container rodando como root, imagem sem versão fixa
(:latest), segredo em variável de ambiente no Dockerfile, porta de SSH
exposta... As dependências já são cobertas pelo OSV-Scanner, então aqui o
Trivy olha só a configuração (mais rápido e sem repetir achado).
"""
from __future__ import annotations

import json
import os

from .base import Adapter, Contexto, achar_programa, caminho_relativo
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

_SEV = {"CRITICAL": Severidade.CRITICO, "HIGH": Severidade.ALTO, "MEDIUM": Severidade.MEDIO,
        "LOW": Severidade.BAIXO, "UNKNOWN": Severidade.INFO}
_TEM_CONFIG = ("dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def parse_trivy(dados: dict, raiz: str | None = None) -> list[Finding]:
    achados: list[Finding] = []
    for res in dados.get("Results") or []:
        alvo = caminho_relativo(res.get("Target", "?"), raiz)
        for m in res.get("Misconfigurations") or []:
            if (m.get("Status") or "FAIL") != "FAIL":
                continue
            linha = (m.get("CauseMetadata") or {}).get("StartLine")
            regra = m.get("AVDID") or m.get("ID") or "TRIVY"
            achados.append(Finding(
                id=f"CFG-T{len(achados) + 1:03d}",
                titulo=(m.get("Title") or regra)[:120],
                severidade=_SEV.get((m.get("Severity") or "").upper(), Severidade.MEDIO),
                categoria=f"TRIVY-{m.get('ID') or regra}", origem="trivy",
                local=f"{alvo}:{linha}" if linha else alvo,
                evidencia=(m.get("Message") or m.get("Description") or "")[:220],
                lentes=[Lente.CRITICO],
                fix=Fix(FixTipo.IA, (m.get("Resolution") or "Seguir a recomendação do Trivy.")[:240]),
                verificacao="re-rodar o scan -> achado some",
                explicacao=(m.get("Description") or "")[:400]))
    return achados


def tem_config(raiz: str) -> bool:
    for pasta, dirs, nomes in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "venv", ".venv"} and not d.startswith(".")]
        if any(n.lower() in _TEM_CONFIG or n.lower().startswith("dockerfile") for n in nomes):
            return True
        if pasta.count(os.sep) - raiz.count(os.sep) >= 3:
            dirs[:] = []
    return False


class TrivyAdapter(Adapter):
    nome = "trivy"

    def disponivel(self) -> bool:
        return achar_programa("trivy") is not None

    def como_instalar(self) -> str:
        return ("Instale o Trivy (Dockerfile/docker-compose): winget install AquaSecurity.Trivy  "
                "(ou choco install trivy, ou baixe de github.com/aquasecurity/trivy/releases).")

    def escanear(self, ctx: Contexto) -> list[Finding]:
        raiz = os.path.abspath(ctx.projeto)
        if not tem_config(raiz):
            progresso.avisar("trivy: sem Dockerfile/docker-compose no projeto", "info")
            return []
        exe = achar_programa("trivy")
        proc = progresso.rodar([exe, "config", "--format", "json", "--quiet", raiz], timeout=600)
        if proc.returncode != 0:
            raise RuntimeError(f"trivy falhou ({proc.returncode}): {(proc.stderr or '').strip()[:300]}")
        saida = (proc.stdout or "").strip()
        return parse_trivy(json.loads(saida), raiz=raiz) if saida else []
