"""
Argos — adapter do nmap (Fase 5).

Duas perguntas, sempre só nas portas que você apontou (nunca a faixa toda):
  1. Em 127.0.0.1: QUE serviço é esse? (nome, produto, versão)
  2. Com --rede, no IP desta máquina na rede local: o que OUTRO aparelho do
     mesmo wifi enxerga? Se abriu ali, a exposição está confirmada de fora.

Modo leve de propósito: -sT (conexão normal, não precisa de admin),
--version-light, -T3. Alvo passa pela trava: só loopback ou rede privada.
A verificação de dono do Railway NÃO libera o nmap — o domínio de lá aponta
pra infraestrutura compartilhada, não só pro teu app.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .base import Adapter, Contexto
from ..core import progresso
from ..schema import Finding, Severidade, Fix, FixTipo
from ..guard.target_lock import validar_alvo
from ..native.riscos import risco_da_porta
from .portas import ip_da_rede

_CAMINHOS_WINDOWS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def _binario() -> str | None:
    achado = shutil.which("nmap")
    if achado:
        return achado
    return next((c for c in _CAMINHOS_WINDOWS if os.path.exists(c)), None)


def parse_xml(xml: str) -> list[dict]:
    """saida -oX do nmap -> [{porta, estado, servico, produto, versao}]."""
    portas = []
    raiz = ET.fromstring(xml)
    for p in raiz.iter("port"):
        estado = p.find("state")
        serv = p.find("service")
        portas.append({
            "porta": int(p.get("portid", "0")),
            "estado": estado.get("state", "") if estado is not None else "",
            "servico": serv.get("name", "") if serv is not None else "",
            "produto": serv.get("product", "") if serv is not None else "",
            "versao": serv.get("version", "") if serv is not None else "",
        })
    return portas


def _descricao(p: dict) -> str:
    return " ".join(x for x in (p["servico"], p["produto"], p["versao"]) if x) or "desconhecido"


def findings_locais(portas: list[dict]) -> list[Finding]:
    out = []
    for i, p in enumerate((p for p in portas if p["estado"] == "open"), start=1):
        out.append(Finding(
            id=f"SVC-{i:03d}",
            titulo=f"Porta {p['porta']}: {_descricao(p)}",
            severidade=Severidade.INFO,
            categoria="SERVICO",
            origem="nmap",
            local=f"porta {p['porta']}/tcp",
            evidencia=f"identificado pelo nmap em 127.0.0.1",
        ))
    return out


def findings_rede(portas: list[dict], ip: str) -> list[Finding]:
    out = []
    for i, p in enumerate((p for p in portas if p["estado"] == "open"), start=1):
        sev, cwe, rotulo = risco_da_porta(p["porta"], p["servico"])
        out.append(Finding(
            id=f"NET-{i:03d}",
            titulo=f"Porta {p['porta']} ({rotulo}) aberta pra rede toda, nao so pra tua maquina",
            severidade=sev,
            categoria=cwe,
            origem="nmap",
            local=f"porta {p['porta']}/tcp",
            evidencia=f"acessivel pelo IP da rede {ip}: {_descricao(p)}",
            fix=Fix(FixTipo.IA, "Escutar so em 127.0.0.1 no dev; em producao, atras de firewall/proxy."),
            verificacao=f"re-rodar 'python cli.py nativo --porta {p['porta']} --rede' -> porta fechada pela rede",
        ))
    return out


class NmapAdapter(Adapter):
    nome = "nmap"

    def disponivel(self) -> bool:
        return _binario() is not None

    def como_instalar(self) -> str:
        return "Instale o nmap: https://nmap.org/download (o instalador do Windows ja traz o Npcap)."

    def _rodar(self, ip: str, portas: list[int]) -> list[dict]:
        validar_alvo(ip)  # trava: so loopback/rede privada, sempre
        cmd = [
            _binario(), "-sT", "-sV", "--version-light", "-Pn", "-T3",
            "-p", ",".join(str(p) for p in sorted(set(portas))),
            "-oX", "-", ip,
        ]
        proc = progresso.rodar(cmd, timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"nmap falhou ({proc.returncode}): {proc.stderr.strip()[:300]}")
        return parse_xml(proc.stdout)

    def escanear(self, ctx: Contexto) -> list[Finding]:
        portas = ctx.opcoes.get("portas") or []
        if not portas:
            return []  # nmap so roda com portas explicitas (sem varrer a faixa toda)
        achados = findings_locais(self._rodar("127.0.0.1", portas))
        if ctx.opcoes.get("rede"):
            ip = ip_da_rede()
            if not ip:
                raise RuntimeError("nao consegui descobrir o IP desta maquina na rede")
            achados += findings_rede(self._rodar(ip, portas), ip)
        return achados
