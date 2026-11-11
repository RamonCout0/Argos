"""
Argos — o orquestrador (o maestro).

Código burro e determinístico de propósito: roda cada adapter disponível,
junta os findings e reporta quem rodou e quem foi pulado.
Nada de IA aqui — o fluxo tem que ser previsível e reproduzível.

Três trilhas, mesma esteira (lentes -> dedup -> score):
  - escanear_projeto: o CODIGO parado (gitleaks, pip-audit, semgrep)
  - escanear_nativo:  o app RODANDO, portas (psutil + nmap)       [Fase 5]
  - analisar_trafego: o que o app MANDA em HTTP sem TLS (tshark)  [Fase 5]

Registrar um scanner novo = adicionar uma linha na lista da trilha.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import Finding
from ..lenses.mapa import enriquecer
from .dedup import deduplicar
from ..adapters.base import Adapter, Contexto
from ..adapters.gitleaks import GitleaksAdapter
from ..adapters.pip_audit import PipAuditAdapter
from ..adapters.semgrep import SemgrepAdapter
from ..adapters.portas import PortasAdapter
from ..adapters.nmap import NmapAdapter
from ..adapters.tshark import TsharkAdapter
# from ..adapters.bandit import BanditAdapter  # extra: SAST so-Python nativo no Windows

# Trilha 1 — codigo
ADAPTERS: list[Adapter] = [
    GitleaksAdapter(),   # segredos vazados
    PipAuditAdapter(),   # CVE em dependencias Python
    SemgrepAdapter(),    # SAST poliglota (via WSL no Windows)
    # BanditAdapter(),   # descomente p/ uma 2a passada so-Python (sobrepoe o semgrep)
]

# Trilha 2 — portas do app rodando (a ordem importa: psutil primeiro, nmap confirma)
NATIVOS: list[Adapter] = [
    PortasAdapter(),
    NmapAdapter(),
]

# Trilha 3 — trafego
TRAFEGO: list[Adapter] = [
    TsharkAdapter(),
]


@dataclass
class Resultado:
    findings: list[Finding] = field(default_factory=list)
    rodaram: list[str] = field(default_factory=list)
    pulados: list[tuple[str, str]] = field(default_factory=list)  # (nome, motivo)
    fundidos: int = 0  # quantos achados repetidos entre scanners foram fundidos


def _rodar(adapters: list[Adapter], ctx: Contexto) -> Resultado:
    res = Resultado()
    for ad in adapters:
        if not ad.disponivel():
            res.pulados.append((ad.nome, "nao instalado. " + ad.como_instalar()))
            continue
        try:
            res.findings.extend(ad.escanear(ctx))
            res.rodaram.append(ad.nome)
        except Exception as e:  # um scanner que quebra nao derruba o scan todo
            res.pulados.append((ad.nome, f"erro: {e}"))

    # pos-processamento deterministico: lentes primeiro, depois funde repetidos
    antes = len(res.findings)
    res.findings = deduplicar(enriquecer(res.findings))
    res.fundidos = antes - len(res.findings)
    return res


def escanear_projeto(caminho: str, adapters: list[Adapter] | None = None) -> Resultado:
    return _rodar(adapters if adapters is not None else ADAPTERS, Contexto(projeto=caminho))


def escanear_nativo(opcoes: dict, adapters: list[Adapter] | None = None) -> Resultado:
    return _rodar(adapters if adapters is not None else NATIVOS, Contexto(projeto="", opcoes=opcoes))


def analisar_trafego(opcoes: dict, adapters: list[Adapter] | None = None) -> Resultado:
    return _rodar(adapters if adapters is not None else TRAFEGO, Contexto(projeto="", opcoes=opcoes))


def auditar(pasta: str | None = None, nativo: dict | None = None,
            trafego: dict | None = None) -> Resultado:
    """Fase 6: roda as trilhas pedidas e junta tudo num veredito so."""
    partes = []
    if pasta:
        partes.append(("codigo", escanear_projeto(pasta)))
    if nativo:
        partes.append(("nativo", escanear_nativo(nativo)))
    if trafego:
        partes.append(("trafego", analisar_trafego(trafego)))

    res = Resultado()
    for trilha, r in partes:
        res.findings.extend(r.findings)
        res.rodaram.extend(f"{trilha}:{n}" for n in r.rodaram)
        res.pulados.extend((f"{trilha}:{n}", m) for n, m in r.pulados)
        res.fundidos += r.fundidos
    antes = len(res.findings)
    res.findings = deduplicar(res.findings)  # a mesma brecha pode aparecer em duas trilhas
    res.fundidos += antes - len(res.findings)
    return res
