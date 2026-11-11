"""
Argos GUI — estado do checklist (lógica pura, sem Tkinter, testável).

Regra que segue a filosofia do Argos: você MARCA o que já corrigiu, mas a
nota só muda quando o RE-SCAN confirma. No scan seguinte, o que sumiu vira
"resolvido" e a marcação é limpa sozinha.

Tudo fica em .argos_cache/checklist.json, separado por projeto.
"""
from __future__ import annotations

import datetime as dt
import json
import os

from ..core.aceitos import fingerprint
from ..schema import Finding, Severidade, Status

ARQUIVO = os.path.join(".argos_cache", "checklist.json")
ULTIMO = os.path.join(".argos_cache", "ultimo.json")

_ORDEM = {Severidade.CRITICO: 0, Severidade.ALTO: 1, Severidade.MEDIO: 2,
          Severidade.BAIXO: 3, Severidade.INFO: 4}


def carregar(caminho: str = ARQUIVO) -> dict:
    try:
        with open(caminho, encoding="utf-8") as fp:
            dados = json.load(fp)
        return dados if isinstance(dados, dict) else {"projetos": {}}
    except (OSError, json.JSONDecodeError):
        return {"projetos": {}}


def salvar(estado: dict, caminho: str = ARQUIVO) -> None:
    os.makedirs(os.path.dirname(caminho) or ".", exist_ok=True)
    with open(caminho, "w", encoding="utf-8") as fp:
        json.dump(estado, fp, ensure_ascii=False, indent=1)


def chave_alvo(pasta: str = "", portas=None, pcap: str = "") -> str:
    partes = []
    if pasta:
        partes.append(os.path.abspath(pasta))
    if portas:
        partes.append("portas:" + ",".join(str(p) for p in sorted(set(portas))))
    if pcap:
        partes.append("pcap:" + os.path.abspath(pcap))
    return " + ".join(partes) or "geral"


def _projeto(estado: dict, chave: str) -> dict:
    p = estado.setdefault("projetos", {}).setdefault(chave, {})
    p.setdefault("feitos", [])
    p.setdefault("ultimo", {})
    p.setdefault("lgpd", [])
    return p


def conta(f: Finding) -> bool:
    """Entra no checklist: brecha de verdade, aberta (nao info, nao aceita)."""
    return f.severidade is not Severidade.INFO and f.status is Status.ABERTO


def marcado(estado: dict, chave: str, fp: str) -> bool:
    return fp in _projeto(estado, chave)["feitos"]


def alternar(estado: dict, chave: str, fp: str) -> bool:
    feitos = _projeto(estado, chave)["feitos"]
    if fp in feitos:
        feitos.remove(fp)
        return False
    feitos.append(fp)
    return True


def resolvidos(estado: dict, chave: str, findings: list[Finding]) -> list[str]:
    """Titulos das brechas do scan anterior que sumiram neste."""
    anterior = _projeto(estado, chave)["ultimo"]
    atuais = {fingerprint(f) for f in findings if conta(f)}
    return [titulo for fp, titulo in anterior.items() if fp not in atuais]


def registrar_scan(estado: dict, chave: str, findings: list[Finding]) -> None:
    p = _projeto(estado, chave)
    p["ultimo"] = {fingerprint(f): f.titulo for f in findings if conta(f)}
    p["feitos"] = [fp for fp in p["feitos"] if fp in p["ultimo"]]  # resolvido limpa a marca
    p["quando"] = dt.datetime.now().isoformat(timespec="seconds")


def progresso(estado: dict, chave: str, findings: list[Finding]) -> tuple[int, int]:
    alvos = [fingerprint(f) for f in findings if conta(f)]
    feitos = set(_projeto(estado, chave)["feitos"])
    return sum(1 for fp in alvos if fp in feitos), len(alvos)


def filtrar(findings: list[Finding], filtro: str = "todas") -> list[Finding]:
    vis = [f for f in findings if f.status is not Status.IGNORADO]
    if filtro == "info":
        vis = [f for f in vis if f.severidade is Severidade.INFO]
    elif filtro != "todas":
        vis = [f for f in vis if any(l.value == filtro for l in f.lentes)]
    return sorted(vis, key=lambda f: _ORDEM[f.severidade])


def lgpd_marcado(estado: dict, chave: str, i: int) -> bool:
    return i in _projeto(estado, chave)["lgpd"]


def alternar_lgpd(estado: dict, chave: str, i: int) -> bool:
    lista = _projeto(estado, chave)["lgpd"]
    if i in lista:
        lista.remove(i)
        return False
    lista.append(i)
    return True


def salvar_ultimo(findings: list[Finding], caminho: str = ULTIMO) -> None:
    """Mesmo formato da CLI: deixa o 'python cli.py aceitar ID' funcionar depois da GUI."""
    os.makedirs(os.path.dirname(caminho) or ".", exist_ok=True)
    dados = {
        "gerado_em": dt.datetime.now().isoformat(timespec="seconds"),
        "findings": [{"id": f.id, "fingerprint": fingerprint(f), "titulo": f.titulo,
                      "severidade": f.severidade.value} for f in findings],
    }
    with open(caminho, "w", encoding="utf-8") as fp:
        json.dump(dados, fp, ensure_ascii=False, indent=1)
