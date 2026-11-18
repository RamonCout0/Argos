"""
Argos — mapa de falhas (Fase D+): onde, no app, concentra mais brecha.

Agrupa os achados por ÁREA (derivada do `local`: pasta do arquivo, rota da URL
ou grupo de config) e devolve, por área, quantas falhas e quão graves. A UI
desenha isso como um mapa de calor — bate o olho e vê qual parte do sistema
está mais exposta. Serve pro scan e pro modo ataque.
"""
from __future__ import annotations

import re

from .schema import Finding, Severidade, Status

_PESO = {Severidade.CRITICO: 40, Severidade.ALTO: 20, Severidade.MEDIO: 10,
         Severidade.BAIXO: 3, Severidade.INFO: 0}
_ORDEM = ["critico", "alto", "medio", "baixo", "info"]
_LINHA = re.compile(r":\d+$")


def area_de(local: str) -> str:
    """Nome curto da parte do app a que o achado pertence."""
    loc = (local or "").strip()
    if not loc:
        return "(sem local)"
    if "://" in loc:                                   # URL: usa o caminho, sem query
        caminho = re.sub(r"^\w+://[^/]+", "", loc).split("?")[0].strip("/")
        return "/" + (caminho or "")
    if loc.startswith("porta "):                       # trilha nativa
        return loc.split("?")[0]
    if " · " in loc or " ·" in loc:                    # config/check (ex.: "settings · W021")
        return loc.split("·")[0].strip()
    caminho = _LINHA.sub("", loc).replace("\\", "/")   # arquivo:linha -> pasta
    partes = [p for p in caminho.split("/") if p]
    if len(partes) <= 1:
        return partes[0] if partes else loc
    return "/".join(partes[:2])                        # ex.: portal/api


def construir(findings: list[Finding], limite: int = 12) -> list[dict]:
    """Lista de áreas com contagem/gravidade, da mais exposta pra menos."""
    areas: dict[str, dict] = {}
    for f in findings:
        if f.status is Status.IGNORADO:                # risco aceito não entra no mapa
            continue
        nome = area_de(f.local)
        a = areas.setdefault(nome, {"area": nome, "total": 0, "peso": 0,
                                    "por_sev": {s: 0 for s in _ORDEM}, "exemplos": []})
        a["total"] += 1
        a["peso"] += _PESO.get(f.severidade, 0)
        a["por_sev"][f.severidade.value] += 1
        loc = f.local or ""
        if loc and loc not in a["exemplos"] and len(a["exemplos"]) < 4:
            a["exemplos"].append(loc)
    for a in areas.values():
        a["max_sev"] = next((s for s in _ORDEM if a["por_sev"][s] > 0), "info")
    ordenadas = sorted(areas.values(), key=lambda a: (a["peso"], a["total"]), reverse=True)
    return ordenadas[:limite]
