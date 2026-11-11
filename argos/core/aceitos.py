"""
Argos — riscos aceitos (Fase 6).

Sem isso, um falso positivo trava o deploy pra sempre. Com isso mal feito,
vira o tapete onde se esconde brecha de verdade. Por isso as regras:

  - todo aceite tem MOTIVO (mínimo de 10 caracteres) e PRAZO (1 a 90 dias);
  - venceu o prazo, o achado volta a contar sozinho e o relatório avisa;
  - aceito não some: sai do score, mas aparece na seção "riscos aceitos";
  - o arquivo argos-aceitos.json é texto simples, feito pra ir pro git e
    ser revisado como qualquer outro código.

A identidade de um achado ("fingerprint") é categoria + local, com caminho
relativo à pasta do Argos — os IDs tipo CODE-S001 mudam a cada execução.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from typing import Optional

from ..schema import Finding, Status

ARQUIVO = "argos-aceitos.json"
MAX_DIAS = 90
MIN_MOTIVO = 10

_LOCAL_COM_LINHA = re.compile(r"^(.*):(\d+)$")


class AceiteInvalido(ValueError):
    pass


def fingerprint(f: Finding) -> str:
    m = _LOCAL_COM_LINHA.match(f.local)
    if m:
        caminho = m.group(1)
        try:
            caminho = os.path.relpath(os.path.abspath(caminho))
        except ValueError:  # outro drive no Windows
            pass
        local = caminho.replace("\\", "/") + ":" + m.group(2)
    else:
        local = f.local.strip().lower()
    return f"{f.categoria.upper().strip()}|{local}"


def carregar(caminho: str = ARQUIVO) -> list[dict]:
    if not os.path.exists(caminho):
        return []
    with open(caminho, encoding="utf-8") as fp:
        dados = json.load(fp)
    return dados.get("aceitos", []) if isinstance(dados, dict) else []


def salvar(aceitos: list[dict], caminho: str = ARQUIVO) -> None:
    with open(caminho, "w", encoding="utf-8") as fp:
        json.dump({"aceitos": aceitos}, fp, ensure_ascii=False, indent=2)
        fp.write("\n")


def aceitar(fp: str, motivo: str, dias: int, *, hoje: Optional[dt.date] = None,
            caminho: str = ARQUIVO, titulo: str = "") -> dict:
    motivo = (motivo or "").strip()
    if len(motivo) < MIN_MOTIVO:
        raise AceiteInvalido(f"motivo curto demais: explique em pelo menos {MIN_MOTIVO} caracteres.")
    if not 1 <= dias <= MAX_DIAS:
        raise AceiteInvalido(f"prazo deve ser de 1 a {MAX_DIAS} dias (depois, revise de novo).")
    hoje = hoje or dt.date.today()
    novo = {
        "fingerprint": fp,
        "titulo": titulo,
        "motivo": motivo,
        "aceito_em": hoje.isoformat(),
        "ate": (hoje + dt.timedelta(days=dias)).isoformat(),
    }
    lista = [a for a in carregar(caminho) if a.get("fingerprint") != fp] + [novo]
    salvar(lista, caminho)
    return novo


def aplicar(findings: list[Finding], *, hoje: Optional[dt.date] = None,
            caminho: str = ARQUIVO) -> list[str]:
    """Marca como IGNORADO o que tem aceite válido. Devolve avisos de aceites vencidos."""
    hoje = hoje or dt.date.today()
    mapa = {a.get("fingerprint"): a for a in carregar(caminho)}
    avisos: list[str] = []
    for f in findings:
        a = mapa.get(fingerprint(f))
        if not a:
            continue
        try:
            ate = dt.date.fromisoformat(a.get("ate", ""))
        except ValueError:
            avisos.append(f"aceite com data invalida ignorado: {fingerprint(f)}")
            continue
        if ate >= hoje:
            f.status = Status.IGNORADO
            f.justificativa = f"{a.get('motivo', '')} (aceito ate {ate.isoformat()})"
        else:
            avisos.append(f"aceite VENCIDO em {ate.isoformat()} - voltou a contar: [{f.id}] {f.titulo}")
    return avisos
