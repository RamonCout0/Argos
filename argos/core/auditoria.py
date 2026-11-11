"""
Argos — registro de auditoria encadeado (v1.1, transparência).

Cada execução (scan, nativo, trafego, auditar, check) grava uma linha em
~/.argos/auditoria.jsonl com: quando, o que, contra qual alvo, o resultado da
verificação de dono e o veredito. Cada linha carrega o hash da anterior —
a mesma ideia de uma corrente de blocos ou do histórico do git:

  - editou uma linha?            o hash dela não bate mais
  - apagou uma do meio?          a seguinte aponta pra um "anterior" que sumiu
  - trocou a ordem?              a sequência e os elos quebram

Limite honesto: apagar o FINAL da corrente (ou reescrever ela inteira) não
deixa marca por dentro. Por isso existe a ÂNCORA: `auditoria --ancora` mostra
o hash atual; guarde em outro lugar (um commit, uma nota, um e-mail pra você
mesmo). Depois, `auditoria --conferir <hash>` prova que o histórico até ali
continua intacto.

Isto não pega quem modificou o Argos — pega adulteração do TEU histórico, e
te dá prova do que você testou e com que autorização.
O registro fica só na tua máquina e guarda contagens, não os achados.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from typing import Optional

from .. import __version__
from ..identidade import id_execucao

GENESE = "0" * 64


def caminho_padrao() -> str:
    return os.environ.get("ARGOS_AUDITORIA") or os.path.join(
        os.path.expanduser("~"), ".argos", "auditoria.jsonl")


def _canonico(dados: dict) -> str:
    return json.dumps(dados, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(dados: dict) -> str:
    return hashlib.sha256(_canonico(dados).encode("utf-8")).hexdigest()


def _linhas(caminho: str) -> list[str]:
    if not os.path.exists(caminho):
        return []
    with open(caminho, encoding="utf-8") as fp:
        return [l for l in fp.read().splitlines() if l.strip()]


def ler(caminho: Optional[str] = None) -> list[dict]:
    saida = []
    for linha in _linhas(caminho or caminho_padrao()):
        try:
            saida.append(json.loads(linha))
        except json.JSONDecodeError:
            saida.append({"_invalida": linha})
    return saida


def registrar(evento: dict, caminho: Optional[str] = None) -> dict:
    caminho = caminho or caminho_padrao()
    os.makedirs(os.path.dirname(caminho) or ".", exist_ok=True)
    entradas = ler(caminho)
    validas = [e for e in entradas if "hash" in e]
    corpo = {
        "seq": len(entradas) + 1,
        "momento": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "versao": __version__,
        "execucao": id_execucao(),
        **evento,
        "anterior": validas[-1]["hash"] if validas else GENESE,
    }
    corpo["hash"] = _hash(corpo)
    with open(caminho, "a", encoding="utf-8") as fp:
        fp.write(_canonico(corpo) + "\n")
    return corpo


def verificar(caminho: Optional[str] = None) -> tuple[bool, int, list[str]]:
    """(corrente_integra, total_de_entradas, problemas)."""
    problemas: list[str] = []
    anterior = GENESE
    entradas = ler(caminho)
    for i, e in enumerate(entradas, start=1):
        if "_invalida" in e:
            problemas.append(f"linha {i}: nao e JSON valido (foi editada a mao?)")
            anterior = None
            continue
        if e.get("seq") != i:
            problemas.append(f"linha {i}: sequencia {e.get('seq')} fora de ordem (linha apagada ou movida?)")
        if anterior is not None and e.get("anterior") != anterior:
            problemas.append(f"linha {i}: elo quebrado com a linha anterior (algo foi apagado ou trocado)")
        sem_hash = {k: v for k, v in e.items() if k != "hash"}
        if e.get("hash") != _hash(sem_hash):
            problemas.append(f"linha {i}: conteudo alterado (o hash nao confere)")
        anterior = e.get("hash")
    return (not problemas, len(entradas), problemas)


def ancora(caminho: Optional[str] = None) -> Optional[str]:
    validas = [e for e in ler(caminho) if "hash" in e]
    return validas[-1]["hash"] if validas else None


def contem(hash_ancora: str, caminho: Optional[str] = None) -> bool:
    return any(e.get("hash") == hash_ancora.strip() for e in ler(caminho))
