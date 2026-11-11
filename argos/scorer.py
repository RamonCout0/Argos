"""
Argos — o placar e o selo.

Regra de ouro: o número é MATEMÁTICA sobre os findings reais, nunca a
opinião da IA. Mesma entrada = mesmo resultado, sempre.

Duas coisas SEPARADAS:
  - score: a barra motivacional (0-100). Cai conforme os findings abertos.
  - selo "ok pra prod": booleano frio. Só libera se não houver nenhum
    crítico OU alto aberto. Um score alto NUNCA libera deploy sozinho.
"""
from __future__ import annotations

from dataclasses import dataclass

from .schema import Finding, Severidade, Status

SEVERIDADES_BLOQUEANTES = {Severidade.CRITICO, Severidade.ALTO}

# Ordem de gravidade. O limite do selo pode ficar MAIS rigoroso (medio, baixo),
# nunca mais frouxo que o padrao (alto): critico e alto sempre bloqueiam.
_GRAVIDADE = [Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO, Severidade.BAIXO]
LIMITE_PADRAO = Severidade.ALTO


class LimiteInvalido(ValueError):
    pass


def bloqueantes_para(limite: Severidade) -> set[Severidade]:
    if limite not in _GRAVIDADE or _GRAVIDADE.index(limite) < _GRAVIDADE.index(LIMITE_PADRAO):
        raise LimiteInvalido(
            f"limite '{limite.value}' invalido: o selo pode ficar mais rigoroso "
            "(medio, baixo), nunca mais frouxo que 'alto'."
        )
    return set(_GRAVIDADE[: _GRAVIDADE.index(limite) + 1])


@dataclass
class Placar:
    score: int
    aprovado: bool          # o selo "ok pra prod"
    abertos: int
    por_severidade: dict    # {"critico": 2, "alto": 1, ...} (só abertos)
    por_lente: dict         # {"lgpd": 3, ...} (só abertos)
    bloqueantes: list       # findings abertos que barram o deploy
    riscos_aceitos: list    # findings IGNORADO (com justificativa)
    limite: Severidade = LIMITE_PADRAO

    @property
    def motivo_reprovacao(self) -> str:
        if self.aprovado:
            return ""
        n = len(self.bloqueantes)
        return f"{n} brecha(s) de nivel '{self.limite.value}' ou mais grave aberta(s) bloqueiam o deploy."


def calcular(findings: list[Finding], limite: Severidade = LIMITE_PADRAO) -> Placar:
    abertos = [f for f in findings if f.status is Status.ABERTO]
    ignorados = [f for f in findings if f.status is Status.IGNORADO]

    perda = sum(f.peso for f in abertos)
    score = max(0, min(100, 100 - perda))

    barram = bloqueantes_para(limite)
    bloqueantes = [f for f in abertos if f.severidade in barram]
    aprovado = len(bloqueantes) == 0

    por_severidade: dict = {}
    for f in abertos:
        chave = f.severidade.value
        por_severidade[chave] = por_severidade.get(chave, 0) + 1

    por_lente: dict = {}
    for f in abertos:
        for l in f.lentes:
            por_lente[l.value] = por_lente.get(l.value, 0) + 1

    return Placar(
        score=score,
        aprovado=aprovado,
        abertos=len(abertos),
        por_severidade=por_severidade,
        por_lente=por_lente,
        bloqueantes=bloqueantes,
        riscos_aceitos=ignorados,
        limite=limite,
    )
