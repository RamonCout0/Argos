"""
Argos — o mapa das lentes (Fase 3).

As lentes não são decididas pelo scanner "no chute": elas saem de regras
fixas e auditáveis, aplicadas a todos os findings depois do scan.

  - CRITICO: o que te derruba primeiro = severidade crítica ou alta.
  - LGPD:    a categoria (CWE) é de dado pessoal exposto/mal protegido.
  - BOT:     a categoria (CWE) é de abuso automatizado (brute force, sem limite).

Um adapter pode marcar LGPD/BOT por conta própria (ele conhece o contexto);
isso é mantido. A lente CRITICO, porém, é sempre recalculada pela
severidade — senão ela vira "tudo" e perde o sentido.
"""
from __future__ import annotations

from ..schema import Finding, Lente, Severidade

# Dado pessoal exposto ou mal protegido (LGPD art. 46: medidas de segurança).
CWE_LGPD = {
    "CWE-798",  # credencial hardcoded
    "CWE-259",  # senha hardcoded
    "CWE-319",  # transmissao em texto claro (HTTP puro)
    "CWE-312",  # armazenamento em texto claro
    "CWE-311",  # falta de criptografia
    "CWE-532",  # dado sensivel em log
    "CWE-359",  # exposicao de informacao pessoal privada
    "CWE-200",  # exposicao de informacao sensivel
    "CWE-327",  # criptografia fraca (ex.: md5 pra senha)
    "CWE-916",  # hash de senha fraco
}

# Abuso automatizado / bots.
CWE_BOT = {
    "CWE-307",  # tentativas de login sem limite (brute force)
    "CWE-770",  # recurso sem limite
    "CWE-799",  # frequencia de interacao sem controle
    "CWE-400",  # consumo de recurso descontrolado
    "CWE-804",  # captcha adivinhavel
}

_ORDEM = [Lente.CRITICO, Lente.LGPD, Lente.BOT]


def lentes_de(f: Finding) -> list[Lente]:
    lentes = set(f.lentes) - {Lente.CRITICO}
    if f.severidade in (Severidade.CRITICO, Severidade.ALTO):
        lentes.add(Lente.CRITICO)
    cat = f.categoria.upper().strip()
    if cat in CWE_LGPD:
        lentes.add(Lente.LGPD)
    if cat in CWE_BOT:
        lentes.add(Lente.BOT)
    return [l for l in _ORDEM if l in lentes]


def enriquecer(findings: list[Finding]) -> list[Finding]:
    """Recalcula as lentes de cada finding (in place) e devolve a lista."""
    for f in findings:
        f.lentes = lentes_de(f)
    return findings
