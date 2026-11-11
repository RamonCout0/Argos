"""
Argos — deduplicação (Fase 3).

Quando dois scanners pisam no mesmo calo (ex.: gitleaks e semgrep acham o
mesmo segredo, ou bandit e semgrep acham o mesmo `eval`), o relatório não
pode contar duas vezes — senão o score cai em dobro por uma brecha só.

Chave de igualdade: (arquivo normalizado, linha, categoria CWE).
  - o caminho é normalizado pra absoluto + caixa do SO, então
    "exemplos/x.py" e "C:\\...\\exemplos\\x.py" viram a mesma coisa;
  - ao fundir, fica o finding MAIS GRAVE como principal, as origens se
    juntam ("bandit+semgrep"), as lentes se somam, e um fix
    DETERMINÍSTICO tem preferência sobre um de IA.
"""
from __future__ import annotations

import os
import re

from ..schema import Finding, Severidade, FixTipo

_SEV = {
    Severidade.CRITICO: 0,
    Severidade.ALTO: 1,
    Severidade.MEDIO: 2,
    Severidade.BAIXO: 3,
    Severidade.INFO: 4,
}

_LOCAL_COM_LINHA = re.compile(r"^(.*):(\d+)$")


def chave(f: Finding) -> tuple:
    m = _LOCAL_COM_LINHA.match(f.local)
    cat = f.categoria.upper().strip()
    if m:
        caminho = os.path.normcase(os.path.abspath(m.group(1)))
        return (caminho, m.group(2), cat)
    return (f.local.strip().lower(), None, cat)


def _fundir(principal: Finding, outro: Finding) -> Finding:
    origens = set(principal.origem.split("+")) | set(outro.origem.split("+"))
    principal.origem = "+".join(sorted(origens))
    principal.lentes = list(dict.fromkeys(principal.lentes + outro.lentes))
    if outro.fix is not None and (
        principal.fix is None
        or (principal.fix.tipo is FixTipo.IA and outro.fix.tipo is FixTipo.DETERMINISTICO)
    ):
        principal.fix = outro.fix
    if not principal.evidencia and outro.evidencia:
        principal.evidencia = outro.evidencia
    return principal


def deduplicar(findings: list[Finding]) -> list[Finding]:
    """Funde findings iguais. Mantém a ordem da primeira aparição."""
    grupos: dict[tuple, Finding] = {}
    ordem: list[tuple] = []
    for f in findings:
        k = chave(f)
        if k not in grupos:
            grupos[k] = f
            ordem.append(k)
            continue
        existente = grupos[k]
        if _SEV[f.severidade] < _SEV[existente.severidade]:
            grupos[k] = _fundir(f, existente)
        else:
            grupos[k] = _fundir(existente, f)
    return [grupos[k] for k in ordem]
