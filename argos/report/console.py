"""
Argos — relatório no console.

Mostra o score, o selo, a 'boss bar' e os findings ordenados por severidade.
Desde a Fase 3 aceita uma LENTE (critico | lgpd | bot) pra filtrar a visão.

Regra importante: score e selo são SEMPRE do projeto inteiro. A lente só
muda o que aparece na lista — nunca esconde uma brecha da decisão de deploy.
"""
from __future__ import annotations

import json
import textwrap
from typing import Optional

from ..schema import Finding, Severidade, Lente, Status
from ..scorer import Placar, calcular, LIMITE_PADRAO
from ..lenses.lgpd_manual import CHECKLIST_LGPD, AVISO

_ICONE = {
    "critico": "[CRIT]",
    "alto": "[ALTO]",
    "medio": "[MED ]",
    "baixo": "[BAIX]",
    "info": "[INFO]",
}

_ORDEM = {
    Severidade.CRITICO: 0,
    Severidade.ALTO: 1,
    Severidade.MEDIO: 2,
    Severidade.BAIXO: 3,
    Severidade.INFO: 4,
}

_NOME_LENTE = {
    Lente.CRITICO: "CRITICO - o que te derruba primeiro",
    Lente.LGPD: "LGPD - dado pessoal exposto ou mal protegido",
    Lente.BOT: "BOT - abuso automatizado",
}


def _quebrar(texto: str, largura: int = 96) -> list[str]:
    recuo = " " * 9
    saida: list[str] = []
    for paragrafo in texto.splitlines() or [""]:
        saida.extend(textwrap.wrap(paragrafo, largura, initial_indent=recuo,
                                   subsequent_indent=recuo + "  ") or [recuo])
    return saida


def _boss_bar(score: int, largura: int = 20) -> str:
    cheio = round(score / 100 * largura)
    return "[" + "#" * cheio + "-" * (largura - cheio) + f"] {score}/100"


def render(
    findings: list[Finding],
    *,
    json_tambem: bool = False,
    lente: Optional[Lente] = None,
    limite: Severidade = LIMITE_PADRAO,
) -> str:
    placar: Placar = calcular(findings, limite)  # sempre sobre TUDO
    # riscos aceitos saem da lista principal e vao pra secao propria, la embaixo
    visiveis = [f for f in findings
                if f.status is not Status.IGNORADO and (lente is None or lente in f.lentes)]

    linhas: list[str] = []
    linhas.append("=" * 52)
    linhas.append("  ARGOS - relatorio de brechas")
    if lente is not None:
        linhas.append(f"  Visao: {_NOME_LENTE[lente]}")
    linhas.append("=" * 52)
    linhas.append("")
    linhas.append("  HP do deploy: " + _boss_bar(placar.score))
    selo = "OK PRA PROD" if placar.aprovado else "BLOQUEADO"
    linhas.append(f"  Selo: {selo}")
    if not placar.aprovado:
        linhas.append(f"  -> {placar.motivo_reprovacao}")
    if lente is not None:
        linhas.append("  (score e selo contam o projeto inteiro, nao so esta lente)")
    linhas.append("")

    if not findings:
        linhas.append("  Nenhuma brecha encontrada pelos scanners que rodaram.")
        linhas.append("")
    elif not visiveis:
        linhas.append("  Nenhuma brecha nesta lente.")
        linhas.append("")

    if placar.por_severidade:
        resumo = "   ".join(f"{n} {sev}" for sev, n in placar.por_severidade.items())
        linhas.append("  Abertos: " + resumo)
    if lente is None and placar.por_lente:
        por_l = "   ".join(f"{n} {l}" for l, n in placar.por_lente.items())
        linhas.append("  Lentes:  " + por_l + "   (use --lente pra filtrar)")
    if placar.por_severidade or (lente is None and placar.por_lente):
        linhas.append("")

    for f in sorted(visiveis, key=lambda x: _ORDEM[x.severidade]):
        ic = _ICONE.get(f.severidade.value, "[????]")
        marca = "" if f.status.value == "aberto" else f"  ({f.status.value})"
        linhas.append(f"  {ic} [{f.id}] {f.titulo}{marca}")
        linhas.append(f"         onde: {f.local}   cat: {f.categoria}")
        linhas.append(f"         achado por: {f.origem}")
        if f.evidencia:
            linhas.extend(_quebrar(f"evidencia: {f.evidencia}"))
        if f.lentes:
            linhas.append(f"         lentes: {', '.join(l.value for l in f.lentes)}")
        if f.fix:
            linhas.extend(_quebrar(f"fix ({f.fix.tipo.value}): {f.fix.descricao}"))
        if f.explicacao:
            rotulo = "por que importa (IA):" if f.fonte_explicacao == "ia" else "por que importa:"
            linhas.extend(_quebrar(f"{rotulo} {f.explicacao}"))
        if f.sugestao_ia:
            linhas.extend(_quebrar(f"sugestao da IA (confira antes de aplicar): {f.sugestao_ia}"))
        if f.verificacao:
            linhas.append(f"         confirmar: {f.verificacao}")
        linhas.append("")

    if lente is Lente.LGPD:
        linhas.append("  -- checklist manual LGPD (fora do score) --")
        linhas.append(f"  {AVISO}")
        for titulo, texto in CHECKLIST_LGPD:
            linhas.append(f"   [ ] {titulo}: {texto}")
        linhas.append("")

    if placar.riscos_aceitos:
        linhas.append("  -- riscos aceitos (fora do score, mas a vista) --")
        for f in placar.riscos_aceitos:
            ic = _ICONE.get(f.severidade.value, "[????]")
            linhas.append(f"   {ic} [{f.id}] {f.titulo}")
            linhas.extend(_quebrar(f"aceito: {f.justificativa}"))
        linhas.append("")

    linhas.append("=" * 52)
    texto = "\n".join(linhas)

    if json_tambem:
        dump = {
            "score": placar.score,
            "aprovado": placar.aprovado,
            "lente": lente.value if lente else None,
            "findings": [f.to_dict() for f in visiveis],
        }
        texto += "\n\n" + json.dumps(dump, ensure_ascii=False, indent=2)
    return texto
