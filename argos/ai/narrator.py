"""
Argos — o narrador (Fase 4).

A IA é a VOZ do relatório, não o cérebro:
  - ela só escreve nos campos de texto `explicacao` e `sugestao_ia`;
  - severidade, status, fix e score continuam vindo do scanner + matemática;
  - só narra o que precisa de explicação (fix do tipo IA). Fix determinístico
    ("sobe pra versão X") já vem certo do advisory e não passa por ela;
  - parte da explicação base da CWE e recebe o trecho com segredos mascarados;
  - guarda as respostas em cache, pra não perguntar a mesma coisa toda vez.

Sem Ollama, todo achado ainda recebe a explicação base (fonte "template").
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

from ..core import progresso
from ..schema import Finding, FixTipo, Severidade
from .contexto import trecho_de
from .templates import explicacao_base

SISTEMA = (
    "Voce e um revisor de seguranca ajudando um desenvolvedor iniciante. "
    "Responda em portugues do Brasil, curto e direto. "
    "Use SOMENTE os dados fornecidos: nao invente arquivos, versoes, bibliotecas nem CVEs. "
    "A severidade ja foi decidida pelo scanner: nao comente nem altere. "
    'Responda apenas JSON no formato {"explicacao": "...", "correcao": "..."}. '
    "explicacao: ate 3 frases sobre o risco NESTE trecho. "
    "correcao: o ajuste concreto, com um trecho curto de codigo se ajudar."
)

LIMITE_TEXTO = 700
_ORDEM = {Severidade.CRITICO: 0, Severidade.ALTO: 1, Severidade.MEDIO: 2,
          Severidade.BAIXO: 3, Severidade.INFO: 4}


@dataclass
class Estatisticas:
    candidatos: int = 0
    gerados: int = 0
    do_cache: int = 0
    falhas: int = 0


def precisa_da_ia(f: Finding) -> bool:
    if f.severidade is Severidade.INFO:  # inventario/"ok" nao e brecha
        return False
    return f.fix is None or f.fix.tipo is FixTipo.IA


def montar_prompt(f: Finding, trecho: str) -> str:
    risco, caminho = explicacao_base(f.categoria)
    return (
        f"Achado: {f.titulo}\n"
        f"Categoria: {f.categoria}\n"
        f"Local: {f.local}\n"
        f"Detectado por: {f.origem}\n"
        f"Explicacao base da categoria: {risco} Correcao usual: {caminho}\n"
        f"Trecho do codigo (segredos mascarados):\n{trecho or '(trecho indisponivel)'}\n"
    )


def _limpar(resposta: dict) -> tuple[str, str]:
    if not isinstance(resposta, dict):
        return "", ""
    exp = resposta.get("explicacao")
    cor = resposta.get("correcao")
    exp = exp.strip()[:LIMITE_TEXTO] if isinstance(exp, str) else ""
    cor = cor.strip()[:LIMITE_TEXTO] if isinstance(cor, str) else ""
    return exp, cor


def _chave_cache(modelo: str, f: Finding, trecho: str) -> str:
    base = f"{modelo}|{f.categoria}|{f.titulo}|{trecho}"
    return hashlib.sha256(base.encode()).hexdigest()


def _ler_cache(caminho: Optional[str]) -> dict:
    if not caminho or not os.path.exists(caminho):
        return {}
    try:
        with open(caminho, encoding="utf-8") as fp:
            return json.load(fp)
    except (OSError, json.JSONDecodeError):
        return {}


def _gravar_cache(caminho: Optional[str], dados: dict) -> None:
    if not caminho:
        return
    os.makedirs(os.path.dirname(caminho) or ".", exist_ok=True)
    with open(caminho, "w", encoding="utf-8") as fp:
        json.dump(dados, fp, ensure_ascii=False, indent=1)


def aplicar_templates(findings: list[Finding]) -> None:
    for f in findings:
        if not f.explicacao and f.severidade is not Severidade.INFO:
            risco, _ = explicacao_base(f.categoria)
            f.explicacao = risco
            f.fonte_explicacao = "template"


def narrar(
    findings: list[Finding],
    cliente=None,
    *,
    maximo: int = 10,
    cache: Optional[str] = os.path.join(".argos_cache", "ia.json"),
    raiz: str = ".",
) -> Estatisticas:
    """Preenche explicacao/sugestao. `cliente` None = so templates."""
    aplicar_templates(findings)
    est = Estatisticas()
    if cliente is None:
        return est

    alvos = sorted((f for f in findings if precisa_da_ia(f)), key=lambda f: _ORDEM[f.severidade])
    alvos = alvos[:maximo]
    est.candidatos = len(alvos)
    memoria = _ler_cache(cache)
    modelo = getattr(cliente, "modelo", "?")

    for i, f in enumerate(alvos, start=1):
        progresso.checar()
        progresso.avisar(f"IA ({modelo}): explicando {f.id} ({i}/{len(alvos)})", "ia")
        trecho = trecho_de(f, raiz=raiz)
        chave = _chave_cache(modelo, f, trecho)
        if chave in memoria:
            exp, cor = memoria[chave]["explicacao"], memoria[chave]["correcao"]
            est.do_cache += 1
        else:
            try:
                exp, cor = _limpar(progresso.esperar(cliente.gerar_json, SISTEMA, montar_prompt(f, trecho)))
            except Exception:
                est.falhas += 1
                continue
            if not exp:
                est.falhas += 1
                continue
            memoria[chave] = {"explicacao": exp, "correcao": cor}
            est.gerados += 1
        f.explicacao, f.sugestao_ia, f.fonte_explicacao = exp, cor, "ia"

    _gravar_cache(cache, memoria)
    return est
