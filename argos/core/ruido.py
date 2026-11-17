"""
Argos — filtro de ruído (v2.3).

Lição do primeiro teste real (Gatuno de Estrelas): a maior parte dos alarmes
falsos não vinha de regra ruim, mas de ONDE o scanner olhou:

  - código GERADO (build do Angular, minificado, collectstatic): é cópia do
    fonte que já é escaneado. Achado ali é repetido e impossível de corrigir
    no lugar -> sai do relatório (o log conta quantos);
  - arquivos de TESTE: senha inventada de teste não é vazamento, e padrão
    "perigoso" proposital em teste não é brecha. Segredo em teste vira INFO;
    o resto fica no máximo BAIXO, com "(arquivo de teste)" no título.

Achados da trilha web/nativa (URL, porta) não passam por aqui.
"""
from __future__ import annotations

import fnmatch
import os
import re

from ..schema import Finding, Severidade

# pastas que o Argos NUNCA deve escanear, nem quando ele se audita a si mesmo:
# o proprio cache de respostas da IA (pode conter trecho de codigo do alvo).
_SEMPRE_IGNORAR = (".argos_cache",)
_ARGOSIGNORE = ".argosignore"


def ler_argosignore(raiz: str | None) -> list[str]:
    """Padroes do arquivo .argosignore na raiz do projeto (estilo .gitignore,
    simples: nome de pasta, caminho ou glob; '#' comenta). Sempre inclui o cache."""
    padroes = list(_SEMPRE_IGNORAR)
    if not raiz:
        return padroes
    caminho = os.path.join(raiz, _ARGOSIGNORE)
    try:
        with open(caminho, encoding="utf-8") as fp:
            for linha in fp:
                linha = linha.split("#", 1)[0].strip().replace("\\", "/").rstrip("/")
                if linha:
                    padroes.append(linha)
    except OSError:
        pass
    return padroes


def deve_ignorar(caminho: str, padroes: list[str]) -> bool:
    """True se o caminho (relativo, com '/') casa com algum padrao do .argosignore."""
    caminho = caminho.replace("\\", "/").strip("/")
    segmentos = caminho.split("/")
    for p in padroes:
        if not p:
            continue
        # nome de pasta/arquivo solto casa em qualquer nivel (ex.: "exemplos", "*.pcap")
        if "/" not in p and any(fnmatch.fnmatch(s, p) for s in segmentos):
            return True
        # caminho/prefixo a partir da raiz (ex.: "exemplos/projeto_vulneravel")
        if fnmatch.fnmatch(caminho, p) or fnmatch.fnmatch(caminho, p + "/*"):
            return True
    return False


def cortar_ignorados(findings: list[Finding], raiz: str | None) -> tuple[list[Finding], int]:
    """Remove achados em caminhos listados no .argosignore (e no cache do Argos).
    Devolve (achados que ficam, quantos sairam). URL/porta nunca saem por aqui."""
    padroes = ler_argosignore(raiz)
    ficam, cortados = [], 0
    for f in findings:
        caminho = _caminho(f)
        if caminho is not None and deve_ignorar(caminho, padroes):
            cortados += 1
            continue
        ficam.append(f)
    return ficam, cortados

# pastas de saída de build e cópias geradas
_PASTAS_GERADAS = {"frontend_build", "dist", "build", "staticfiles", ".angular", "node_modules",
                   "coverage", "htmlcov", ".next", ".nuxt", "out", "__pycache__", "site-packages",
                   "venv", ".venv", "env", ".tox", "bower_components"}
_ARQ_GERADO = re.compile(r"(\.min\.(js|css)|\.bundle\.js|\.map|[-.]chunk[-.][\w-]*\.js|"
                         r"(^|/)(main|polyfills|runtime|vendor|styles)[-.][0-9a-f]{8,}\.(js|css))$", re.I)

_PASTAS_TESTE = {"tests", "test", "__tests__", "spec", "specs", "testing", "fixtures", "e2e", "cypress"}
_ARQ_TESTE = re.compile(r"(^|/)(tests?\.py|test_[^/]*\.py|[^/]*_tests?\.py|conftest\.py|"
                        r"[^/]*\.(spec|test|e2e-spec)\.[jt]sx?|[^/]*\.http)$", re.I)

# categorias de segredo: em arquivo de teste, é senha de mentira
_SEGREDO = {"CWE-798", "CWE-259", "CWE-521", "CWE-547", "CWE-321"}


def _caminho(f: Finding) -> str | None:
    """Parte de arquivo do `local` (sem :linha e sem ':pacote'); None se for URL/porta."""
    local = (f.local or "").strip()
    if "://" in local or local.startswith(("porta ", " ·")) or not local:
        return None
    caminho = re.sub(r":[^/\\]*$", "", local) if ":" in local[2:] else local
    return caminho.replace("\\", "/")


def gerado(caminho: str) -> bool:
    partes = [p.lower() for p in caminho.split("/")]
    return any(p in _PASTAS_GERADAS for p in partes[:-1]) or bool(_ARQ_GERADO.search(caminho))


def de_teste(caminho: str) -> bool:
    partes = [p.lower() for p in caminho.split("/")]
    return any(p in _PASTAS_TESTE for p in partes[:-1]) or bool(_ARQ_TESTE.search(caminho))


def filtrar(findings: list[Finding]) -> tuple[list[Finding], int, int]:
    """Devolve (achados que ficam, quantos sumiram por serem gerados, quantos foram rebaixados)."""
    ficam, gerados, rebaixados = [], 0, 0
    for f in findings:
        caminho = _caminho(f)
        if caminho is None:
            ficam.append(f)
            continue
        if gerado(caminho):
            gerados += 1
            continue
        if de_teste(caminho) and f.severidade is not Severidade.INFO:
            novo = Severidade.INFO if (f.categoria in _SEGREDO or f.origem == "gitleaks") else Severidade.BAIXO
            if _peso(novo) > _peso(f.severidade):
                f.severidade = novo
                rebaixados += 1
            if "(arquivo de teste)" not in f.titulo:
                f.titulo += " (arquivo de teste)"
        ficam.append(f)
    return ficam, gerados, rebaixados


_ORDEM = [Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO, Severidade.BAIXO, Severidade.INFO]


def _peso(s: Severidade) -> int:
    return _ORDEM.index(s)
