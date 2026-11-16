"""
Argos — o trecho de código que vai pro modelo, com segredos mascarados.

Mesmo com o Ollama rodando local, o modelo não precisa ver a chave pra
explicar que ela não deveria estar ali. Princípio do menor privilégio
também vale pra IA.
"""
from __future__ import annotations

import os
import re

from ..schema import Finding

_LOCAL_COM_LINHA = re.compile(r"^(.*):(\d+)$")
_STRING_LONGA = re.compile(r"""(["'])([A-Za-z0-9_\-/+=.~]{12,})\1""")
_CREDENCIAL_EM_URL = re.compile(r"(://)[^/\s:@]+:[^/\s@]+@")
_TOKENS_CONHECIDOS = re.compile(r"\b(ghp_|gho_|github_pat_|AKIA|xox[abp]-|sk_live_|sk-)[A-Za-z0-9_\-]{8,}")
# valor logo depois de um rótulo de credencial, com ou sem aspas (ex.: .http, .env, headers):
#   Authorization: Token 93b7...   api_key=abc123...   "senha": "xyz..."
_ROTULO = re.compile(r"(?i)\b(authorization|bearer|token|api[_-]?key|apikey|secret|client[_-]?secret|"
                     r"password|passwd|senha|access[_-]?key|private[_-]?key)\b(\s*[:=]\s*|\s+)"
                     r"(?:(?:token|bearer|basic)\s+)?([\"']?)([^\s\"',;]{6,})\3", )
# token solto com cara de segredo: 20+ caracteres, letras E pelo menos 3 dígitos, sem barra (não é caminho/URL)
_TOKEN_SOLTO = re.compile(r"(?<![\w\-+=.~/])(?=[\w\-+=.~]*[A-Za-z])(?=(?:[\w\-+=.~]*\d){3})"
                          r"[\w\-+=.~]{20,}(?![\w\-+=.~/])")


def mascarar(texto: str) -> str:
    linhas = []
    for linha in (texto or "").splitlines():
        if "PRIVATE KEY" in linha:
            linhas.append(re.sub(r"-----.*", "[chave privada mascarada]", linha))
            continue
        linha = _CREDENCIAL_EM_URL.sub(r"\1***:***@", linha)
        linha = _TOKENS_CONHECIDOS.sub("***", linha)
        linha = _ROTULO.sub(lambda m: m.group(0)[: m.start(4) - m.start(0)] + "***" + m.group(3), linha)
        linha = _STRING_LONGA.sub(lambda m: f"{m.group(1)}***{m.group(1)}", linha)
        linha = _TOKEN_SOLTO.sub("***", linha)
        linhas.append(linha)
    return "\n".join(linhas)


def trecho_de(f: Finding, raio: int = 3, raiz: str = ".") -> str:
    """Linhas ao redor do achado, numeradas e mascaradas. '' se não der pra ler."""
    m = _LOCAL_COM_LINHA.match(f.local)
    if not m:
        return ""
    caminho, linha = m.group(1), int(m.group(2))
    if not os.path.exists(caminho):
        caminho = os.path.join(raiz, caminho)
    try:
        with open(caminho, encoding="utf-8", errors="replace") as fp:
            todas = fp.read().splitlines()
    except OSError:
        return ""
    ini, fim = max(1, linha - raio), min(len(todas), linha + raio)
    bloco = "\n".join(
        f"{'>' if n == linha else ' '}{n:4d} | {todas[n - 1]}" for n in range(ini, fim + 1)
    )
    return mascarar(bloco)
