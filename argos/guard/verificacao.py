"""
Argos — verificação de dono (pra rodar fora do localhost).

Regra: fora de dev/local, o Argos só aceita um alvo se o PRÓPRIO SITE provar
que é seu. Não basta uma variável no teu PC (qualquer um coloca o valor que
quiser lá). A prova vem do servidor:

  1. Você gera um segredo (ARGOS_SECRET) e coloca o MESMO valor em dois
     lugares: no .env do Argos e nas variáveis do Railway.
  2. O site publica em https://SEU-SITE/.well-known/argos-verify.txt um token:
         HMAC-SHA256(segredo, "argos-verify|<host>|<ano>-W<semana>")
  3. Antes de escanear, o Argos baixa esse token e compara com o que ele
     calcula do segredo local. Bateu -> é teu. Não bateu -> bloqueia.

Por que HMAC + semana (e não um hash fixo):
  - o token gira SOZINHO toda semana ISO (UTC). Ninguém troca nada na mão;
  - o token publicado não revela o segredo (HMAC é de mão única);
  - ele é amarrado ao domínio: o token de um site não serve em outro;
  - um token que vazar vale no máximo até o fim da semana seguinte
    (aceitamos também a semana anterior, pra virada de domingo/segunda).

Interruptor de emergência: apagou ARGOS_SECRET no Railway -> o endpoint some
-> o Argos para de aceitar o site na hora.

Honestidade: o Argos é open-source, então alguém pode forkar e tirar isto.
É um guard-rail que exige o consentimento do dono do alvo, não um DRM.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import secrets
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlparse

CAMINHO_VERIFICACAO = "/.well-known/argos-verify.txt"
TAMANHO_MINIMO_SEGREDO = 32


class AlvoNaoVerificado(Exception):
    """O alvo é público e não provou ser do dono do segredo."""


def gerar_segredo() -> str:
    """Segredo forte e aleatório pra colocar no .env e no Railway."""
    return secrets.token_urlsafe(48)


def _semana_iso(data: _dt.date) -> str:
    ano, semana, _ = data.isocalendar()
    return f"{ano}-W{semana:02d}"


def _hoje_utc() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def token_da_semana(segredo: str, host: str, data: Optional[_dt.date] = None) -> str:
    """O token que o site deve publicar nesta semana (UTC)."""
    data = data or _hoje_utc()
    msg = f"argos-verify|{host.lower()}|{_semana_iso(data)}".encode()
    return hmac.new(segredo.encode(), msg, hashlib.sha256).hexdigest()


def tokens_aceitos(segredo: str, host: str, data: Optional[_dt.date] = None) -> list[str]:
    """Semana atual + semana anterior (tolerância na virada)."""
    data = data or _hoje_utc()
    return [
        token_da_semana(segredo, host, data),
        token_da_semana(segredo, host, data - _dt.timedelta(days=7)),
    ]


def _host_de(alvo: str) -> str:
    alvo = alvo.strip()
    if "://" not in alvo:
        alvo = "https://" + alvo
    host = urlparse(alvo).hostname or ""
    if not host:
        raise AlvoNaoVerificado(f"Nao consegui extrair o host de {alvo!r}.")
    return host.lower()


def url_de_verificacao(alvo: str) -> str:
    # sempre HTTPS: em HTTP puro alguem no meio do caminho poderia forjar o token
    return f"https://{_host_de(alvo)}{CAMINHO_VERIFICACAO}"


def _buscar_https(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Argos-verify/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (url sempre https)
        return resp.read(256).decode("utf-8", "replace").strip()


def verificar_dono(
    alvo: str,
    segredo: Optional[str],
    *,
    buscar: Optional[Callable[[str], str]] = None,
    data: Optional[_dt.date] = None,
) -> str:
    """
    Confere se o alvo publica o token certo. Devolve o host verificado.
    Levanta AlvoNaoVerificado com o motivo, se não bater.
    """
    if not segredo:
        raise AlvoNaoVerificado(
            "Alvo publico e ARGOS_SECRET nao configurado. Rode 'python cli.py segredo' "
            "e coloque o mesmo valor no .env e nas variaveis do Railway."
        )
    if len(segredo) < TAMANHO_MINIMO_SEGREDO:
        raise AlvoNaoVerificado(
            f"ARGOS_SECRET curto demais (minimo {TAMANHO_MINIMO_SEGREDO} caracteres). "
            "Gere um com 'python cli.py segredo'."
        )

    host = _host_de(alvo)
    url = url_de_verificacao(alvo)
    buscar = buscar or _buscar_https
    try:
        publicado = buscar(url)
    except Exception as e:
        raise AlvoNaoVerificado(f"Nao consegui ler {url}: {e}") from e

    for esperado in tokens_aceitos(segredo, host, data):
        if hmac.compare_digest(publicado, esperado):  # comparacao em tempo constante
            return host
    raise AlvoNaoVerificado(
        f"O token em {url} nao bate com o teu ARGOS_SECRET. "
        "Confira se o segredo e o mesmo nos dois lugares."
    )
