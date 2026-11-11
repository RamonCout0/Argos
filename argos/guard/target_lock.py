"""
Argos — a trava de alvo (o cofre).

Argos nasce preso ao ambiente de desenvolvimento. Todo scanner passa o
alvo por aqui ANTES de rodar. Se o alvo não resolver para um endereço
local (loopback) ou de rede privada, Argos recusa e nem liga a ferramenta.

Isso não é uma trava inquebrável — sendo open-source, dá pra forkar e
remover. O objetivo é deixar explícito e honesto que Argos é ferramenta
de dev, não arma contra terceiros. A validação olha o IP RESOLVIDO, não
só o texto do host, pra não cair em truque de apontar um domínio público.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class AlvoNaoLocal(Exception):
    """Levantado quando o alvo resolve para um endereço público."""


def _extrair_host(alvo: str) -> str:
    alvo = alvo.strip()
    if "://" in alvo:
        host = urlparse(alvo).hostname or ""
    elif alvo.count(":") == 1:
        host = alvo.rsplit(":", 1)[0]  # host:porta
    else:
        host = alvo
    if not host:
        raise AlvoNaoLocal(f"Nao consegui extrair um host de: {alvo!r}")
    return host


def _ip_e_local(ip) -> bool:
    return ip.is_loopback or ip.is_private or ip.is_link_local


def validar_alvo(alvo: str) -> list[str]:
    """
    Resolve o alvo e garante que TODO IP é local/privado.
    Retorna a lista de IPs resolvidos (úteis pro scanner).
    Levanta AlvoNaoLocal se qualquer IP for público.
    """
    host = _extrair_host(alvo)

    # host já é um IP literal?
    try:
        ip = ipaddress.ip_address(host)
        if not _ip_e_local(ip):
            raise AlvoNaoLocal(f"{host} e um IP publico. Argos so roda em dev/local.")
        return [str(ip)]
    except ValueError:
        pass  # não é IP literal — resolve por DNS

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise AlvoNaoLocal(f"Nao consegui resolver {host!r}: {e}") from e

    ips = sorted({info[4][0] for info in infos})
    for bruto in ips:
        ip = ipaddress.ip_address(bruto)
        if not _ip_e_local(ip):
            raise AlvoNaoLocal(
                f"{host} resolve para {bruto}, que e publico. Argos so roda em dev/local."
            )
    return ips


def alvo_e_local(alvo: str) -> bool:
    """Versão booleana, sem exceção."""
    try:
        validar_alvo(alvo)
        return True
    except AlvoNaoLocal:
        return False


def autorizar_alvo(alvo: str, segredo=None, *, buscar=None) -> tuple[str, str]:
    """
    A porta de entrada de qualquer scanner que olha um alvo.
      - alvo local/privado  -> liberado, sem token;
      - alvo publico        -> so com verificacao de dono (token HMAC da semana).
    Devolve ("local", ips) ou ("verificado", host).
    Levanta AlvoNaoLocal (sem segredo / host invalido) ou AlvoNaoVerificado.
    """
    from .verificacao import verificar_dono  # import local evita ciclo

    try:
        return ("local", ", ".join(validar_alvo(alvo)))
    except AlvoNaoLocal:
        pass  # publico (ou nao resolvido): so passa provando que e dono
    return ("verificado", verificar_dono(alvo, segredo, buscar=buscar))
