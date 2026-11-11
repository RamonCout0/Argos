"""
Argos — identidade (v1.1, transparência).

O Argos oficial se apresenta em toda requisição que faz pra fora:
  User-Agent: Argos/<versão> (+<url do projeto>; ...)
  X-Argos-Execucao: <id desta execução>

Quem administra o site vê nos logs QUEM está testando e pode bloquear.
O id da execução é o mesmo gravado no registro de auditoria local, então
uma requisição vista no log do site pode ser casada com a linha exata do
registro de quem rodou ("mostra a entrada com esse id").

Uma cópia modificada pode tirar isso — mas aí ela deixa de se passar pelo
Argos oficial, e o nome do projeto não fica associado ao tráfego dela.
"""
from __future__ import annotations

import secrets

from . import __version__

# Troque pela URL do repositorio oficial assim que ele existir.
PROJETO_URL = "https://github.com/SEU-USUARIO/argos"

_execucao: dict = {"id": None}


def iniciar_execucao() -> str:
    _execucao["id"] = secrets.token_hex(6)
    return _execucao["id"]


def id_execucao() -> str:
    return _execucao["id"] or iniciar_execucao()


def user_agent() -> str:
    return f"Argos/{__version__} (+{PROJETO_URL}; auditoria do proprio projeto)"


def cabecalhos() -> dict:
    return {"User-Agent": user_agent(), "X-Argos-Execucao": id_execucao()}
