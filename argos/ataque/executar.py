"""Argos — porta de entrada do modo ataque: trava primeiro, laboratório depois."""
from __future__ import annotations

import os

from ..adapters.base import Adapter, Contexto
from ..adapters.django_deploy import python_do_projeto
from ..core import progresso
from ..guard.ativo import confirmar_dono, AtaqueRecusado
from ..schema import Finding
from .ataques import Ataque
from .laboratorio import Laboratorio, LabFalhou


def atacar(projeto: str, carga_max: int = 512, sem_carga: bool = False, buscar_dono=None) -> list[Finding]:
    raiz = os.path.abspath(projeto)
    dono = confirmar_dono(raiz, buscar_dono)  # 1ª trava: repositório onde você é admin
    progresso.avisar(f"trava: GitHub confirmou que você administra {dono}", "ok")
    if not os.path.isfile(os.path.join(raiz, "manage.py")):
        raise AtaqueRecusado("o modo ataque, por enquanto, é pra projeto Django (manage.py na raiz da pasta)")
    python = python_do_projeto(raiz, raiz)
    # 2ª trava: o próprio Argos sobe o app em 127.0.0.1 e só ataca esse processo
    with Laboratorio(raiz, python) as lab:
        return Ataque(lab, carga_max=carga_max, sem_carga=sem_carga).rodar()


class AtaqueAdapter(Adapter):
    nome = "ataque"

    def disponivel(self) -> bool:
        return True

    def escanear(self, ctx: Contexto) -> list[Finding]:
        try:
            return atacar(ctx.projeto, carga_max=int(ctx.opcoes.get("carga_max") or 512),
                          sem_carga=bool(ctx.opcoes.get("sem_carga")))
        except (AtaqueRecusado, LabFalhou) as e:
            raise RuntimeError(str(e)) from e
