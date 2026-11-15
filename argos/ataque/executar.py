"""Argos — porta de entrada do modo ataque: trava primeiro, laboratório depois."""
from __future__ import annotations

import os

from ..adapters.base import Adapter, Contexto
from ..adapters.django_deploy import python_do_projeto, achar_manage
from ..core import progresso
from ..guard.ativo import confirmar_dono, AtaqueRecusado
from ..schema import Finding
from .ataques import Ataque
from .laboratorio import Laboratorio, LabFalhou


def raiz_do_repositorio(pasta: str) -> str:
    """Sobe a partir da pasta até achar o .git (projeto Django + Angular costuma ter o
    backend numa subpasta e o .git na raiz)."""
    atual = os.path.abspath(pasta)
    while True:
        if os.path.isdir(os.path.join(atual, ".git")):
            return atual
        pai = os.path.dirname(atual)
        if pai == atual:
            return os.path.abspath(pasta)  # sem .git: a trava recusa com a mensagem certa
        atual = pai


def atacar(projeto: str, carga_max: int = 512, sem_carga: bool = False, buscar_dono=None) -> list[Finding]:
    pasta = os.path.abspath(projeto)
    repo = raiz_do_repositorio(pasta)
    dono = confirmar_dono(repo, buscar_dono)  # 1ª trava: repositório onde você é admin
    progresso.avisar(f"trava: GitHub confirmou que você administra {dono}", "ok")
    manage = achar_manage(pasta, profundidade=4)
    if not manage:
        raise AtaqueRecusado("não achei o manage.py nessa pasta nem nas subpastas: o modo ataque, por "
                             "enquanto, é pra projeto Django (o Angular não precisa subir: o ataque vai "
                             "direto no backend, como faria um atacante de verdade)")
    backend = os.path.dirname(manage)
    if os.path.relpath(backend, repo).startswith(".."):
        raise AtaqueRecusado("o manage.py está fora do repositório verificado")
    if backend != pasta:
        progresso.avisar(f"ataque: backend Django em {os.path.relpath(backend, pasta)}", "info")
    python = python_do_projeto(repo, backend)
    # 2ª trava: o próprio Argos sobe o app em 127.0.0.1 e só ataca esse processo
    with Laboratorio(backend, python, repo=repo) as lab:
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
