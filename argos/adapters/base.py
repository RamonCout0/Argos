"""
Argos — o contrato do adapter.

Esta é a peça que faz "um MCP por scanner" virar realidade. Todo scanner
— gitleaks, trivy, semgrep, nmap, tshark... — implementa esta mesma
interface. O orquestrador não sabe nada de ferramenta específica: ele só
conhece `Adapter` e `Finding`.

Adicionar uma ferramenta nova = escrever um adapter e registrá-lo. O
núcleo não muda.
"""
from __future__ import annotations

import os
import shutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..schema import Finding


def achar_executavel(nome: str) -> Optional[str]:
    """Caminho de uma ferramenta: primeiro no PATH, depois ao lado do Python atual.

    Ferramentas instaladas via pip (pip-audit, semgrep, bandit) ficam na pasta
    de scripts do venv. Se o Argos roda com o Python do venv mas sem o venv
    ativado, essa pasta não está no PATH e o `shutil.which` sozinho não acha.
    """
    achado = shutil.which(nome)
    if achado:
        return achado
    pasta = Path(sys.executable).parent  # venv/bin (Linux) ou venv\Scripts (Windows)
    return shutil.which(nome, path=os.fspath(pasta))


def caminho_relativo(arquivo: str, raiz: Optional[str]) -> str:
    """Caminho curto, relativo à pasta auditada (com '/').
    (C:/Users/.../tevejo/src/x.py -> src/x.py; fora da pasta, fica como está.)"""
    if raiz and arquivo and os.path.isabs(arquivo):
        try:
            rel = os.path.relpath(arquivo, raiz)
            if not rel.startswith(".."):
                return rel.replace("\\", "/")
        except ValueError:  # outro disco no Windows
            pass
    return arquivo or "?"


@dataclass
class Contexto:
    """O que um scanner recebe pra trabalhar."""

    projeto: str                      # caminho da pasta do projeto a escanear
    alvo: Optional[str] = None        # host/url p/ scanners dinamicos (ja validado pela trava)
    opcoes: dict = field(default_factory=dict)  # Fase 5: portas, processo, interface, pcap...


class Adapter(ABC):
    """Molde de todo scanner do Argos."""

    nome: str = "adapter"

    @abstractmethod
    def disponivel(self) -> bool:
        """A ferramenta externa está instalada e pronta?"""

    @abstractmethod
    def escanear(self, ctx: Contexto) -> list[Finding]:
        """Roda o scanner e devolve findings normalizados."""

    def como_instalar(self) -> str:
        """Dica de instalação, mostrada quando a ferramenta não está disponível."""
        return ""
