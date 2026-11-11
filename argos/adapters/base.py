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

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ..schema import Finding


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
