"""
Argos — schema central.

Tudo no Argos gira em torno de uma única estrutura: o Finding.
Cada scanner (gitleaks, trivy, semgrep, nmap, tshark...) traduz a própria
saída para um Finding. O resto do sistema — score, lentes, relatório, IA —
só conhece o Finding, nunca o formato cru de cada ferramenta.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severidade(Enum):
    CRITICO = "critico"
    ALTO = "alto"
    MEDIO = "medio"
    BAIXO = "baixo"
    INFO = "info"

    @property
    def peso(self) -> int:
        """Pontos que este finding tira do score enquanto está aberto."""
        return _PESOS[self]


_PESOS = {
    Severidade.CRITICO: 40,
    Severidade.ALTO: 20,
    Severidade.MEDIO: 10,
    Severidade.BAIXO: 3,
    Severidade.INFO: 0,
}


class Lente(Enum):
    """As três visões do relatório. Um finding pode estar em mais de uma."""

    CRITICO = "critico"  # o que te derruba primeiro
    LGPD = "lgpd"        # pegada técnica de dado pessoal exposto
    BOT = "bot"          # proteção contra bots / abuso


class Status(Enum):
    ABERTO = "aberto"
    CORRIGIDO = "corrigido"
    IGNORADO = "ignorado"  # falso positivo / risco aceito (exige justificativa)


class FixTipo(Enum):
    DETERMINISTICO = "deterministico"  # resposta exata (ex: CVE -> versão). Não passa pela IA.
    IA = "ia"                          # precisa de explicação. O Ollama veste.


@dataclass
class Fix:
    tipo: FixTipo
    descricao: str
    patch: Optional[str] = None

    def to_dict(self) -> dict:
        return {"tipo": self.tipo.value, "descricao": self.descricao, "patch": self.patch}


@dataclass
class Finding:
    id: str            # ex: "SECRET-001"
    titulo: str
    severidade: Severidade
    categoria: str     # CWE/OWASP, ex: "CWE-798"
    origem: str        # qual scanner achou, ex: "gitleaks"
    local: str         # arquivo:linha | host:porta | endpoint
    evidencia: str = ""                              # trecho real que o scanner cuspiu
    lentes: list[Lente] = field(default_factory=list)
    fix: Optional[Fix] = None
    verificacao: str = ""                            # como re-checar que sumiu
    status: Status = Status.ABERTO
    justificativa: str = ""                          # obrigatória quando IGNORADO
    # Fase 4 — a voz. Campos SO de texto: a IA nunca toca severidade/status/fix.
    explicacao: str = ""                             # por que isso importa
    sugestao_ia: str = ""                            # ajuste sugerido pelo modelo (conferir!)
    fonte_explicacao: str = ""                       # "template" | "ia"

    def __post_init__(self):
        if self.status is Status.IGNORADO and not self.justificativa.strip():
            raise ValueError(
                f"Finding {self.id} está IGNORADO sem justificativa. "
                "Risco aceito tem que ser explícito."
            )

    @property
    def peso(self) -> int:
        return self.severidade.peso

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "titulo": self.titulo,
            "severidade": self.severidade.value,
            "categoria": self.categoria,
            "origem": self.origem,
            "local": self.local,
            "evidencia": self.evidencia,
            "lentes": [l.value for l in self.lentes],
            "fix": self.fix.to_dict() if self.fix else None,
            "verificacao": self.verificacao,
            "status": self.status.value,
            "justificativa": self.justificativa,
            "explicacao": self.explicacao,
            "sugestao_ia": self.sugestao_ia,
            "fonte_explicacao": self.fonte_explicacao,
        }
