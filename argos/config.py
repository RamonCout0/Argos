"""
Argos — configuração.

O segredo de verificação vem da variável de ambiente ARGOS_SECRET ou, se ela
não existir, de um arquivo .env na pasta de onde o Argos é rodado.
O .env já está no .gitignore: o segredo nunca vai pro repositório.
"""
from __future__ import annotations

import os
from typing import Optional


def _ler_env(caminho: str) -> dict[str, str]:
    valores: dict[str, str] = {}
    try:
        with open(caminho, encoding="utf-8") as fp:
            for linha in fp:
                linha = linha.strip()
                if not linha or linha.startswith("#") or "=" not in linha:
                    continue
                chave, valor = linha.split("=", 1)
                valores[chave.strip()] = valor.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return valores


def carregar(chave: str, padrao: Optional[str] = None, pasta: str = ".") -> Optional[str]:
    """Variavel de ambiente tem prioridade; senao, .env; senao, o padrao."""
    return os.environ.get(chave) or _ler_env(os.path.join(pasta, ".env")).get(chave) or padrao


def carregar_segredo(pasta: str = ".") -> Optional[str]:
    return carregar("ARGOS_SECRET", None, pasta)
