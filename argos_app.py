"""
Argos — ponto de entrada do executável.

Quando empacotado com PyInstaller (ver argos.spec), vira o Argos.exe: clicar
abre direto a interface, sem terminal e sem precisar de Python instalado.

Os subcomandos de linha de comando (auditar, atacar, web, ci-github, ...)
continuam em cli.py, pra quem roda pelo terminal.
"""
from __future__ import annotations


def main() -> None:
    from argos.ui.janela import main as abrir_interface
    abrir_interface()


if __name__ == "__main__":
    main()
