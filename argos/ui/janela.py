"""
Argos UI — abre a janela nativa (pywebview).

    python cli.py gui            -> interface nova
    python cli.py gui --demo     -> com dados de exemplo
    python cli.py gui --classico -> a interface antiga em Tkinter

Requisitos: pip install pywebview
  - Windows: usa o WebView2 (já vem no Windows 10/11).
  - Linux:   sudo apt install python3-gi gir1.2-webkit2-4.1
"""
from __future__ import annotations

from pathlib import Path

from .api import ApiArgos

WEB = Path(__file__).resolve().parent / "web"


def _tamanho(webview) -> tuple[int, int]:
    """Cabe na tela: notebook 1366x768 ou monitor grande."""
    larg, alt = 1340, 860
    try:
        tela = webview.screens[0]
        larg = min(larg, tela.width - 40)
        alt = min(alt, tela.height - 70)
    except Exception:  # noqa: BLE001 - sem info da tela, fica no padrao
        pass
    return larg, alt


def criar(webview, demo=None):
    api = ApiArgos(demo=demo)
    larg, alt = _tamanho(webview)
    janela = webview.create_window(
        "Argos — o vigia de cem olhos",
        url=str(WEB / "index.html"),
        js_api=api,
        width=larg, height=alt, min_size=(1000, 620),
        background_color="#07090f",
    )
    api._janela = janela
    return janela, api


def main(demo=None) -> None:
    import webview

    criar(webview, demo)
    webview.start()
