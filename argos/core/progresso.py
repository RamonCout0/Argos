"""
Argos — progresso ao vivo e cancelamento.

Quem roda uma varredura abre uma `Sessao` na thread de trabalho. Dali pra baixo,
qualquer scanner pode:
  - avisar("GET /.env -> 404")   -> vira uma linha no log da interface
  - checar()                     -> se o usuário cancelou, para aqui (levanta Cancelado)
  - rodar(cmd)                   -> igual subprocess.run, mas o programa externo
                                    (semgrep, nmap, tshark...) é morto ao cancelar

Sem sessão aberta (CLI, testes) tudo vira no-op e rodar() é só subprocess.run.
"""
from __future__ import annotations

import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Optional

MAX_LINHAS = 600


class Cancelado(BaseException):
    """BaseException (como o Ctrl+C) pra não ser engolida pelos `except Exception` dos scanners."""


class Sessao:
    def __init__(self) -> None:
        self.inicio = time.monotonic()
        self.linhas: list[dict] = []
        self.descartadas = 0
        self.cancelado = threading.Event()
        self._trava = threading.Lock()
        self._procs: set = set()

    def avisar(self, msg: str, tipo: str = "info") -> None:
        with self._trava:
            self.linhas.append({"t": round(time.monotonic() - self.inicio, 1), "msg": str(msg)[:300], "tipo": tipo})
            if len(self.linhas) > MAX_LINHAS:  # log longo: guarda o fim
                corte = len(self.linhas) - MAX_LINHAS
                del self.linhas[:corte]
                self.descartadas += corte

    def desde(self, n: int) -> tuple[list[dict], int]:
        """Linhas a partir da posição absoluta n; devolve (linhas, nova posição)."""
        with self._trava:
            total = self.descartadas + len(self.linhas)
            ini = max(0, int(n or 0) - self.descartadas)
            return list(self.linhas[ini:]), total

    def cancelar(self) -> None:
        if self.cancelado.is_set():
            return
        self.cancelado.set()
        self.avisar("cancelando: parando o que estiver rodando…", "aviso")
        with self._trava:
            procs = list(self._procs)
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass

    def _registrar(self, p) -> None:
        with self._trava:
            self._procs.add(p)

    def _soltar(self, p) -> None:
        with self._trava:
            self._procs.discard(p)


_local = threading.local()


def atual() -> Optional[Sessao]:
    return getattr(_local, "sessao", None)


@contextmanager
def sessao(s: Sessao):
    anterior = atual()
    _local.sessao = s
    try:
        yield s
    finally:
        _local.sessao = anterior


def avisar(msg: str, tipo: str = "info") -> None:
    s = atual()
    if s is not None:
        s.avisar(msg, tipo)


def checar() -> None:
    s = atual()
    if s is not None and s.cancelado.is_set():
        raise Cancelado()


def rodar(cmd: list[str], timeout: Optional[float] = None, **kw) -> subprocess.CompletedProcess:
    """subprocess.run(capture_output, texto UTF-8) que obedece ao cancelamento."""
    kw.setdefault("encoding", "utf-8")
    kw.setdefault("errors", "replace")
    s = atual()
    if s is None:
        return subprocess.run(cmd, capture_output=True, timeout=timeout, **kw)
    checar()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    s._registrar(p)
    try:
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            raise
    finally:
        s._soltar(p)
    if s.cancelado.is_set():
        raise Cancelado()
    return subprocess.CompletedProcess(cmd, p.returncode, out, err)


def esperar(fn, *args, **kw):
    """Roda fn numa thread auxiliar e espera, olhando o cancelamento a cada 0,2 s.
    Pra chamadas que bloqueiam (ex.: uma resposta do Ollama): ao cancelar, a tela
    não fica presa esperando; a resposta atrasada é simplesmente descartada."""
    s = atual()
    if s is None:
        return fn(*args, **kw)
    checar()
    caixa: dict = {}

    def alvo():
        try:
            caixa["ok"] = fn(*args, **kw)
        except BaseException as e:  # noqa: BLE001 - devolvido pra thread de trabalho
            caixa["erro"] = e

    t = threading.Thread(target=alvo, daemon=True)
    t.start()
    while t.is_alive():
        t.join(0.2)
        if s.cancelado.is_set():
            raise Cancelado()
    if "erro" in caixa:
        raise caixa["erro"]
    return caixa["ok"]
