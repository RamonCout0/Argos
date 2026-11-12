"""Log ao vivo e cancelamento (v2.1)."""
import os
import sys
import time

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from argos.core import progresso  # noqa: E402
from argos.core.orchestrator import Resultado, _rodar  # noqa: E402
from argos.adapters.base import Adapter, Contexto  # noqa: E402
from argos.ui import api as mod_api  # noqa: E402
from argos.ui.api import ApiArgos  # noqa: E402


def _esperar(api, limite=15):
    for _ in range(limite * 20):
        s = api.status()
        if not s.get("ocupado") and ("dados" in s or "erro" in s or "cancelado" in s):
            return s
        time.sleep(0.05)
    raise AssertionError("nao terminou")


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return ApiArgos(arquivo_estado=str(tmp_path / "checklist.json"))


def test_sem_sessao_tudo_e_no_op():
    progresso.avisar("ninguem ouve")
    progresso.checar()
    r = progresso.rodar([sys.executable, "-c", "print('oi')"])
    assert r.returncode == 0 and r.stdout.strip() == "oi"


def test_log_incremental_e_corte():
    s = progresso.Sessao()
    for i in range(5):
        s.avisar(f"linha {i}")
    linhas, pos = s.desde(0)
    assert [l["msg"] for l in linhas][-1] == "linha 4" and pos == 5
    s.avisar("nova")
    linhas, pos = s.desde(pos)
    assert [l["msg"] for l in linhas] == ["nova"] and pos == 6
    for i in range(progresso.MAX_LINHAS + 50):
        s.avisar("x")
    linhas, pos = s.desde(0)
    assert len(linhas) == progresso.MAX_LINHAS and pos == 6 + progresso.MAX_LINHAS + 50


def test_orquestrador_narra_cada_scanner():
    class Bom(Adapter):
        nome = "bom"
        def disponivel(self): return True
        def escanear(self, ctx): return []

    class Ausente(Bom):
        nome = "ausente"
        def disponivel(self): return False
        def como_instalar(self): return "x"

    s = progresso.Sessao()
    with progresso.sessao(s):
        _rodar([Bom(), Ausente()], Contexto(projeto="."))
    msgs = [l["msg"] for l in s.desde(0)[0]]
    assert "bom: começando…" in msgs
    assert any(m.startswith("bom: 0 achado(s)") for m in msgs)
    assert any("ausente" in m and "não instalado" in m for m in msgs)


def test_cancelar_mata_o_processo_externo():
    s = progresso.Sessao()
    t0 = time.monotonic()
    import threading
    threading.Timer(0.4, s.cancelar).start()
    with progresso.sessao(s), pytest.raises(progresso.Cancelado):
        progresso.rodar([sys.executable, "-c", "import time; time.sleep(30)"])
    assert time.monotonic() - t0 < 5


def test_cancelado_nao_e_engolido_pelos_scanners():
    assert not issubclass(progresso.Cancelado, Exception)


def test_cancelar_pela_ponte(api, tmp_path, monkeypatch):
    def demorado(*a, **k):
        progresso.avisar("trabalhando…")
        for _ in range(200):
            time.sleep(0.05)
            progresso.checar()
        return Resultado()
    monkeypatch.setattr(mod_api.orq, "auditar", demorado)
    assert "erro" in api.cancelar()  # nada rodando
    assert api.auditar({"pasta": str(tmp_path)}) == {"ok": True}
    time.sleep(0.2)
    s = api.status(0)
    assert s["ocupado"] == "auditoria" and any(l["msg"] == "trabalhando…" for l in s["log"])
    assert api.cancelar() == {"ok": True}
    fim = _esperar(api)
    assert fim.get("cancelado") is True
    assert any("cancelado" in l["msg"] for l in api.status(0)["log"])
    assert api.inicio()["auditoria"] is None  # resultado antigo (nenhum) preservado


def test_esperar_solta_a_tela_ao_cancelar():
    s = progresso.Sessao()
    import threading
    threading.Timer(0.3, s.cancelar).start()
    t0 = time.monotonic()
    with progresso.sessao(s), pytest.raises(progresso.Cancelado):
        progresso.esperar(time.sleep, 20)  # "a IA demorando"
    assert time.monotonic() - t0 < 3
