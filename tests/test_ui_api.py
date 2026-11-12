import json
import os
import sys
import time

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argos.schema import Finding, Severidade  # noqa: E402
from argos.core.orchestrator import Resultado  # noqa: E402
from argos.ui import api as mod_api  # noqa: E402
from argos.ui.api import ApiArgos, humor  # noqa: E402


def _f(id, sev=Severidade.ALTO):
    return Finding(id=id, titulo=f"t {id}", severidade=sev, categoria="CWE-78", origem="x",
                   local=f"a/{id}.py:1")


def _esperar(api, limite=10):
    for _ in range(limite * 20):
        s = api.status()
        if not s.get("ocupado") and ("dados" in s or "erro" in s):
            return s
        time.sleep(0.05)
    raise AssertionError("a varredura nao terminou")


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return ApiArgos(arquivo_estado=str(tmp_path / "checklist.json"))


def test_humor_do_olho():
    assert humor([_f("a", Severidade.CRITICO)]) == "alerta"
    assert humor([_f("a", Severidade.MEDIO)]) == "ressalva"
    assert humor([_f("a", Severidade.INFO)]) == "ok"
    assert humor([]) == "ok"


def test_inicio_e_serializavel(api):
    ini = api.inicio()
    json.dumps(ini)
    assert ini["auditoria"] is None and len(ini["lgpd"]) == 7


def test_validacoes_da_auditoria(api, tmp_path):
    assert "erro" in api.auditar({})
    assert "erro" in api.auditar({"portas": "80, abc"})
    assert "erro" in api.auditar({"pasta": str(tmp_path / "nao_existe")})


def test_auditoria_completa_pela_ponte(api, tmp_path, monkeypatch):
    monkeypatch.setattr(mod_api.orq, "auditar",
                        lambda p, n, t, w=None: Resultado(findings=[_f("A"), _f("B", Severidade.MEDIO)], rodaram=["x"]))
    assert api.auditar({"pasta": str(tmp_path)}) == {"ok": True}
    s = _esperar(api)
    d = s["dados"]
    json.dumps(d)
    assert d["humor"] == "alerta" and d["placar"]["total"] == 2
    assert [f["sev"] for f in d["findings"]] == ["alto", "medio"]
    assert d["findings"][0]["explicacao"]  # explicacao base aplicada

    fp = d["findings"][0]["fp"]
    r = api.alternar("auditoria", fp)
    assert r == {"feito": True, "feitos": 1, "total": 2}
    assert api.alternar_lgpd(0) == {"feito": True}
    assert api.inicio()["auditoria"]["placar"]["feitos"] == 1


def test_auditoria_com_urls_vai_pra_trilha_web(api, monkeypatch):
    visto = {}

    def falso(p, n, t, w=None):
        visto["web"] = w
        return Resultado()
    monkeypatch.setattr(mod_api.orq, "auditar", falso)
    assert "erro" in api.auditar({"urls": "127.0.0.1:8000"})          # sem http://
    assert "erro" in api.auditar({"urls": "ftp://127.0.0.1"})
    assert api.auditar({"urls": "http://127.0.0.1:8000/, http://127.0.0.1:4200"}) == {"ok": True}
    _esperar(api)
    assert visto["web"] == {"urls": ["http://127.0.0.1:8000", "http://127.0.0.1:4200"]}


def test_nao_deixa_duas_varreduras_ao_mesmo_tempo(api, tmp_path, monkeypatch):
    def demorado(*a):
        time.sleep(0.4)
        return Resultado()
    monkeypatch.setattr(mod_api.orq, "auditar", demorado)
    assert api.auditar({"pasta": str(tmp_path)}) == {"ok": True}
    assert "erro" in api.auditar({"pasta": str(tmp_path)})
    _esperar(api)


def test_erro_do_scanner_vira_mensagem(api, tmp_path, monkeypatch):
    def quebra(*a):
        raise RuntimeError("deu ruim")
    monkeypatch.setattr(mod_api.orq, "auditar", quebra)
    api.auditar({"pasta": str(tmp_path)})
    assert _esperar(api)["erro"] == "deu ruim"


def test_teste_de_ia_pela_ponte(api):
    from test_prompt_injection import FakeOllama
    falso = FakeOllama("vulneravel")
    try:
        os.environ["OLLAMA_URL"] = falso.url
        assert "erro" in api.testar_ia({"modo": "ollama", "sistema": "  "})
        assert api.testar_ia({"modo": "ollama", "modelo": "teste:1b", "sistema": "Você é a Lumi."}) == {"ok": True}
        d = _esperar(api, 20)["dados"]
        assert d["humor"] == "alerta"
        assert any("LLM07" in f["titulo"] for f in d["findings"])
    finally:
        os.environ.pop("OLLAMA_URL", None)
        falso.fechar()


def test_http_exige_url(api):
    assert "erro" in api.testar_ia({"modo": "http", "url": ""})


def test_aceitar_valida(api):
    assert "erro" in api.aceitar("X|y", "t", "curto", 10)
    assert "erro" in api.aceitar("X|y", "t", "motivo bem explicado", "abc")
    assert api.aceitar("X|y", "t", "motivo bem explicado", "15")["ok"] is True


def test_exemplos_de_prompt_e_canario(api):
    assert "Lumi" in api.exemplo_prompt("fraco")
    assert "Regras" in api.exemplo_prompt("reforcado")
    assert api.exemplo_prompt("../../etc/passwd") == ""
    assert api.gerar_canario().startswith("ARGOS-CANARIO-")


def test_metodos_internos_nao_vazam_pro_javascript():
    publicos = [m for m in dir(ApiArgos) if not m.startswith("_")]
    assert all(not m.startswith("_") for m in publicos)
    assert "_executar" not in publicos and "_dialogo" not in publicos


def test_tela_nao_usa_innerhtml_com_dados():
    js = open(os.path.join(RAIZ, "argos", "ui", "web", "app.js"), encoding="utf-8").read()
    for linha in js.splitlines():
        if linha.strip().startswith(("*", "/*", "//")):
            continue
        if "innerHTML" in linha:
            assert "ICONES" in linha, f"innerHTML com algo que nao e icone fixo: {linha.strip()}"
