from argos import mapa
from argos.schema import Finding, Severidade, Fix, FixTipo, Status


def _f(local, sev=Severidade.ALTO, st=Status.ABERTO, just=""):
    return Finding(id="X", titulo="t", severidade=sev, categoria="CWE-89", origem="s",
                   local=local, fix=Fix(FixTipo.IA, "f"), status=st, justificativa=just)


def test_area_de_varios_formatos():
    assert mapa.area_de("portal/api/busca.py:42") == "portal/api"
    assert mapa.area_de("http://127.0.0.1:8000/conteudos/1?x=2") == "/conteudos/1"
    assert mapa.area_de("settings · security.W021") == "settings"
    assert mapa.area_de("porta 8000") == "porta 8000"
    assert mapa.area_de("manage.py:1") == "manage.py"


def test_agrupa_e_ordena_por_peso():
    fs = [_f("portal/api/a.py:1", Severidade.CRITICO), _f("portal/api/b.py:2"),
          _f("portal/views.py:3", Severidade.MEDIO)]
    m = mapa.construir(fs)
    assert m[0]["area"] == "portal/api" and m[0]["total"] == 2
    assert m[0]["max_sev"] == "critico"
    assert [a["area"] for a in m] == ["portal/api", "portal/views.py"]


def test_aceito_fica_de_fora():
    fs = [_f("a/b.py:1", Severidade.ALTO, Status.IGNORADO, "aceito"), _f("c/d.py:1")]
    m = mapa.construir(fs)
    assert [a["area"] for a in m] == ["c/d.py"]


def test_limite():
    fs = [_f(f"p{i}/x.py:1") for i in range(20)]
    assert len(mapa.construir(fs, limite=5)) == 5
