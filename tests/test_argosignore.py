import os
from argos.core import ruido
from argos.schema import Finding, Severidade, Fix, FixTipo


def _f(local, cat="CWE-798", sev=Severidade.ALTO):
    return Finding(id="X", titulo="t", severidade=sev, categoria=cat, origem="gitleaks",
                   local=local, fix=Fix(FixTipo.IA, "f", "p"))


def test_cache_do_argos_sempre_sai(tmp_path):
    fs = [_f(".argos_cache/ia.json:4"), _f("portal/views.py:10")]
    ficam, cortados = ruido.cortar_ignorados(fs, str(tmp_path))
    assert cortados == 1 and [f.local for f in ficam] == ["portal/views.py:10"]


def test_argosignore_pasta_e_glob(tmp_path):
    (tmp_path / ".argosignore").write_text("exemplos/\n*.pcap\n", encoding="utf-8")
    fs = [_f("exemplos/projeto_vulneravel/app.py:1"),
          _f("capturas/amostra.pcap"),
          _f("src/real.py:2")]
    ficam, cortados = ruido.cortar_ignorados(fs, str(tmp_path))
    assert cortados == 2 and [f.local for f in ficam] == ["src/real.py:2"]


def test_comentario_e_linha_vazia_ignorados(tmp_path):
    (tmp_path / ".argosignore").write_text("# so comentario\n\n  \n", encoding="utf-8")
    fs = [_f("src/a.py:1")]
    ficam, cortados = ruido.cortar_ignorados(fs, str(tmp_path))
    assert cortados == 0 and len(ficam) == 1


def test_url_e_porta_nunca_saem(tmp_path):
    (tmp_path / ".argosignore").write_text("exemplos/\n", encoding="utf-8")
    fs = [_f("https://exemplos/x", cat="CWE-319"), _f("porta 8000")]
    ficam, cortados = ruido.cortar_ignorados(fs, str(tmp_path))
    assert cortados == 0 and len(ficam) == 2
