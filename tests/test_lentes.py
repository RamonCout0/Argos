import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.schema import Finding, Severidade, Lente  # noqa: E402
from argos.lenses.mapa import lentes_de, enriquecer  # noqa: E402
from argos.report.console import render  # noqa: E402


def _f(sev, cat, lentes=None, id="X"):
    return Finding(id=id, titulo=id, severidade=sev, categoria=cat,
                   origem="t", local="a.py:1", lentes=lentes or [])


def test_segredo_critico_vira_critico_e_lgpd():
    assert lentes_de(_f(Severidade.CRITICO, "CWE-798")) == [Lente.CRITICO, Lente.LGPD]


def test_brute_force_medio_vira_so_bot():
    assert lentes_de(_f(Severidade.MEDIO, "CWE-307")) == [Lente.BOT]


def test_md5_medio_vira_lgpd():
    assert lentes_de(_f(Severidade.MEDIO, "CWE-327")) == [Lente.LGPD]


def test_injection_alto_vira_critico():
    assert lentes_de(_f(Severidade.ALTO, "CWE-78")) == [Lente.CRITICO]


def test_critico_do_adapter_e_recalculado_pela_severidade():
    # adapter marcou CRITICO num achado medio: a lente cai
    assert lentes_de(_f(Severidade.MEDIO, "CWE-1", lentes=[Lente.CRITICO])) == []


def test_lgpd_do_adapter_e_mantida():
    assert lentes_de(_f(Severidade.BAIXO, "CWE-1", lentes=[Lente.LGPD])) == [Lente.LGPD]


def test_categoria_em_minusculo_tambem_casa():
    assert Lente.LGPD in lentes_de(_f(Severidade.BAIXO, "cwe-532"))


# --- relatorio por lente ---

def _amostra():
    return enriquecer([
        _f(Severidade.CRITICO, "CWE-798", id="SEGREDO"),
        _f(Severidade.MEDIO, "CWE-307", id="BRUTEFORCE"),
    ])


def test_visao_lgpd_mostra_checklist_e_esconde_bot():
    txt = render(_amostra(), lente=Lente.LGPD)
    assert "checklist manual LGPD" in txt
    assert "SEGREDO" in txt
    assert "BRUTEFORCE" not in txt


def test_visao_filtrada_nao_muda_o_selo():
    # o segredo critico bloqueia mesmo olhando so a lente BOT
    txt = render(_amostra(), lente=Lente.BOT)
    assert "BLOQUEADO" in txt
    assert "SEGREDO" not in txt


def test_visao_geral_nao_mostra_checklist():
    assert "checklist manual LGPD" not in render(_amostra())
