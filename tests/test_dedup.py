import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.schema import Finding, Severidade, Lente, Fix, FixTipo  # noqa: E402
from argos.core.dedup import deduplicar  # noqa: E402
from argos.scorer import calcular  # noqa: E402


def _f(id, local, sev=Severidade.MEDIO, cat="CWE-78", origem="semgrep", lentes=None, fix=None):
    return Finding(id=id, titulo=id, severidade=sev, categoria=cat,
                   origem=origem, local=local, lentes=lentes or [], fix=fix)


def test_mesmo_lugar_relativo_e_absoluto_viram_um():
    rel = "proj/views.py:7"
    absoluto = os.path.abspath("proj/views.py") + ":7"
    out = deduplicar([_f("A", rel, origem="bandit"), _f("B", absoluto, origem="semgrep")])
    assert len(out) == 1
    assert out[0].origem == "bandit+semgrep"


def test_fica_o_mais_grave():
    out = deduplicar([
        _f("MEDIO", "a.py:3", sev=Severidade.MEDIO),
        _f("ALTO", "a.py:3", sev=Severidade.ALTO, origem="bandit"),
    ])
    assert len(out) == 1
    assert out[0].severidade is Severidade.ALTO


def test_linhas_diferentes_nao_fundem():
    assert len(deduplicar([_f("A", "a.py:3"), _f("B", "a.py:4")])) == 2


def test_categorias_diferentes_nao_fundem():
    assert len(deduplicar([_f("A", "a.py:3", cat="CWE-78"), _f("B", "a.py:3", cat="CWE-327")])) == 2


def test_fix_deterministico_tem_preferencia():
    ia = Fix(FixTipo.IA, "explica")
    det = Fix(FixTipo.DETERMINISTICO, "sobe pra 2.0", "pkg==2.0")
    out = deduplicar([
        _f("A", "requirements.txt:pkg", cat="CVE-1", fix=ia),
        _f("B", "requirements.txt:pkg", cat="CVE-1", fix=det, origem="trivy"),
    ])
    assert len(out) == 1
    assert out[0].fix.tipo is FixTipo.DETERMINISTICO


def test_lentes_se_somam():
    out = deduplicar([
        _f("A", "a.py:1", lentes=[Lente.CRITICO]),
        _f("B", "a.py:1", lentes=[Lente.LGPD], origem="bandit"),
    ])
    assert out[0].lentes == [Lente.CRITICO, Lente.LGPD]


def test_score_nao_cai_em_dobro_por_brecha_repetida():
    dup = [_f("A", "a.py:1", sev=Severidade.CRITICO, origem="gitleaks"),
           _f("B", "a.py:1", sev=Severidade.CRITICO)]
    assert calcular(dup).score == 20           # sem dedup: conta 2x
    assert calcular(deduplicar(dup)).score == 60  # com dedup: conta 1x


def test_ordem_da_primeira_aparicao_e_mantida():
    out = deduplicar([_f("A", "a.py:1"), _f("B", "b.py:1"), _f("C", "a.py:1")])
    assert [f.id for f in out] == ["A", "B"]
