import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.schema import Finding, Severidade, Status, Lente  # noqa: E402
from argos.scorer import calcular  # noqa: E402


def _f(id, sev, status=Status.ABERTO, lentes=None, justificativa=""):
    return Finding(
        id=id, titulo=id, severidade=sev, categoria="X",
        origem="teste", local="x", lentes=lentes or [],
        status=status, justificativa=justificativa,
    )


def test_score_cheio_sem_findings():
    p = calcular([])
    assert p.score == 100
    assert p.aprovado is True


def test_pesos_descontam():
    p = calcular([_f("a", Severidade.CRITICO), _f("b", Severidade.MEDIO)])
    assert p.score == 100 - 40 - 10


def test_score_nao_fica_negativo():
    p = calcular([_f(str(i), Severidade.CRITICO) for i in range(5)])
    assert p.score == 0


def test_selo_bloqueia_com_alto_aberto():
    p = calcular([_f("a", Severidade.ALTO)])
    assert p.aprovado is False
    assert len(p.bloqueantes) == 1


def test_selo_passa_so_com_medios_e_baixos():
    p = calcular([_f("a", Severidade.MEDIO), _f("b", Severidade.BAIXO)])
    assert p.aprovado is True
    assert p.score == 100 - 10 - 3


def test_corrigido_nao_conta():
    p = calcular([_f("a", Severidade.CRITICO, status=Status.CORRIGIDO)])
    assert p.score == 100
    assert p.aprovado is True


def test_ignorado_sai_do_score_mas_vira_risco_aceito():
    p = calcular([_f("a", Severidade.CRITICO, status=Status.IGNORADO,
                     justificativa="falso positivo")])
    assert p.score == 100
    assert p.aprovado is True
    assert len(p.riscos_aceitos) == 1


def test_contagem_por_lente():
    p = calcular([
        _f("a", Severidade.MEDIO, lentes=[Lente.LGPD, Lente.BOT]),
        _f("b", Severidade.BAIXO, lentes=[Lente.LGPD]),
    ])
    assert p.por_lente["lgpd"] == 2
    assert p.por_lente["bot"] == 1
