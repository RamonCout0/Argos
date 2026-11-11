import datetime as dt
import json
import os
import sys

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from argos.schema import Finding, Severidade, Status, Lente  # noqa: E402
from argos.scorer import calcular, LimiteInvalido  # noqa: E402
from argos.core import aceitos  # noqa: E402
from argos.core import orchestrator  # noqa: E402
from argos.core.orchestrator import Resultado  # noqa: E402
from argos.report.html import render_html  # noqa: E402
from argos.report.console import render  # noqa: E402
import cli  # noqa: E402

HOJE = dt.date(2026, 11, 11)


def _f(id, sev=Severidade.MEDIO, cat="CWE-78", local="app/views.py:7", titulo=None, lentes=None):
    return Finding(id=id, titulo=titulo or id, severidade=sev, categoria=cat,
                   origem="t", local=local, lentes=lentes or [])


# --- selo mais rigoroso, nunca mais frouxo ---

def test_padrao_nao_bloqueia_medio_mas_modo_rigoroso_bloqueia():
    fs = [_f("A", Severidade.MEDIO)]
    assert calcular(fs).aprovado is True
    assert calcular(fs, Severidade.MEDIO).aprovado is False


def test_limite_mais_frouxo_que_alto_e_proibido():
    with pytest.raises(LimiteInvalido):
        calcular([_f("A", Severidade.ALTO)], Severidade.CRITICO)


# --- riscos aceitos ---

def test_fingerprint_igual_pra_caminho_relativo_e_absoluto():
    rel = _f("A", local="app/views.py:7")
    absoluto = _f("B", local=os.path.abspath("app/views.py") + ":7")
    assert aceitos.fingerprint(rel) == aceitos.fingerprint(absoluto) == "CWE-78|app/views.py:7"


def test_aceite_valido_tira_do_score_e_vai_pra_secao_propria(tmp_path):
    arq = str(tmp_path / "aceitos.json")
    f = _f("A", Severidade.ALTO)
    aceitos.aceitar(aceitos.fingerprint(f), "eval so roda no script de teste", 30, hoje=HOJE, caminho=arq)
    avisos = aceitos.aplicar([f], hoje=HOJE, caminho=arq)
    assert avisos == [] and f.status is Status.IGNORADO and "aceito ate 2026-12-11" in f.justificativa
    p = calcular([f])
    assert p.aprovado is True and p.riscos_aceitos == [f]
    txt = render([f])
    assert "riscos aceitos" in txt and txt.count("[A]") == 1  # nao aparece duas vezes


def test_aceite_vencido_volta_a_contar_e_avisa(tmp_path):
    arq = str(tmp_path / "aceitos.json")
    f = _f("A", Severidade.ALTO)
    aceitos.aceitar(aceitos.fingerprint(f), "motivo bem explicado", 10, hoje=HOJE, caminho=arq)
    avisos = aceitos.aplicar([f], hoje=HOJE + dt.timedelta(days=11), caminho=arq)
    assert f.status is Status.ABERTO and "VENCIDO" in avisos[0]
    assert calcular([f]).aprovado is False


@pytest.mark.parametrize("motivo,dias", [("curto", 10), ("motivo bem explicado", 0),
                                         ("motivo bem explicado", 91)])
def test_aceite_exige_motivo_e_prazo(tmp_path, motivo, dias):
    with pytest.raises(aceitos.AceiteInvalido):
        aceitos.aceitar("X|y", motivo, dias, caminho=str(tmp_path / "a.json"))


def test_reaceitar_substitui_em_vez_de_duplicar(tmp_path):
    arq = str(tmp_path / "a.json")
    aceitos.aceitar("X|y", "primeiro motivo aqui", 5, caminho=arq)
    aceitos.aceitar("X|y", "segundo motivo aqui", 9, caminho=arq)
    assert [a["motivo"] for a in aceitos.carregar(arq)] == ["segundo motivo aqui"]


# --- relatorio HTML ---

def test_html_escapa_tudo_que_vem_de_fora():
    perigoso = _f("X", titulo="<script>alert(1)</script>")
    perigoso.evidencia = '"><img src=x onerror=alert(2)>'
    h = render_html([perigoso], {"alvo": "<b>alvo</b>"})
    assert "<script>alert(1)" not in h and "&lt;script&gt;alert(1)" in h
    assert "<img src=x" not in h and "<b>alvo</b>" not in h


def test_html_e_offline_e_tem_csp():
    h = render_html([_f("A")], {})
    assert "Content-Security-Policy" in h and "default-src 'none'" in h
    assert 'src="http' not in h and "<link" not in h and "@import" not in h


def test_html_mostra_selo_cards_checklist_e_aceitos():
    ok = _f("OK", Severidade.INFO, cat="INVENTARIO")
    ruim = _f("RUIM", Severidade.CRITICO, lentes=[Lente.CRITICO])
    aceito = _f("ACEITO", Severidade.ALTO, local="b.py:1")
    aceito.status, aceito.justificativa = Status.IGNORADO, "falso positivo comprovado"
    h = render_html([ok, ruim, aceito], {"avisos": ["aceite VENCIDO em x"]})
    assert "BLOQUEADO" in h and h.count("<article") == 2  # aceito nao vira card
    assert "Checklist manual LGPD" in h and "falso positivo comprovado" in h
    assert "aceite VENCIDO" in h and 'data-lentes="critico"' in h


# --- auditar junta as trilhas ---

def test_auditar_junta_trilhas_e_funde_repetidos(monkeypatch):
    comum = lambda: _f("DUP", Severidade.ALTO, local="porta 8000/tcp", cat="CWE-668")  # noqa: E731
    monkeypatch.setattr(orchestrator, "escanear_projeto",
                        lambda p: Resultado(findings=[_f("COD")], rodaram=["gitleaks"]))
    monkeypatch.setattr(orchestrator, "escanear_nativo",
                        lambda o: Resultado(findings=[comum()], rodaram=["portas"]))
    monkeypatch.setattr(orchestrator, "analisar_trafego",
                        lambda o: Resultado(findings=[comum()], rodaram=["tshark"],
                                            pulados=[("x", "y")]))
    res = orchestrator.auditar(".", {"portas": [8000]}, {"pcap": "c.pcap"})
    assert res.rodaram == ["codigo:gitleaks", "nativo:portas", "trafego:tshark"]
    assert res.pulados == [("trafego:x", "y")]
    assert len(res.findings) == 2 and res.fundidos == 1


def test_auditar_sem_nada_pedido_nao_roda(capsys):
    assert cli.main(["auditar"]) == 2


# --- fluxo completo na CLI: scan -> aceitar pelo ID -> veredito muda ---

def test_aceitar_pelo_id_do_ultimo_relatorio(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    alto = _f("CODE-S001", Severidade.ALTO, local="app/x.py:3")
    monkeypatch.setattr(cli, "escanear_projeto",
                        lambda p: Resultado(findings=[_f("CODE-S001", Severidade.ALTO, local="app/x.py:3")],
                                            rodaram=["semgrep"]))
    assert cli.main(["scan", ".", "--html", "r.html", "--saida-json", "r.json"]) == 1
    assert os.path.exists("r.html")
    dados = json.load(open("r.json", encoding="utf-8"))
    assert dados["aprovado"] is False and dados["findings"][0]["fingerprint"] == aceitos.fingerprint(alto)

    assert cli.main(["aceitar", "CODE-S001", "--motivo", "regra nao se aplica aqui", "--dias", "15"]) == 0
    assert cli.main(["scan", "."]) == 0  # agora passa, com o risco a vista


def test_aceitar_id_inexistente_falha(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["aceitar", "NADA-001", "--motivo", "motivo comprido aqui"]) == 1


def test_demo_gera_html(tmp_path):
    saida = tmp_path / "demo.html"
    assert cli.main(["demo", "--html", str(saida)]) == 0
    assert "ARGOS" in saida.read_text(encoding="utf-8")
