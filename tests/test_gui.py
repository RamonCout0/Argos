import json
import os
import sys

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from argos.schema import Finding, Severidade, Status, Lente  # noqa: E402
from argos.core.aceitos import fingerprint  # noqa: E402
from argos.gui import estado as est  # noqa: E402


def _f(id, sev=Severidade.ALTO, local=None, lentes=None, status=Status.ABERTO):
    f = Finding(id=id, titulo=f"titulo {id}", severidade=sev, categoria="CWE-78", origem="t",
                local=local or f"app/{id}.py:1", lentes=lentes or [])
    if status is Status.IGNORADO:
        f.status, f.justificativa = status, "falso positivo comprovado"
    return f


def test_chave_alvo_junta_as_trilhas():
    assert est.chave_alvo() == "geral"
    k = est.chave_alvo("proj", [4200, 8000, 8000], "c.pcap")
    assert k.endswith("portas:4200,8000 + pcap:" + os.path.abspath("c.pcap"))


def test_marcar_e_desmarcar():
    e = {"projetos": {}}
    assert est.alternar(e, "p", "FP") is True and est.marcado(e, "p", "FP")
    assert est.alternar(e, "p", "FP") is False and not est.marcado(e, "p", "FP")


def test_re_scan_mostra_resolvidas_e_limpa_a_marca():
    e = {"projetos": {}}
    a, b = _f("A"), _f("B")
    est.registrar_scan(e, "p", [a, b])
    est.alternar(e, "p", fingerprint(a))
    # no scan seguinte, A sumiu: foi corrigida de verdade
    assert est.resolvidos(e, "p", [b]) == ["titulo A"]
    est.registrar_scan(e, "p", [b])
    assert not est.marcado(e, "p", fingerprint(a))


def test_progresso_ignora_info_e_aceitos():
    e = {"projetos": {}}
    fs = [_f("A"), _f("B", Severidade.INFO), _f("C", status=Status.IGNORADO)]
    est.alternar(e, "p", fingerprint(fs[0]))
    assert est.progresso(e, "p", fs) == (1, 1)


def test_filtrar_por_lente_ordena_e_esconde_aceitos():
    fs = [_f("M", Severidade.MEDIO, lentes=[Lente.LGPD]), _f("C", Severidade.CRITICO, lentes=[Lente.CRITICO]),
          _f("I", Severidade.INFO), _f("X", status=Status.IGNORADO)]
    assert [f.id for f in est.filtrar(fs)] == ["C", "M", "I"]
    assert [f.id for f in est.filtrar(fs, "lgpd")] == ["M"]
    assert [f.id for f in est.filtrar(fs, "info")] == ["I"]


def test_checklist_lgpd_por_projeto():
    e = {"projetos": {}}
    est.alternar_lgpd(e, "tevejo", 2)
    assert est.lgpd_marcado(e, "tevejo", 2) and not est.lgpd_marcado(e, "gatuno", 2)


def test_salvar_e_carregar(tmp_path):
    arq = str(tmp_path / "c.json")
    e = {"projetos": {}}
    est.alternar(e, "p", "FP")
    est.salvar(e, arq)
    assert est.marcado(est.carregar(arq), "p", "FP")
    assert est.carregar(str(tmp_path / "nao_existe.json")) == {"projetos": {}}


def test_ultimo_no_formato_da_cli(tmp_path):
    arq = str(tmp_path / "ultimo.json")
    f = _f("CODE-S001")
    est.salvar_ultimo([f], arq)
    dados = json.load(open(arq, encoding="utf-8"))
    assert dados["findings"][0] == {"id": "CODE-S001", "fingerprint": fingerprint(f),
                                    "titulo": "titulo CODE-S001", "severidade": "alto"}


# --- a janela de verdade (só onde houver Tkinter e tela) ---

def _tem_tela():
    try:
        import tkinter
        r = tkinter.Tk()
        r.destroy()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _tem_tela(), reason="sem Tkinter ou sem tela")
def test_janela_abre_desenha_e_marca(tmp_path, monkeypatch):
    import tkinter as tk
    import cli
    from argos.gui.app import App

    monkeypatch.chdir(tmp_path)
    demo = cli.enriquecer(cli._findings_demo())
    cli.narrar(demo, None)
    root = tk.Tk()
    try:
        app = App(root, demo=demo)
        root.update()
        app._desenhar_lista()
        assert app.lista.find_all(), "a lista de cards deveria ter sido desenhada"
        primeiro = est.filtrar(app.findings)[0]
        app._clique_card(primeiro, 0)  # sem item 'current': seleciona e mostra o detalhe
        assert app.selecionado is primeiro
        assert primeiro.titulo in app.detalhe.get("1.0", "end")
        est.alternar(app.estado, app.chave, fingerprint(primeiro))
        assert est.progresso(app.estado, app.chave, app.findings)[0] == 1
        app._filtrar("lgpd")
        app._aba("lgpd")
        app._desenhar_lgpd()
        assert app.lista_lgpd.find_all()
    finally:
        root.destroy()
