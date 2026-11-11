import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.schema import Finding, Severidade, Status, Fix, FixTipo  # noqa: E402
from argos.ai.contexto import mascarar, trecho_de  # noqa: E402
from argos.ai.templates import explicacao_base, GENERICO  # noqa: E402
from argos.ai.narrator import narrar, LIMITE_TEXTO  # noqa: E402
from argos.ai.ollama import Ollama  # noqa: E402

SEGREDO = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"


class ModeloFalso:
    modelo = "falso:1b"

    def __init__(self, resposta=None, quebra=False):
        self.resposta = resposta or {"explicacao": "risco X", "correcao": "faca Y"}
        self.quebra = quebra
        self.prompts = []

    def gerar_json(self, sistema, prompt):
        self.prompts.append(prompt)
        if self.quebra:
            raise OSError("caiu")
        return self.resposta


def _f(id, sev=Severidade.ALTO, cat="CWE-78", local="x.py:1", fix_tipo=FixTipo.IA):
    return Finding(id=id, titulo=id, severidade=sev, categoria=cat, origem="t",
                   local=local, fix=Fix(fix_tipo, "fix original", "patch"))


# --- mascara ---

def test_mascara_tokens_e_strings_longas():
    txt = mascarar(f'TOKEN = "{SEGREDO}"\nAWS = AKIAQJ7XR3ZL5MN2PV8T\nx = "curta"')
    assert SEGREDO not in txt and "AKIAQJ7XR3ZL5MN2PV8T" not in txt
    assert '"curta"' in txt


def test_mascara_chave_privada_e_senha_em_url():
    txt = mascarar("-----BEGIN RSA PRIVATE KEY-----\nDB = 'postgres://admin:senha123@host/db'")
    assert "BEGIN RSA" not in txt and "senha123" not in txt


def test_trecho_marca_a_linha_e_mascara(tmp_path):
    arq = tmp_path / "settings.py"
    arq.write_text(f'A = 1\nB = 2\nTOKEN = "{SEGREDO}"\nC = 3\n', encoding="utf-8")
    f = _f("S", local=f"{arq}:3")
    t = trecho_de(f)
    assert ">   3 |" in t and SEGREDO not in t


def test_trecho_vazio_sem_linha_ou_arquivo():
    assert trecho_de(_f("A", local="requirements.txt:requests")) == ""
    assert trecho_de(_f("B", local="nao_existe.py:3")) == ""


# --- templates ---

def test_template_conhecido_e_generico():
    assert explicacao_base("cwe-798") != GENERICO
    assert explicacao_base("CWE-99999") == GENERICO


# --- narrador ---

def test_sem_ia_todo_mundo_ganha_explicacao_base():
    fs = [_f("A"), _f("B", fix_tipo=FixTipo.DETERMINISTICO)]
    narrar(fs, None, cache=None)
    assert all(f.explicacao and f.fonte_explicacao == "template" for f in fs)


def test_ia_so_narra_quem_precisa_e_nao_mexe_na_decisao():
    ia, det = _f("IA"), _f("DET", fix_tipo=FixTipo.DETERMINISTICO)
    modelo = ModeloFalso()
    narrar([ia, det], modelo, cache=None)
    assert ia.fonte_explicacao == "ia" and ia.sugestao_ia == "faca Y"
    assert det.fonte_explicacao == "template" and not det.sugestao_ia
    # a IA nao toca no que decide o deploy
    assert ia.severidade is Severidade.ALTO and ia.status is Status.ABERTO
    assert ia.fix.tipo is FixTipo.IA and ia.fix.descricao == "fix original"
    assert len(modelo.prompts) == 1


def test_prompt_nao_leva_o_segredo(tmp_path):
    arq = tmp_path / "s.py"
    arq.write_text(f'TOKEN = "{SEGREDO}"\n', encoding="utf-8")
    modelo = ModeloFalso()
    narrar([_f("S", cat="CWE-798", local=f"{arq}:1")], modelo, cache=None)
    assert SEGREDO not in modelo.prompts[0]


def test_maximo_prioriza_os_mais_graves():
    fs = [_f("BAIXO", sev=Severidade.BAIXO), _f("CRIT", sev=Severidade.CRITICO),
          _f("MED", sev=Severidade.MEDIO)]
    narrar(fs, ModeloFalso(), maximo=1, cache=None)
    assert [f.id for f in fs if f.fonte_explicacao == "ia"] == ["CRIT"]


def test_cache_evita_perguntar_de_novo(tmp_path):
    cache = str(tmp_path / "ia.json")
    narrar([_f("A")], ModeloFalso(), cache=cache)
    segundo = ModeloFalso()
    est = narrar([_f("A")], segundo, cache=cache)
    assert est.do_cache == 1 and segundo.prompts == []


def test_falha_do_modelo_mantem_explicacao_base():
    f = _f("A")
    est = narrar([f], ModeloFalso(quebra=True), cache=None)
    assert est.falhas == 1 and f.fonte_explicacao == "template"


def test_resposta_torta_vira_falha():
    f = _f("A")
    est = narrar([f], ModeloFalso(resposta={"outra_coisa": 1}), cache=None)
    assert est.falhas == 1 and f.fonte_explicacao == "template"


def test_texto_gigante_e_cortado():
    f = _f("A")
    narrar([f], ModeloFalso(resposta={"explicacao": "x" * 5000, "correcao": "y"}), cache=None)
    assert len(f.explicacao) == LIMITE_TEXTO


# --- cliente Ollama ---

def test_ollama_remoto_e_recusado_sem_sair_da_maquina():
    ok, msg = Ollama(url="http://8.8.8.8:11434").status()
    assert not ok and "local" in msg


def test_ollama_desligado_vira_mensagem_clara():
    ok, msg = Ollama(url="http://127.0.0.1:9").status()
    assert not ok and "nao consegui falar" in msg


def test_status_e_gerar_json_com_servidor_falso(monkeypatch):
    def req_falso(self, caminho, payload=None, timeout=None):
        if caminho == "/api/tags":
            return {"models": [{"name": "llama3.1:8b"}]}
        assert payload["format"] == "json" and payload["options"]["temperature"] == 0
        return {"response": '{"explicacao": "a", "correcao": "b"}'}

    monkeypatch.setattr(Ollama, "_req", req_falso)
    cli = Ollama(modelo="llama3.1:8b")
    assert cli.status()[0] is True
    assert cli.gerar_json("s", "p") == {"explicacao": "a", "correcao": "b"}
    assert Ollama(modelo="outro:7b").status()[0] is False
