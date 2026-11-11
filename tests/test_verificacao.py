import datetime as dt
import importlib.util
import os
import sys
import types

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from argos.guard.verificacao import (  # noqa: E402
    AlvoNaoVerificado, gerar_segredo, token_da_semana, tokens_aceitos,
    verificar_dono, url_de_verificacao,
)
from argos.guard.target_lock import autorizar_alvo  # noqa: E402
from argos.config import carregar_segredo  # noqa: E402

SEGREDO = "s" * 40
HOJE = dt.date(2026, 11, 11)


def _site_que_publica(token):
    chamadas = []

    def buscar(url):
        chamadas.append(url)
        return token
    buscar.chamadas = chamadas
    return buscar


# --- token ---

def test_token_e_deterministico_na_mesma_semana():
    assert token_da_semana(SEGREDO, "meusite.com", HOJE) == token_da_semana(
        SEGREDO, "meusite.com", HOJE + dt.timedelta(days=1))


def test_token_gira_na_semana_seguinte():
    assert token_da_semana(SEGREDO, "meusite.com", HOJE) != token_da_semana(
        SEGREDO, "meusite.com", HOJE + dt.timedelta(days=7))


def test_token_amarrado_ao_dominio():
    assert token_da_semana(SEGREDO, "a.com", HOJE) != token_da_semana(SEGREDO, "b.com", HOJE)


def test_token_nao_contem_o_segredo():
    t = token_da_semana(SEGREDO, "a.com", HOJE)
    assert SEGREDO not in t and len(t) == 64


def test_segredo_gerado_e_forte():
    assert len(gerar_segredo()) >= 32
    assert gerar_segredo() != gerar_segredo()


# --- verificacao de dono ---

def test_dono_verificado_com_token_da_semana():
    buscar = _site_que_publica(token_da_semana(SEGREDO, "meusite.com", HOJE))
    assert verificar_dono("https://meusite.com/app", SEGREDO, buscar=buscar, data=HOJE) == "meusite.com"


def test_aceita_token_da_semana_anterior_na_virada():
    anterior = tokens_aceitos(SEGREDO, "meusite.com", HOJE)[1]
    assert verificar_dono("meusite.com", SEGREDO, buscar=_site_que_publica(anterior), data=HOJE)


def test_recusa_token_de_duas_semanas_atras():
    velho = token_da_semana(SEGREDO, "meusite.com", HOJE - dt.timedelta(days=14))
    with pytest.raises(AlvoNaoVerificado):
        verificar_dono("meusite.com", SEGREDO, buscar=_site_que_publica(velho), data=HOJE)


def test_recusa_token_errado():
    with pytest.raises(AlvoNaoVerificado):
        verificar_dono("meusite.com", SEGREDO, buscar=_site_que_publica("x" * 64), data=HOJE)


def test_recusa_sem_segredo():
    with pytest.raises(AlvoNaoVerificado, match="ARGOS_SECRET"):
        verificar_dono("meusite.com", None, buscar=_site_que_publica("x"))


def test_recusa_segredo_curto():
    with pytest.raises(AlvoNaoVerificado, match="curto"):
        verificar_dono("meusite.com", "123", buscar=_site_que_publica("x"))


def test_erro_de_rede_bloqueia():
    def quebra(url):
        raise OSError("sem rede")
    with pytest.raises(AlvoNaoVerificado):
        verificar_dono("meusite.com", SEGREDO, buscar=quebra)


def test_sempre_busca_via_https_mesmo_pedindo_http():
    buscar = _site_que_publica("x")
    with pytest.raises(AlvoNaoVerificado):
        verificar_dono("http://meusite.com", SEGREDO, buscar=buscar)
    assert buscar.chamadas == ["https://meusite.com/.well-known/argos-verify.txt"]
    assert url_de_verificacao("meusite.com:8443") == "https://meusite.com/.well-known/argos-verify.txt"


# --- porta de entrada ---

def test_local_continua_sem_token():
    assert autorizar_alvo("127.0.0.1", None)[0] == "local"


def test_publico_sem_segredo_bloqueia():
    with pytest.raises(AlvoNaoVerificado):
        autorizar_alvo("8.8.8.8", None)


def test_publico_com_dono_verificado_passa():
    buscar = _site_que_publica(token_da_semana(SEGREDO, "8.8.8.8"))
    assert autorizar_alvo("8.8.8.8", SEGREDO, buscar=buscar) == ("verificado", "8.8.8.8")


# --- config ---

def test_segredo_lido_do_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGOS_SECRET", raising=False)
    (tmp_path / ".env").write_text('# comentario\nARGOS_SECRET="abc123"\n', encoding="utf-8")
    assert carregar_segredo(str(tmp_path)) == "abc123"


def test_variavel_de_ambiente_tem_prioridade(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("ARGOS_SECRET=do_arquivo\n", encoding="utf-8")
    monkeypatch.setenv("ARGOS_SECRET", "do_ambiente")
    assert carregar_segredo(str(tmp_path)) == "do_ambiente"


# --- o site Django e o Argos falam a mesma lingua ---

def test_endpoint_django_publica_exatamente_o_token_que_o_argos_espera(monkeypatch):
    # stub minimo de django.http, pra testar o snippet sem instalar Django
    http = types.ModuleType("django.http")

    class HttpResponse(dict):
        def __init__(self, content, content_type=None):
            super().__init__()
            self.content = content

    class Http404(Exception):
        pass

    http.HttpResponse, http.Http404 = HttpResponse, Http404
    monkeypatch.setitem(sys.modules, "django", types.ModuleType("django"))
    monkeypatch.setitem(sys.modules, "django.http", http)

    caminho = os.path.join(RAIZ, "exemplos", "railway_django", "argos_verify.py")
    spec = importlib.util.spec_from_file_location("argos_verify_snippet", caminho)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class Req:
        def get_host(self):
            return "MeuSite.com:443"

    monkeypatch.setenv("ARGOS_SECRET", SEGREDO)
    publicado = mod.argos_verify(Req()).content
    assert publicado == token_da_semana(SEGREDO, "meusite.com")

    monkeypatch.delenv("ARGOS_SECRET")
    with pytest.raises(Http404):  # sem segredo no Railway -> rota some
        mod.argos_verify(Req())
