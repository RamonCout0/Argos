import os
import shutil
import sys

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from argos.schema import Severidade  # noqa: E402
from argos.native.sensiveis import cpf_valido, detectar  # noqa: E402
from argos.adapters.tshark import (  # noqa: E402
    _texto_de, requisicoes_do_json, analisar, TsharkAdapter,
)
from argos.core.orchestrator import analisar_trafego  # noqa: E402
from argos.report.console import render  # noqa: E402


# --- detector ---

@pytest.mark.parametrize("cpf,ok", [
    ("529.982.247-25", True), ("52998224725", True), ("123.456.789-09", True),
    ("111.111.111-11", False), ("123.456.789-00", False),
])
def test_cpf_valido(cpf, ok):
    assert cpf_valido(cpf) is ok


def test_detecta_form_e_nunca_devolve_o_valor():
    d = detectar("email=ramon%40exemplo.com&senha=123456&cpf=529.982.247-25")
    texto = " ".join(d["credenciais"] + d["pessoais"])
    assert "senha" in texto and "***-25" in texto and "r***@exemplo.com" in texto
    assert "123456" not in texto and "529.982" not in texto and "ramon@" not in texto


def test_detecta_json_authorization_e_cookie_de_sessao():
    d = detectar('{"password": "x1"}', autorizacao="Bearer abc.def", cookie="sessionid=9f; tema=escuro")
    texto = " ".join(d["credenciais"])
    assert "password" in texto and "Bearer ***" in texto and "sessionid=***" in texto
    assert "tema" not in texto and "abc.def" not in texto


def test_numero_qualquer_nao_vira_cpf():
    assert detectar("pedido=12345678901")["pessoais"] == []


# --- parse do tshark ---

def test_corpo_em_hex_do_wireshark_4_volta_pra_texto():
    assert _texto_de("73656e68613d31") == "senha=1"
    assert _texto_de("texto normal") == "texto normal"


def _pkt(dst, metodo, uri, host, **extra):
    camadas = {"ip.dst": [dst], "tcp.dstport": ["80"], "http.request.method": [metodo],
               "http.request.uri": [uri], "http.host": [host]}
    camadas.update({k: [v] if isinstance(v, str) else v for k, v in extra.items()})
    return {"_source": {"layers": camadas}}


def test_requisicoes_usam_form_quando_nao_ha_corpo():
    reqs = requisicoes_do_json([_pkt("203.0.113.10", "POST", "/login", "api.x.com",
                                     **{"urlencoded-form.key": ["senha"], "urlencoded-form.value": ["1"]})])
    assert reqs[0]["corpo"] == "senha=1"


def test_pacote_sem_metodo_http_e_ignorado():
    assert requisicoes_do_json([{"_source": {"layers": {"ip.dst": ["1.2.3.4"]}}}]) == []


# --- analise ---

def test_credencial_pra_fora_e_critica_e_cpf_alto():
    reqs = requisicoes_do_json([_pkt("203.0.113.10", "POST", "/login", "api.x.com",
                                     **{"http.file_data": "senha=1&cpf=529.982.247-25"})])
    sev = {(f.local, f.categoria): f.severidade for f in analisar(reqs)}
    endpoint = "POST http://api.x.com/login"
    assert sev[(endpoint, "CWE-319")] is Severidade.CRITICO    # a senha
    assert sev[(endpoint, "CWE-359")] is Severidade.ALTO       # o CPF
    assert sev[("http://api.x.com", "CWE-319")] is Severidade.MEDIO  # o host em HTTP


def test_so_email_e_medio():
    reqs = requisicoes_do_json([_pkt("203.0.113.10", "POST", "/n", "x.com", **{"http.file_data": "e=a@b.com"})])
    pess = [f for f in analisar(reqs) if f.categoria == "CWE-359"][0]
    assert pess.severidade is Severidade.MEDIO


def test_localhost_vira_baixo_e_nao_gera_alerta_de_host():
    reqs = requisicoes_do_json([_pkt("127.0.0.1", "POST", "/l", "127.0.0.1:8000",
                                     **{"http.file_data": "senha=1"})])
    fs = analisar(reqs)
    assert len(fs) == 1 and fs[0].severidade is Severidade.BAIXO


def test_alerta_de_host_sai_uma_vez_por_host():
    reqs = requisicoes_do_json([_pkt("203.0.113.20", "GET", f"/{i}.png", "cdn.x.com") for i in range(3)])
    assert len(analisar(reqs)) == 1


# --- comando ---

def test_comando_pcap_nao_usa_filtro_de_captura():
    cmd = TsharkAdapter().comando({"pcap": "c.pcap"})
    assert "-r" in cmd and "-f" not in cmd and "-a" not in cmd


def test_comando_ao_vivo_limita_janela_e_filtra_portas():
    cmd = TsharkAdapter().comando({"segundos": 999, "portas_http": [80, 8080]})
    assert "duration:300" in cmd and "tcp port 80 or tcp port 8080" in cmd
    assert "duration:5" in TsharkAdapter().comando({"segundos": 1})


# --- integracao real (roda onde o tshark estiver instalado) ---

@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark nao instalado")
def test_captura_de_exemplo_com_tshark_de_verdade():
    pcap = os.path.join(RAIZ, "exemplos", "captura_exemplo.pcap")
    res = analisar_trafego({"pcap": pcap})
    assert res.rodaram == ["tshark"]
    sev = sorted(f.severidade.value for f in res.findings)
    assert sev.count("critico") == 2 and sev.count("alto") == 1
    texto = render(res.findings)
    assert "529.982.247" not in texto and "123456" not in texto  # nada cru no relatorio
    assert "***.***.***-25" in texto
