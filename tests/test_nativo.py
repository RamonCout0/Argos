import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.schema import Severidade  # noqa: E402
from argos.native.riscos import risco_da_porta, ip_e_local  # noqa: E402
from argos.adapters import portas as mod_portas  # noqa: E402
from argos.adapters.portas import classificar, PortasAdapter  # noqa: E402
from argos.adapters import nmap as mod_nmap  # noqa: E402
from argos.adapters.nmap import parse_xml, findings_locais, findings_rede, NmapAdapter  # noqa: E402
from argos.adapters.base import Contexto  # noqa: E402
from argos.guard.target_lock import AlvoNaoLocal  # noqa: E402


# --- risco por porta ---

@pytest.mark.parametrize("porta,servico,sev,cwe", [
    (9229, "", Severidade.CRITICO, "CWE-489"),   # node inspector
    (5432, "", Severidade.ALTO, "CWE-668"),      # postgres
    (6379, "", Severidade.ALTO, "CWE-306"),      # redis sem senha
    (11434, "", Severidade.ALTO, "CWE-306"),     # ollama sem auth
    (15432, "postgresql", Severidade.ALTO, "CWE-668"),  # banco em porta trocada
    (8000, "http", Severidade.MEDIO, "CWE-668"),
])
def test_risco_da_porta(porta, servico, sev, cwe):
    s, c, _ = risco_da_porta(porta, servico)
    assert (s, c) == (sev, cwe)


@pytest.mark.parametrize("ip,local", [
    ("127.0.0.1", True), ("::1", True), ("192.168.0.5", True), ("10.1.2.3", True),
    ("172.20.0.1", True), ("203.0.113.10", False), ("8.8.8.8", False),
])
def test_ip_e_local(ip, local):
    assert ip_e_local(ip) is local


# --- psutil / classificar ---

def _s(ip, porta, proc="python.exe", pid=10):
    return {"ip": ip, "porta": porta, "pid": pid, "processo": proc}


def test_porta_em_0000_e_exposta():
    f = classificar([_s("0.0.0.0", 8000)], portas=[8000])[0]
    assert f.severidade is Severidade.MEDIO and f.categoria == "CWE-668"


def test_porta_so_em_loopback_e_ok():
    f = classificar([_s("127.0.0.1", 8000)], portas=[8000])[0]
    assert f.severidade is Severidade.INFO and "ok" in f.titulo


def test_ip_da_rede_especifico_tambem_e_exposto():
    assert classificar([_s("192.168.0.5", 8000)], portas=[8000])[0].severidade is Severidade.MEDIO


def test_ipv4_e_ipv6_na_mesma_porta_viram_um_achado():
    fs = classificar([_s("0.0.0.0", 5432, "postgres"), _s("::", 5432, "postgres")], portas=[5432])
    assert len(fs) == 1 and fs[0].severidade is Severidade.ALTO


def test_filtro_por_processo_ignora_o_resto():
    socks = [_s("0.0.0.0", 445, "System", 4), _s("0.0.0.0", 3000, "node.exe")]
    fs = classificar(socks, processo="node")
    assert [f.local for f in fs] == ["porta 3000/tcp"]


def test_porta_pedida_sem_ninguem_escutando_avisa():
    f = classificar([], portas=[8000])[0]
    assert f.severidade is Severidade.INFO and "Nada escutando" in f.titulo


def test_sem_escopo_o_adapter_recusa():
    with pytest.raises(ValueError):
        PortasAdapter().escanear(Contexto(projeto="", opcoes={}))


# --- nmap ---

XML = """<nmaprun><host><address addr="127.0.0.1"/><ports>
<port protocol="tcp" portid="5432"><state state="open"/>
  <service name="postgresql" product="PostgreSQL DB" version="15.2"/></port>
<port protocol="tcp" portid="8000"><state state="open"/><service name="http" product="WSGIServer"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/></port>
</ports></host></nmaprun>"""


def test_parse_xml_do_nmap():
    ps = parse_xml(XML)
    assert [p["porta"] for p in ps] == [5432, 8000, 9999]
    assert ps[0]["servico"] == "postgresql" and ps[0]["versao"] == "15.2"


def test_findings_locais_so_portas_abertas_e_sao_info():
    fs = findings_locais(parse_xml(XML))
    assert len(fs) == 2 and all(f.severidade is Severidade.INFO for f in fs)


def test_findings_rede_pesa_pelo_servico():
    fs = findings_rede(parse_xml(XML), "192.168.0.5")
    sev = {f.local: f.severidade for f in fs}
    assert sev["porta 5432/tcp"] is Severidade.ALTO
    assert sev["porta 8000/tcp"] is Severidade.MEDIO


def _nmap_falso(monkeypatch):
    chamadas = []

    class Proc:
        returncode, stderr, stdout = 0, "", XML

    def run(cmd, **kw):
        chamadas.append(cmd)
        return Proc()

    monkeypatch.setattr(mod_nmap, "_binario", lambda: "nmap")
    monkeypatch.setattr(mod_nmap.subprocess, "run", run)
    return chamadas


def test_nmap_so_nas_portas_pedidas_e_em_modo_leve(monkeypatch):
    chamadas = _nmap_falso(monkeypatch)
    NmapAdapter().escanear(Contexto(projeto="", opcoes={"portas": [8000, 5432]}))
    cmd = chamadas[0]
    assert "-sT" in cmd and "-p-" not in cmd
    assert cmd[cmd.index("-p") + 1] == "5432,8000"
    assert cmd[-1] == "127.0.0.1"


def test_nmap_sem_porta_nao_varre_nada(monkeypatch):
    chamadas = _nmap_falso(monkeypatch)
    assert NmapAdapter().escanear(Contexto(projeto="", opcoes={})) == []
    assert chamadas == []


def test_nmap_nunca_mira_ip_publico(monkeypatch):
    chamadas = _nmap_falso(monkeypatch)
    with pytest.raises(AlvoNaoLocal):
        NmapAdapter()._rodar("8.8.8.8", [80])
    assert chamadas == []


def test_rede_com_ip_publico_e_recusada(monkeypatch):
    chamadas = _nmap_falso(monkeypatch)
    monkeypatch.setattr(mod_nmap, "ip_da_rede", lambda: "8.8.8.8")
    with pytest.raises(AlvoNaoLocal):
        NmapAdapter().escanear(Contexto(projeto="", opcoes={"portas": [80], "rede": True}))
    assert all(c[-1] == "127.0.0.1" for c in chamadas)  # so o scan local chegou a rodar


def test_ip_da_rede_devolve_algo_plausivel():
    ip = mod_portas.ip_da_rede()
    assert ip is None or ip.count(".") == 3
