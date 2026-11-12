"""Trilha web (v2.1): varredura passiva contra servidores locais de mentira."""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)
sys.path.insert(0, os.path.join(RAIZ, "exemplos"))

import web_inseguro  # noqa: E402
from argos.adapters import web as modweb  # noqa: E402
from argos.adapters.web import Varredura, Cliente, WebAdapter  # noqa: E402
from argos.adapters.base import Contexto  # noqa: E402
from argos.core.orchestrator import analisar_web, auditar  # noqa: E402
from argos.schema import Severidade  # noqa: E402


@pytest.fixture(autouse=True)
def sem_pausa(monkeypatch):
    # testes rapidos: sem a pausa educada entre requisicoes
    original = Cliente.__init__

    def init(self, base, pausa=0.0, *a, **k):
        original(self, base, 0.0, *a, **k)
    monkeypatch.setattr(Cliente, "__init__", init)


def _subir(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture
def inseguro():
    srv = web_inseguro.criar(0)
    yield _subir(srv)
    srv.shutdown()
    srv.server_close()


class SpaSegura(BaseHTTPRequestHandler):
    """Angular/React em producao bem configurado: devolve index.html pra QUALQUER caminho."""
    server_version = "srv"
    sys_version = ""

    def log_message(self, *a):
        pass

    def do_GET(self):
        corpo = (b"<!doctype html><html><head><title>App</title></head><body><app-root></app-root>"
                 b'<script src="/main.js"></script></body></html>')
        if self.path.startswith("/main.js") and not self.path.endswith(".map"):
            corpo, tipo = b"console.log('oi')", "application/javascript"
        else:
            tipo = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "sessionid=x; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(corpo)

    def do_TRACE(self):
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def spa():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), SpaSegura)
    yield _subir(srv)
    srv.shutdown()
    srv.server_close()


def _cats(achados):
    return {f.categoria for f in achados}


def test_app_inseguro_acha_tudo_que_foi_plantado(inseguro):
    achados = Varredura(inseguro, local=True).rodar()
    titulos = " | ".join(f.titulo for f in achados)
    esperadas = {"CWE-538", "CWE-527", "CWE-548", "CWE-798", "CWE-540", "CWE-942", "CWE-1004",
                 "CWE-1275", "CWE-497", "CWE-693", "CWE-1021", "CWE-489", "ARGOS-ADMIN-PADRAO"}
    assert esperadas <= _cats(achados), titulos
    assert "TRACE" in titulos
    env = next(f for f in achados if f.local.endswith("/.env"))
    assert env.severidade == Severidade.CRITICO
    cors = next(f for f in achados if f.categoria == "CWE-942")
    assert cors.severidade == Severidade.ALTO  # reflete origem + credenciais


def test_segredos_saem_mascarados(inseguro):
    achados = Varredura(inseguro, local=True).rodar()
    tudo = " ".join(f.evidencia + f.titulo for f in achados)
    assert "AKIAFALSA" not in tudo
    assert "AKIA***" in tudo
    assert "falsa-nao-use" not in tudo        # valor do .env nunca aparece
    assert "SECRET_KEY" in tudo               # so o nome da variavel


def test_spa_segura_nao_gera_falso_positivo(spa):
    # o fallback de SPA responde 200 pra /.env, /.git/HEAD, /admin/... com o index.html:
    # sem assinatura de conteudo isso viraria uma chuva de alarme falso
    achados = Varredura(spa, local=True).rodar()
    acima_de_info = [f for f in achados if f.severidade not in (Severidade.INFO,)]
    assert acima_de_info == [], [f.titulo for f in acima_de_info]


def test_limite_de_requisicoes(inseguro):
    v = Varredura(inseguro, local=True)
    v.rodar()
    assert v.c.enviadas <= 80 and v.c.restantes >= 0


def test_redirect_pra_outro_host_e_recusado():
    class Redireciona(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Redireciona)
    base = _subir(srv)
    try:
        r = Cliente(base).pedir("/")
        assert r is None or r.status in (301, 302, 303, 307, 308)
        assert r is None or "example.com" not in r.url
    finally:
        srv.shutdown()
        srv.server_close()


def test_url_publica_sem_segredo_e_bloqueada():
    res = analisar_web({"urls": ["https://example.com"], "segredo": None})
    assert res.findings == []
    assert any(nome == "web" for nome, _ in res.pulados)


def test_adapter_renumera_ids(inseguro):
    achados = WebAdapter().escanear(Contexto(projeto="", opcoes={"urls": [inseguro]}))
    assert [f.id for f in achados] == [f"WEB-{i:03d}" for i in range(1, len(achados) + 1)]
    assert all(f.origem == "argos-web" for f in achados)


def test_auditar_com_trilha_web(inseguro):
    res = auditar(web={"urls": [inseguro]})
    assert any(r.startswith("web") for r in res.rodaram)
    assert any(f.categoria == "CWE-538" for f in res.findings)
    assert all(f.lentes is not None for f in res.findings)
