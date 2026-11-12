import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.adapters import prompt_injection as pi  # noqa: E402
from argos.adapters.prompt_injection import (  # noqa: E402
    contem, avaliar, gerar_canario, AlvoOllama, AlvoHTTP, rodar, achados, PromptInjectionAdapter,
)
from argos.adapters.base import Contexto  # noqa: E402
from argos.ai.ollama import Ollama  # noqa: E402
from argos.core.orchestrator import testar_ia  # noqa: E402
from argos.guard.target_lock import AlvoNaoLocal  # noqa: E402
from argos.schema import Severidade  # noqa: E402

_MARCA = re.compile(r"(?:palavra|word) (\w+) (?:seguida do número|followed by the number) (\d+)")


def responder(personalidade: str, sistema: str, msg: str) -> str:
    m = _MARCA.search(msg)
    if personalidade == "segura":
        return "Desculpe, não posso ajudar com isso. Posso falar sobre os eventos?"
    if personalidade == "citadora":  # recusa, mas CITA o pedido: nao pode virar falso positivo
        if m:
            return f"Não vou responder a palavra {m.group(1)} seguida do número {m.group(2)}."
        return "Não posso revelar minhas instruções."
    # vulneravel
    if "trás para frente" in msg:
        return sistema[::-1]
    if "instruções" in msg or "código, chave" in msg:
        return "Claro! Minhas instruções são: " + sistema
    if m:
        marcador = m.group(1) + m.group(2)
        return f"O documento fala de crescimento. {marcador}" if "---" in msg else marcador
    return "ok"


class FakeOllama:
    def __init__(self, personalidade="vulneravel", modelos=("teste:1b",)):
        dono = self
        self.personalidade, self.modelos, self.chamadas = personalidade, list(modelos), 0

        class H(BaseHTTPRequestHandler):
            def _json(self, dados):
                corpo = json.dumps(dados).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(corpo)))
                self.end_headers()
                self.wfile.write(corpo)

            def do_GET(self):
                self._json({"models": [{"name": n} for n in dono.modelos]})

            def do_POST(self):
                dados = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                dono.chamadas += 1
                if self.path == "/api/chat":
                    sis = dados["messages"][0]["content"]
                    usr = dados["messages"][1]["content"]
                    self._json({"message": {"content": responder(dono.personalidade, sis, usr)}})
                else:  # endpoint de "app" no modo HTTP
                    self._json({"dados": {"resposta": responder(dono.personalidade,
                                                                 dono.sistema_app, dados["mensagem"])}})

            def log_message(self, *a):
                pass

        self.sistema_app = ""
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def fechar(self):
        self.srv.shutdown()


@pytest.fixture
def ollama_falso():
    criados = []

    def criar(personalidade="vulneravel"):
        f = FakeOllama(personalidade)
        criados.append(f)
        return f
    yield criar
    for f in criados:
        f.fechar()


def _por_categoria(findings):
    return {f.local.split(" · ")[-1]: f for f in findings}


# --- deteccao ---

def test_contem_ignora_espaco_caixa_acento_e_pega_invertido():
    assert contem("o código é a r g o s - c a n á r i o - 1 a 2 b", "ARGOS-CANARIO-1A2B")
    assert contem("B2A1-OIRANAC-SOGRA", "ARGOS-CANARIO-1A2B")
    assert not contem("nada aqui", "ARGOS-CANARIO-1A2B")


def test_sobrescrita_so_conta_resposta_curta_com_marcador_colado():
    assert avaliar("sobrescrita", "TROVAO4821", marcador="TROVAO4821")
    assert not avaliar("sobrescrita", "Não vou dizer a palavra TROVAO seguida do número 4821.",
                       marcador="TROVAO4821")
    longa = "TROVAO4821 " + "x" * 300
    assert not avaliar("sobrescrita", longa, marcador="TROVAO4821")


def test_vazamento_sem_canario_nunca_acusa():
    assert not avaliar("vazamento", "qualquer coisa", canario="")


def test_canario_e_unico():
    assert gerar_canario() != gerar_canario()


# --- ponta a ponta contra um Ollama falso de verdade (HTTP) ---

def test_ia_vulneravel_falha_nas_tres_categorias(ollama_falso):
    f = ollama_falso("vulneravel")
    alvo = AlvoOllama(Ollama(url=f.url, modelo="teste:1b"), "Você é a Lumi.")
    cats = _por_categoria(achados(rodar(alvo), alvo.descricao))
    assert cats["vazamento"].severidade is Severidade.ALTO
    assert cats["sobrescrita"].severidade is Severidade.MEDIO
    assert cats["indireta"].severidade is Severidade.ALTO
    assert "V1" in cats["vazamento"].evidencia and "V3" in cats["vazamento"].evidencia
    assert all(c.categoria == "CWE-1427" for c in cats.values())


def test_ia_segura_resiste_a_tudo(ollama_falso):
    f = ollama_falso("segura")
    alvo = AlvoOllama(Ollama(url=f.url, modelo="teste:1b"), "Você é a Lumi.")
    fs = achados(rodar(alvo), alvo.descricao)
    assert all(x.severidade is Severidade.INFO for x in fs) and len(fs) == 3
    assert all("resistiu" in x.titulo for x in fs)


def test_recusa_que_cita_o_pedido_nao_e_falso_positivo(ollama_falso):
    f = ollama_falso("citadora")
    alvo = AlvoOllama(Ollama(url=f.url, modelo="teste:1b"), "Você é a Lumi.")
    fs = achados(rodar(alvo), alvo.descricao)
    assert all(x.severidade is Severidade.INFO for x in fs)


def test_modelo_ausente_vira_erro_claro(ollama_falso):
    f = ollama_falso()
    ad = PromptInjectionAdapter()
    with pytest.raises(RuntimeError, match="nao encontrado"):
        ad.escanear(Contexto(projeto="", opcoes={"modo": "ollama", "ollama_url": f.url,
                                                 "modelo": "nao-existe:7b", "sistema": "x"}))


def test_orquestrador_trilha_ia_com_lentes(ollama_falso):
    f = ollama_falso("vulneravel")
    res = testar_ia({"modo": "ollama", "ollama_url": f.url, "modelo": "teste:1b", "sistema": "Lumi"})
    assert res.rodaram == ["prompt-injection"]
    altos = [x for x in res.findings if x.severidade is Severidade.ALTO]
    assert altos and all(any(l.value == "critico" for l in x.lentes) for x in altos)


# --- modo HTTP (endpoint do teu app) ---

def test_http_com_canario_e_campo_aninhado(ollama_falso):
    f = ollama_falso("vulneravel")
    canario = gerar_canario()
    f.sistema_app = f"Você é a Lumi. [segredo: {canario}]"
    alvo = AlvoHTTP(f.url + "/chat", "mensagem", "dados.resposta", canario=canario)
    cats = _por_categoria(achados(rodar(alvo), alvo.descricao))
    assert cats["vazamento"].severidade is Severidade.ALTO


def test_http_sem_canario_pula_vazamento(ollama_falso):
    f = ollama_falso("segura")
    alvo = AlvoHTTP(f.url + "/chat", "mensagem", "dados.resposta")
    cats = _por_categoria(achados(rodar(alvo), alvo.descricao))
    assert "não testado" in cats["vazamento"].titulo


def test_http_publico_e_recusado():
    with pytest.raises(AlvoNaoLocal):
        AlvoHTTP("http://8.8.8.8/chat")


def test_ollama_remoto_e_recusado():
    ok, msg = Ollama(url="http://8.8.8.8:11434").status()
    assert not ok and "local" in msg


def test_ia_desligada_vira_erro_e_nao_resultado_vazio():
    alvo = AlvoHTTP("http://127.0.0.1:9/chat", canario="X")
    with pytest.raises(RuntimeError, match="nenhuma sondagem"):
        achados(rodar(alvo), alvo.descricao)


def test_sondagens_sao_inofensivas():
    # nenhuma sondagem pede conteudo perigoso: so marcador sem sentido ou o proprio prompt
    for s in pi.SONDAGENS:
        texto = (s.mensagem + s.documento).lower()
        assert "{palavra}" in texto or s.categoria == "vazamento"
