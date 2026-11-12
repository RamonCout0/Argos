"""Ajustes vindos do uso real no Windows (v2.1)."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.ai import ollama as mod_ollama  # noqa: E402
from argos.ai.ollama import escolher_modelo, _limpar, Ollama  # noqa: E402
from argos.adapters import semgrep as mod_semgrep, pip_audit as mod_pip  # noqa: E402
from argos.adapters.base import Contexto  # noqa: E402


def test_escolhe_modelo_instalado_quando_o_padrao_falta():
    assert escolher_modelo(["qwen3:8b", "llama3.2:1b", "nomic-embed-text:latest"]) == "qwen3:8b"
    assert escolher_modelo(["llama3.2:1b", "llama3.2:3b"]) == "llama3.2:3b"
    assert escolher_modelo(["nomic-embed-text"]) is None


def test_status_troca_so_se_o_usuario_nao_escolheu(monkeypatch):
    monkeypatch.delenv("ARGOS_MODELO", raising=False)
    monkeypatch.setattr(mod_ollama, "carregar", lambda nome, padrao=None: padrao)
    monkeypatch.setattr(Ollama, "modelos", lambda self: ["qwen3:8b", "llama3.2:1b"])
    o = Ollama()
    ok, msg = o.status()
    assert ok and o.modelo == "qwen3:8b"
    fixo = Ollama(modelo="llama3.1:8b")
    ok, msg = fixo.status()
    assert not ok and "llama3.1:8b" in msg


def test_resposta_sem_raciocinio():
    assert _limpar("<think>hmm, vou pensar</think>\n Resposta final") == "Resposta final"


def test_semgrep_nao_usa_config_auto(monkeypatch, tmp_path):
    visto = {}

    def falso(cmd, **k):
        visto["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout='{"results": []}', stderr="")
    ad = mod_semgrep.SemgrepAdapter()
    ad._detectado, ad._modo = True, "native"
    monkeypatch.setattr(mod_semgrep.subprocess, "run", falso)
    ad.escanear(Contexto(projeto=str(tmp_path)))
    assert "auto" not in visto["cmd"] and "--metrics=off" in visto["cmd"]
    assert "p/default" in visto["cmd"]


def test_pip_audit_achado_como_modulo_do_venv(monkeypatch):
    import importlib.util
    monkeypatch.setattr(mod_pip.shutil, "which", lambda n, **k: None)
    monkeypatch.setattr(importlib.util, "find_spec", lambda n: object() if n == "pip_audit" else None)
    ad = mod_pip.PipAuditAdapter()
    assert ad.disponivel()
    assert ad._cmd() == [sys.executable, "-m", "pip_audit"]


def test_gitleaks_titulo_em_portugues_e_caminho_curto(tmp_path):
    from argos.adapters.gitleaks import parse_relatorio
    arq = tmp_path / "src" / "api.http"
    f = parse_relatorio([{"File": str(arq), "StartLine": 16, "RuleID": "generic-api-key",
                          "Secret": "93b7abcdef12bc", "Description": "Detected a Generic API Key"}],
                        raiz=str(tmp_path))[0]
    assert f.titulo == "Chave de API escrita no código"
    assert f.local == "src/api.http:16"
    assert "abcdef" not in f.evidencia
    outro = parse_relatorio([{"File": "x.py", "RuleID": "algo-novo", "Secret": "s"}])[0]
    assert outro.titulo == "Segredo escrito no código (algo novo)"


def test_gui_cai_na_classica_sem_gtk_no_linux(monkeypatch, capsys):
    import importlib.util
    import types
    import cli
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(importlib.util, "find_spec", lambda n: None)
    monkeypatch.setitem(sys.modules, "webview", types.ModuleType("webview"))
    chamado = {}
    monkeypatch.setattr(cli, "_gui_classica", lambda demo: chamado.setdefault("ok", 0))
    args = types.SimpleNamespace(demo=False, classico=False)
    assert cli.cmd_gui(args) == 0 and "ok" in chamado
    assert "python3-gi" in capsys.readouterr().out
