"""Fase 7 — modo ataque: a trava e uma rodada de verdade num mini projeto Django."""
import os
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.guard import ativo  # noqa: E402
from argos.guard.ativo import AtaqueRecusado, confirmar_dono, exigir_loopback  # noqa: E402
from argos.ataque.ataques import Sessao, ler_form  # noqa: E402
from argos.ataque import executar  # noqa: E402
from argos.adapters.base import Contexto  # noqa: E402


def _git(pasta, origem="https://github.com/ramon/projeto.git"):
    subprocess.run(["git", "init", "-q", str(pasta)], check=True)
    subprocess.run(["git", "-C", str(pasta), "remote", "add", "origin", origem], check=True)


# ------------------------------------------------------------------ trava 1: repositório do dono

def test_recusa_pasta_sem_git(tmp_path):
    with pytest.raises(AtaqueRecusado, match="repositório git"):
        confirmar_dono(str(tmp_path), buscar=lambda d, r: {"admin": True})


def test_recusa_origin_fora_do_github(tmp_path):
    _git(tmp_path, "https://gitlab.com/ramon/projeto.git")
    with pytest.raises(AtaqueRecusado, match="GitHub"):
        confirmar_dono(str(tmp_path), buscar=lambda d, r: {"admin": True})


def test_recusa_quem_nao_e_admin(tmp_path):
    _git(tmp_path)
    with pytest.raises(AtaqueRecusado, match="NÃO é administrador"):
        confirmar_dono(str(tmp_path), buscar=lambda d, r: {"admin": False, "push": True})


def test_recusa_quando_nao_da_pra_perguntar_ao_github(tmp_path):
    _git(tmp_path)
    with pytest.raises(AtaqueRecusado, match="gh auth login"):
        confirmar_dono(str(tmp_path), buscar=lambda d, r: None)


def test_aceita_admin_e_le_dono_e_repo(tmp_path):
    _git(tmp_path, "git@github.com:RamonCout0/gatuno-de-estrelas.git")
    perguntado = {}

    def buscar(d, r):
        perguntado["alvo"] = (d, r)
        return {"admin": True}
    assert confirmar_dono(str(tmp_path), buscar=buscar) == "RamonCout0/gatuno-de-estrelas"
    assert perguntado["alvo"] == ("RamonCout0", "gatuno-de-estrelas")


def test_nao_existe_atalho_pra_pular_a_trava():
    fonte = open(ativo.__file__, encoding="utf-8").read() + open(executar.__file__, encoding="utf-8").read()
    for proibido in ("ARGOS_SEM_TRAVA", "ARGOS_FORCAR", "--forcar", "skip_guard", "pular_trava"):
        assert proibido not in fonte


def test_adapter_sempre_passa_pela_trava(tmp_path, monkeypatch):
    def recusa(*a, **k):
        raise AtaqueRecusado("não é teu")
    monkeypatch.setattr(executar, "confirmar_dono", recusa)
    with pytest.raises(RuntimeError, match="não é teu"):
        executar.AtaqueAdapter().escanear(Contexto(projeto=str(tmp_path)))


# ------------------------------------------------------------------ trava 2: só loopback

@pytest.mark.parametrize("url", ["http://10.0.0.5:8000", "http://192.168.0.10", "http://example.com",
                                 "http://localhost:8000", "https://gatunoestrelas.com.br"])
def test_so_loopback_literal(url):
    with pytest.raises(AtaqueRecusado):
        exigir_loopback(url)
    with pytest.raises(AtaqueRecusado):
        Sessao(url, "x")


def test_sessao_so_usa_caminho_relativo():
    s = Sessao("http://127.0.0.1:9", "x")
    with pytest.raises(ValueError):
        s.pedir("GET", "http://example.com/")


def test_ler_form():
    html = ('<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="t">'
            '<input name="titulo" value="oi"><textarea name="corpo">texto</textarea>'
            '<select name="tipo"><option value="a">A</option><option value="b" selected>B</option></select>'
            '<input type="checkbox" name="pub"><input type="file" name="img"></form>')
    assert ler_form(html) == {"csrfmiddlewaretoken": "t", "titulo": "oi", "corpo": "texto", "tipo": "b"}


# ------------------------------------------------------------------ rodada de verdade

VIEWS = {
    "vulneravel": '''
        from django.contrib.auth.decorators import login_required
        from django.http import HttpResponse
        from django.shortcuts import get_object_or_404
        from .models import Nota

        @login_required
        def apagar(request, pk):
            get_object_or_404(Nota, pk=pk).delete()
            return HttpResponse("ok")

        def ver(request, pk):
            nota = get_object_or_404(Nota, pk=pk)
            return HttpResponse(f"<html><body>{nota.texto}</body></html>")
    ''',
    "seguro": '''
        from django.contrib.auth.decorators import login_required
        from django.http import HttpResponse
        from django.shortcuts import get_object_or_404
        from django.utils.html import escape
        from .models import Nota

        @login_required
        def apagar(request, pk):
            get_object_or_404(Nota, pk=pk, user=request.user).delete()
            return HttpResponse("ok")

        def ver(request, pk):
            nota = get_object_or_404(Nota, pk=pk)
            return HttpResponse(f"<html><body>{escape(nota.texto)}</body></html>")
    ''',
}


def _mini_projeto(raiz, tipo, subpasta=""):
    arquivos = {
        "manage.py": '''
            import os, sys
            os.environ.setdefault("DJANGO_SETTINGS_MODULE", "site_mini.settings")
            from django.core.management import execute_from_command_line
            execute_from_command_line(sys.argv)
        ''',
        "site_mini/__init__.py": "",
        "site_mini/settings.py": '''
            SECRET_KEY = "mini"
            DEBUG = True
            ALLOWED_HOSTS = ["*"]
            INSTALLED_APPS = ["django.contrib.contenttypes", "django.contrib.auth",
                              "django.contrib.sessions", "notas"]
            MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
                          "django.middleware.csrf.CsrfViewMiddleware",
                          "django.contrib.auth.middleware.AuthenticationMiddleware"]
            ROOT_URLCONF = "site_mini.urls"
            USE_TZ = True
        ''',
        "site_mini/urls.py": '''
            from django.urls import path
            from notas import views
            urlpatterns = [path("notas/<int:pk>/", views.ver, name="nota_ver"),
                           path("notas/<int:pk>/apagar/", views.apagar, name="nota_apagar")]
        ''',
        "notas/__init__.py": "",
        "notas/models.py": '''
            from django.conf import settings
            from django.db import models

            class Nota(models.Model):
                user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
                texto = models.TextField()
        ''',
        "notas/views.py": VIEWS[tipo],
    }
    for nome, conteudo in arquivos.items():
        caminho = raiz / subpasta / nome if subpasta else raiz / nome
        caminho.parent.mkdir(parents=True, exist_ok=True)
        caminho.write_text(textwrap.dedent(conteudo), encoding="utf-8")
    _git(raiz)


tem_django = subprocess.run([sys.executable, "-c", "import django"], capture_output=True).returncode == 0


@pytest.mark.skipif(not tem_django, reason="Django não instalado neste Python")
@pytest.mark.parametrize("tipo", ["vulneravel", "seguro"])
def test_ataque_de_verdade(tmp_path, tipo):
    _mini_projeto(tmp_path, tipo)
    achados = executar.atacar(str(tmp_path), sem_carga=True, buscar_dono=lambda d, r: {"admin": True})
    cats = {(f.categoria, f.severidade.value) for f in achados}
    if tipo == "vulneravel":
        assert ("CWE-639", "critico") in cats, [f.titulo for f in achados]   # B apagou a nota do A
        assert ("CWE-79", "alto") in cats, [f.titulo for f in achados]       # marcador voltou sem escape
    else:
        graves = [f for f in achados if f.severidade.value in ("critico", "alto", "medio")]
        assert graves == [], [f.titulo for f in graves]


@pytest.mark.skipif(not tem_django, reason="Django não instalado neste Python")
def test_django_mais_angular_backend_em_subpasta(tmp_path):
    """Formato do tevejo: .git na raiz, front Angular numa pasta, Django em src/backend_django."""
    _mini_projeto(tmp_path, "vulneravel", subpasta="src/backend_django")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text('{"dependencies": {"@angular/core": "^20"}}')
    (tmp_path / ".env").write_text("CHAVE_DE_VERDADE=nao-pode-vazar\n")
    achados = executar.atacar(str(tmp_path), sem_carga=True, buscar_dono=lambda d, r: {"admin": True})
    assert ("CWE-639", "critico") in {(f.categoria, f.severidade.value) for f in achados}


def test_raiz_do_repositorio_sobe_ate_o_git(tmp_path):
    _git(tmp_path)
    fundo = tmp_path / "src" / "backend_django"
    fundo.mkdir(parents=True)
    assert executar.raiz_do_repositorio(str(fundo)) == str(tmp_path)
