"""v3.1: privilégio, mass assignment, vazamento privado, upload, histórico, CI e trava no Actions."""
import io
import json
import os
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.ataque import executar  # noqa: E402
from argos.ataque.ataques_extra import forms_de_conteudo, PNG_VALIDO  # noqa: E402
from argos.guard import ativo  # noqa: E402
from argos import ci  # noqa: E402
from argos.gui import estado as est  # noqa: E402
from argos.schema import Finding, Severidade  # noqa: E402

tem_django = subprocess.run([sys.executable, "-c", "import django"], capture_output=True).returncode == 0

FORM = '''
def _form(request, campos, arquivo=False):
    from django.middleware.csrf import get_token
    enc = ' enctype="multipart/form-data"' if arquivo else ""
    html = f'<form method="post" action="/sair/"><input type="hidden" name="csrfmiddlewaretoken" value="{get_token(request)}"></form>'
    html += f'<form method="post"{enc}><input type="hidden" name="csrfmiddlewaretoken" value="{get_token(request)}">'
    html += "".join(f'<input name="{c}" value="">' for c in campos)
    if arquivo:
        html += '<input type="file" name="arquivo">'
    return HttpResponse("<html><body>" + html + "</form></body></html>")
'''

VIEWS = {
    "vulneravel": '''
        from django.contrib.auth.decorators import login_required
        from django.http import HttpResponse
        from django.shortcuts import redirect
        from .models import Nota, Mensagem, Anexo
        # FORM

        @login_required
        def nota_nova(request):          # a TELA barra quem não é staff, o POST não
            if request.method == "POST":
                Nota.objects.create(user=request.user, texto=request.POST.get("texto", ""))
                return HttpResponse("ok")
            if not request.user.is_staff:
                return redirect("/")
            return _form(request, ["texto"])

        @login_required
        def nota_minha(request):         # o dono vem do formulário (mass assignment)
            if request.method == "POST":
                Nota.objects.create(user_id=request.POST.get("user") or request.user.id,
                                    texto=request.POST.get("texto", ""))
                return HttpResponse("ok")
            return _form(request, ["texto"])

        @login_required
        def caixa(request):              # lista as mensagens de TODO MUNDO
            return HttpResponse("<html>" + " | ".join(m.texto for m in Mensagem.objects.all()) + "</html>")

        @login_required
        def anexo(request):              # aceita qualquer arquivo
            if request.method == "POST" and request.FILES.get("arquivo"):
                Anexo.objects.create(user=request.user, arquivo=request.FILES["arquivo"])
                return HttpResponse("ok")
            return _form(request, ["titulo"], arquivo=True)
    ''',
    "seguro": '''
        from django.contrib.auth.decorators import login_required
        from django.http import HttpResponse, HttpResponseForbidden
        from django.shortcuts import redirect
        from django.utils.html import escape
        from .models import Nota, Mensagem, Anexo
        # FORM

        @login_required
        def nota_nova(request):
            if not request.user.is_staff:
                return redirect("/") if request.method == "GET" else HttpResponseForbidden()
            if request.method == "POST":
                Nota.objects.create(user=request.user, texto=request.POST.get("texto", ""))
                return HttpResponse("ok")
            return _form(request, ["texto"])

        @login_required
        def nota_minha(request):
            if request.method == "POST":
                Nota.objects.create(user=request.user, texto=request.POST.get("texto", ""))
                return HttpResponse("ok")
            return _form(request, ["texto"])

        @login_required
        def caixa(request):
            return HttpResponse("<html>" + " | ".join(escape(m.texto) for m in
                                                       Mensagem.objects.filter(remetente=request.user)) + "</html>")

        @login_required
        def anexo(request):
            f = request.FILES.get("arquivo")
            if request.method == "POST" and f:
                if not f.name.lower().endswith((".png", ".jpg", ".jpeg", ".webp")) or f.size > 5_000_000:
                    return HttpResponse("arquivo recusado", status=400)
                Anexo.objects.create(user=request.user, arquivo=f)
                return HttpResponse("ok")
            return _form(request, ["titulo"], arquivo=True)
    ''',
}


def _projeto(raiz, tipo):
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
                              "django.contrib.sessions", "app"]
            MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
                          "django.middleware.csrf.CsrfViewMiddleware",
                          "django.contrib.auth.middleware.AuthenticationMiddleware"]
            ROOT_URLCONF = "site_mini.urls"
            USE_TZ = True
        ''',
        "site_mini/urls.py": '''
            from django.urls import path
            from app import views
            urlpatterns = [path("nota/nova/", views.nota_nova, name="nota_nova"),
                           path("nota/minha/", views.nota_minha, name="nota_minha"),
                           path("caixa/", views.caixa, name="caixa"),
                           path("anexo/", views.anexo, name="anexo")]
        ''',
        "app/__init__.py": "",
        "app/models.py": '''
            from django.conf import settings
            from django.db import models

            class Nota(models.Model):
                user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
                texto = models.TextField()

            class Mensagem(models.Model):
                remetente = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
                texto = models.TextField()

            class Anexo(models.Model):
                user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
                arquivo = models.FileField(upload_to="anexos", blank=True)
        ''',
        "app/views.py": VIEWS[tipo],
    }
    for nome, conteudo in arquivos.items():
        caminho = raiz / nome
        caminho.parent.mkdir(parents=True, exist_ok=True)
        texto = textwrap.dedent(conteudo).replace("# FORM\n", FORM)
        caminho.write_text(texto, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(raiz)], check=True)
    subprocess.run(["git", "-C", str(raiz), "remote", "add", "origin", "https://github.com/ramon/mini.git"], check=True)


@pytest.mark.skipif(not tem_django, reason="Django não instalado neste Python")
@pytest.mark.parametrize("tipo", ["vulneravel", "seguro"])
def test_ataques_v31_de_verdade(tmp_path, tipo):
    _projeto(tmp_path, tipo)
    achados = executar.atacar(str(tmp_path), sem_carga=True, buscar_dono=lambda d, r: {"admin": True})
    cats = {f.categoria for f in achados if f.severidade.value in ("critico", "alto", "medio")}
    titulos = [f.titulo for f in achados]
    if tipo == "vulneravel":
        assert "CWE-269" in cats, titulos   # escalada: tela barra, POST passa
        assert "CWE-915" in cats, titulos   # mass assignment: dono vindo do form
        assert "CWE-639" in cats, titulos   # mensagem do A na caixa do B
        assert "CWE-434" in cats, titulos   # SVG com script aceito de usuário comum
    else:
        assert cats == set(), titulos


def test_forms_de_conteudo_pula_o_logout():
    html = ('<form method="post" action="/contas/logout/"><input name="csrfmiddlewaretoken" value="x"></form>'
            '<form method="post"><input name="csrfmiddlewaretoken" value="x"><input name="titulo">'
            '<input type="file" name="capa"></form>')
    fs = forms_de_conteudo(html, "/novo/")
    assert len(fs) == 1 and "titulo" in fs[0]["campos"] and fs[0]["arquivos"] == ["capa"]


def test_png_de_teste_e_valido():
    pytest.importorskip("PIL")
    from PIL import Image
    Image.open(io.BytesIO(PNG_VALIDO)).verify()


# ------------------------------------------------------------------ histórico

def test_historico_da_nota():
    estado = {}
    f = Finding(id="X", titulo="t", severidade=Severidade.ALTO, categoria="CWE-79", origem="o", local="a.py:1")
    est.registrar_scan(estado, "proj", [f])
    est.registrar_scan(estado, "proj", [])
    h = est.historico(estado, "proj")
    assert [x["nota"] for x in h] == [80, 100] and h[0]["aprovado"] is False and h[1]["aprovado"] is True


# ------------------------------------------------------------------ GitHub Actions

def test_workflow_acha_requirements_do_backend(tmp_path):
    (tmp_path / "src" / "backend").mkdir(parents=True)
    (tmp_path / "src" / "backend" / "manage.py").write_text("")
    (tmp_path / "src" / "backend" / "requirements.txt").write_text("django\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "requirements.txt").write_text("mkdocs\n")
    destino = ci.gerar(str(tmp_path))
    texto = open(destino, encoding="utf-8").read()
    assert "venv/bin/pip install -r src/backend/requirements.txt" in texto
    assert "cli.py atacar ." in texto and "GITHUB_TOKEN" in texto
    with pytest.raises(FileExistsError):
        ci.gerar(str(tmp_path))
    yaml = pytest.importorskip("yaml")
    assert "argos" in yaml.safe_load(texto)["jobs"]


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_trava_no_actions_prova_a_execucao(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "Ramon/Mini")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setattr(ativo.urllib.request, "urlopen", lambda req, timeout=0: _Resp(
        json.dumps({"id": 42, "repository": {"full_name": "ramon/mini"}}).encode()))
    assert ativo._execucao_do_actions("ramon", "mini")["admin"] is True
    # execução de OUTRO repositório não vale
    monkeypatch.setenv("GITHUB_REPOSITORY", "outra/pessoa")
    assert ativo._execucao_do_actions("ramon", "mini")["admin"] is False


def test_fora_do_actions_nao_usa_o_caminho_de_ci(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert ativo._execucao_do_actions("ramon", "mini") is None
