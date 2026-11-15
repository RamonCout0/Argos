"""v2.3: menos ruído (gerado/teste/framework/auditoria) e detector de IDOR."""
import os
import sys
import textwrap
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.core import ruido  # noqa: E402
from argos.adapters import semgrep as sg, permissoes as pm, django_deploy as dj  # noqa: E402
from argos.adapters.base import Contexto  # noqa: E402
from argos.schema import Finding, Severidade  # noqa: E402


def _f(local, sev=Severidade.ALTO, cat="CWE-79", origem="semgrep"):
    return Finding(id="X", titulo="t", severidade=sev, categoria=cat, origem=origem, local=local, evidencia="")


# ------------------------------------------------------------------ ruído

def test_codigo_gerado_sai_do_relatorio():
    fs = [_f("frontend_build/browser/main-ABCD1234.js:1"), _f("static/js/app.min.js:3"),
          _f("frontend/dist/chunk-XYZ.js:9"), _f("portal/views/social.py:12")]
    ficam, gerados, _ = ruido.filtrar(fs)
    assert gerados == 3 and [f.local for f in ficam] == ["portal/views/social.py:12"]


def test_segredo_em_teste_vira_info_e_resto_baixo():
    senha = _f("portal/tests.py:40", Severidade.CRITICO, "CWE-798", "gitleaks")
    padrao = _f("frontend/src/app/auth.spec.ts:7", Severidade.ALTO)
    http = _f("docs/api-testes.http:16", Severidade.CRITICO, "CWE-798", "gitleaks")
    ficam, _, rebaixados = ruido.filtrar([senha, padrao, http])
    assert senha.severidade == Severidade.INFO and padrao.severidade == Severidade.BAIXO
    assert http.severidade == Severidade.INFO
    assert rebaixados == 3 and all(f.titulo.endswith("(arquivo de teste)") for f in ficam)


def test_web_e_dependencias_nao_passam_pelo_filtro():
    web = _f("http://127.0.0.1:8000/build/x.js")
    dep = _f("requirements.txt:django", cat="CVE-2024-1")
    ficam, gerados, rebaixados = ruido.filtrar([web, dep])
    assert len(ficam) == 2 and gerados == rebaixados == 0


# ------------------------------------------------------------------ semgrep

def _res(check_id, sev="ERROR", sub=None, conf=None, path="portal/views.py"):
    meta = {"cwe": ["CWE-89: SQL Injection"]}
    if sub:
        meta["subcategory"] = sub
    if conf:
        meta["confidence"] = conf
    return {"check_id": check_id, "path": path, "start": {"line": 3},
            "extra": {"severity": sev, "message": "msg", "metadata": meta}}


def test_semgrep_descarta_regra_de_framework_ausente():
    dados = {"results": [_res("python.sqlalchemy.performance.len-all-count"),
                         _res("python.django.security.injection.sql")]}
    fs = sg.parse_relatorio(dados, deps={"django", "djangorestframework"})
    assert [f.evidencia for f in fs] == ["python.django.security.injection.sql"]


def test_semgrep_auditoria_e_baixa_confianca_viram_revisar():
    dados = {"results": [_res("a.b.vuln", sub=["vuln"], conf="HIGH"),
                         _res("a.b.audit", sub=["audit"], conf="MEDIUM"),
                         _res("a.b.audit-low", sub=["audit"], conf="LOW")]}
    vuln, audit, audit_low = sg.parse_relatorio(dados)
    assert vuln.severidade == Severidade.ALTO and "(revisar)" not in vuln.titulo
    assert audit.severidade == Severidade.BAIXO and audit.titulo.endswith("(revisar)")
    assert audit_low.severidade == Severidade.INFO


def test_semgrep_regras_pela_stack(tmp_path):
    (tmp_path / "manage.py").write_text("")
    (tmp_path / "requirements.txt").write_text("Django>=5.2,<5.3\ndjangorestframework\n")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text('{"dependencies": {"@angular/core": "^20"}}')
    deps = sg.dependencias_do_projeto(str(tmp_path))
    assert {"django", "djangorestframework", "@angular/core"} <= deps
    regras = sg.regras_do_projeto(str(tmp_path), deps)
    assert regras == ["p/python", "p/django", "p/javascript", "p/typescript"]
    assert "p/default" not in regras and "p/secrets" not in regras


def test_semgrep_erro_de_rede_vira_mensagem_clara():
    proc = types.SimpleNamespace(stdout="", stderr="requests.exceptions.ProxyError: HTTPSConnectionPool("
                                                   "host='semgrep.dev', port=443): Max retries exceeded")
    assert "semgrep.dev" in sg.mensagem_de_erro(proc) and "internet" in sg.mensagem_de_erro(proc)
    proc2 = types.SimpleNamespace(stdout='{"errors": [{"message": "Invalid rule schema"}]}', stderr="")
    assert sg.mensagem_de_erro(proc2) == "Invalid rule schema"


def test_semgrep_exclui_gerado_e_testes():
    for padrao in ("frontend_build", "*.min.js", "tests.py", "*.spec.ts", "migrations"):
        assert padrao in sg.EXCLUIR


# ------------------------------------------------------------------ IDOR

VULNERAVEL = textwrap.dedent('''
    from django.shortcuts import get_object_or_404
    from django.contrib.auth.decorators import login_required
    from django.views.generic import UpdateView
    from rest_framework.views import APIView
    from rest_framework.generics import RetrieveUpdateDestroyAPIView
    from rest_framework.permissions import IsAuthenticated

    @login_required
    def apagar_post(request, pk):
        post = get_object_or_404(Post, pk=pk)
        post.delete()

    @login_required
    def editar_post(request, pk):
        post = get_object_or_404(Post, pk=pk)
        form = PostForm(request.POST, instance=post)

    class PostEdit(LoginRequiredMixin, UpdateView):
        model = Post

    class PostApi(APIView):
        permission_classes = [IsAuthenticated]
        def delete(self, request, pk):
            Post.objects.get(pk=pk).delete()

    class PostGenerico(RetrieveUpdateDestroyAPIView):
        queryset = Post.objects.all()
        permission_classes = [IsAuthenticated]
''')

SEGURO = textwrap.dedent('''
    from django.shortcuts import get_object_or_404

    @login_required
    def apagar_post(request, pk):
        post = get_object_or_404(Post, pk=pk)
        if post.user != request.user and not request.user.is_staff:
            return HttpResponseForbidden()
        post.delete()

    @login_required
    def apagar_meu(request, pk):
        get_object_or_404(Post, pk=pk, user=request.user).delete()

    @login_required
    def curtir(request, pk):
        post = get_object_or_404(Post, pk=pk)
        PostLike.objects.get_or_create(post=post, user=request.user)

    @staff_member_required
    def apagar_qualquer(request, pk):
        get_object_or_404(Post, pk=pk).delete()

    def listar(request):
        return Post.objects.all()

    class DonoMixin:
        def dispatch(self, request, *a, **k):
            if self.get_object().user != request.user:
                raise PermissionDenied
            return super().dispatch(request, *a, **k)

    class PostEdit(DonoMixin, UpdateView):
        model = Post

    class PostEdit2(LoginRequiredMixin, UpdateView):
        def get_queryset(self):
            return Post.objects.filter(user=self.request.user)

    class EhDono(BasePermission):
        def has_object_permission(self, request, view, obj):
            return obj.user == request.user

    class PostGenerico(RetrieveUpdateDestroyAPIView):
        queryset = Post.objects.all()
        permission_classes = [IsAuthenticated, EhDono]
''')


def test_idor_pega_as_formas_classicas():
    fs = pm.analisar_fonte(VULNERAVEL, "portal/views.py")
    titulos = " | ".join(f.titulo for f in fs)
    assert len(fs) == 5, titulos
    assert all(f.categoria == "CWE-639" and f.titulo.endswith("(revisar)") for f in fs)


def test_idor_respeita_quem_confere_o_dono():
    fs = pm.analisar_fonte(SEGURO, "portal/views.py")
    assert fs == [], [f.titulo for f in fs]


def test_so_estar_logado_nao_conta_como_checar_o_dono():
    fonte = textwrap.dedent('''
        class SoLoginMixin:
            def dispatch(self, request, *a, **k):
                if not request.user.is_authenticated:
                    return redirect("/login")
                return super().dispatch(request, *a, **k)

        class CapituloEdit(SoLoginMixin, UpdateView):
            model = Capitulo
    ''')
    fs = pm.analisar_fonte(fonte, "views.py")
    assert len(fs) == 1 and "CapituloEdit" in fs[0].titulo


def test_idor_segue_mixin_de_outro_arquivo(tmp_path):
    (tmp_path / "base.py").write_text(textwrap.dedent('''
        class DonoMixin:
            def test_func(self):
                return self.get_object().autor == self.request.user
    '''))
    (tmp_path / "views.py").write_text(textwrap.dedent('''
        class Edita(DonoMixin, UpdateView):
            model = Obra
        def request_dummy(request): pass
    '''))
    assert pm.PermissoesAdapter().escanear(Contexto(projeto=str(tmp_path))) == []


# ------------------------------------------------------------------ django check

def test_check_deploy_tenta_de_novo_com_chave_temporaria(tmp_path, monkeypatch):
    (tmp_path / "manage.py").write_text("")
    chamadas = []

    def falso(cmd, timeout=None, **kw):
        chamadas.append(dict(kw["env"]))
        if "SECRET_KEY" not in kw["env"]:
            return types.SimpleNamespace(returncode=1, stdout="", stderr=(
                "django.core.exceptions.ImproperlyConfigured: Defina a variável de ambiente SECRET_KEY"))
        return types.SimpleNamespace(returncode=0, stdout="", stderr=(
            "?: (security.W021) You have not set the SECURE_HSTS_PRELOAD setting to True."))
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setattr(dj.progresso, "rodar", falso)
    fs = dj.DjangoDeployAdapter().escanear(Contexto(projeto=str(tmp_path)))
    assert len(chamadas) == 2 and len(chamadas[1]["SECRET_KEY"]) >= 50
    assert chamadas[0]["PYTHONUTF8"] == "1"
    assert [f.local for f in fs] == ["settings · security.W021"]
