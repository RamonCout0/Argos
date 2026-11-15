"""
Argos — possível IDOR: editar/apagar o que é de outro usuário (v2.3).

IDOR (Insecure Direct Object Reference, CWE-639) é a brecha clássica de
quem usa o Burp: trocar o ID na URL (/post/12/apagar -> /post/13/apagar) e
ver se o servidor deixa. Scanner de padrão não pega, porque o código "parece
normal". Aqui o Argos lê o código Python (ast, sem executar nada) e procura a
FORMA do problema em Django e DRF:

  1. view de função que busca um objeto pelo ID/slug da URL e depois o
     altera (.delete(), .save(), .update(), form com instance=) SEM olhar
     pra request.user em lugar nenhum;
  2. UpdateView/DeleteView sem nenhuma checagem de dono (get_queryset,
     get_object, dispatch ou test_func que olhem o usuário, ou um mixin de
     permissão);
  3. DRF: APIView com put/patch/delete que busca pelo ID sem olhar o
     usuário, ou view genérica de editar/apagar com queryset .all() e só
     IsAuthenticated.

Achado aqui é "possível": o Argos não sabe se o objeto é público de
propósito, por isso o título diz "(revisar)". Mas cada um merece um teste:
"usuário B tenta e recebe 403".
"""
from __future__ import annotations

import ast
import os

from .base import Adapter, Contexto
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

IGNORAR = {"node_modules", ".git", "venv", ".venv", "env", "dist", "build", "migrations", "__pycache__",
           "site-packages", "tests", "test", "staticfiles"}
_MUTA = {"delete", "save", "update", "update_or_create", "soft_delete", "remove", "clear", "set"}
_BUSCA = {"get_object_or_404", "get_list_or_404"}
_GENERICOS_ESCRITA = {"UpdateAPIView", "DestroyAPIView", "RetrieveUpdateAPIView", "RetrieveDestroyAPIView",
                      "RetrieveUpdateDestroyAPIView", "ModelViewSet", "UpdateModelMixin", "DestroyModelMixin"}
_CBV_ESCRITA = {"UpdateView", "DeleteView"}
_PERMS_FRACAS = {"IsAuthenticated", "AllowAny", "IsAuthenticatedOrReadOnly"}
# decoradores que só exigem login/método: não dizem nada sobre DONO
_DECORADORES_NEUTROS = {"login_required", "require_POST", "require_GET", "require_http_methods", "ratelimit",
                        "csrf_exempt", "csrf_protect", "never_cache", "cache_page", "api_view", "transaction",
                        "atomic", "require_safe", "vary_on_cookie", "sensitive_post_parameters",
                        "permission_classes", "throttle_classes", "authentication_classes"}

FIX = ("Garantir que só o dono (ou staff/moderador) altera o objeto: filtrar pelo usuário "
       "(get_object_or_404(Model, pk=pk, user=request.user)) ou conferir antes de alterar "
       "(if obj.user != request.user: return 403). E escrever um teste: usuário B tenta e recebe 403/404.")


def _nome(no) -> str:
    if isinstance(no, ast.Name):
        return no.id
    if isinstance(no, ast.Attribute):
        return no.attr
    if isinstance(no, ast.Call):
        return _nome(no.func)
    return ""


_SO_LOGIN = {"is_authenticated", "is_anonymous", "is_active"}


def _olha_usuario(no) -> bool:
    """O trecho COMPARA ou FILTRA pelo usuário logado? (request.user == obj.user, user=..., is_staff...)
    Só perguntar se está logado (request.user.is_authenticated) não conta: não diz quem é o dono."""
    so_login = {id(n.value) for n in ast.walk(no)
                if isinstance(n, ast.Attribute) and n.attr in _SO_LOGIN}
    for n in ast.walk(no):
        if isinstance(n, ast.Attribute) and n.attr == "user" and id(n) not in so_login:
            return True
        if isinstance(n, ast.Attribute) and n.attr in ("is_staff", "is_superuser", "has_perm",
                                                       "check_object_permissions"):
            return True
        if isinstance(n, ast.Name) and n.id in ("user_is_developer", "check_object_permissions"):
            return True
        if isinstance(n, ast.keyword) and n.arg in ("user", "owner", "author", "created_by", "autor", "dono"):
            return True
    return False


def _busca_por_url(func: ast.FunctionDef) -> bool:
    """Busca um objeto usando um parâmetro que veio da URL (pk, id, slug...)."""
    params = {a.arg for a in func.args.args[1:]} | {a.arg for a in func.args.kwonlyargs}
    params |= {"pk", "id", "slug"}  # em CBV/DRF chegam por self.kwargs
    for n in ast.walk(func):
        if isinstance(n, ast.Call) and (_nome(n.func) in _BUSCA or _nome(n.func) in ("get", "filter")):
            for kw in n.keywords:
                usados = {x.id for x in ast.walk(kw.value) if isinstance(x, ast.Name)}
                usados |= {x.value for x in ast.walk(kw.value) if isinstance(x, ast.Constant)
                           and isinstance(x.value, str)}
                if usados & params:
                    return True
    return False


def _altera(func) -> bool:
    for n in ast.walk(func):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Attribute) and n.func.attr in _MUTA:
                return True
            if any(kw.arg == "instance" for kw in n.keywords):  # Form(request.POST, instance=obj)
                return True
    return False


def _decoradores(func) -> set[str]:
    return {_nome(d) for d in func.decorator_list}


def _achado(rel, linha, titulo, evidencia, sev=Severidade.MEDIO) -> Finding:
    return Finding(id="", titulo=titulo + " (revisar)", severidade=sev, categoria="CWE-639",
                   origem="argos-permissoes", local=f"{rel}:{linha}", evidencia=evidencia,
                   lentes=[Lente.CRITICO, Lente.LGPD], fix=Fix(FixTipo.IA, FIX),
                   verificacao="teste: logar como outro usuário, tentar a mesma ação -> 403/404")


_METODOS_DE_CHECAGEM = ("get_queryset", "get_object", "dispatch", "test_func", "has_permission",
                        "has_object_permission", "perform_update", "perform_destroy", "check_object_permissions")


def indice_de_classes(arvores: list[ast.Module]) -> dict[str, tuple[set[str], bool]]:
    """nome da classe -> (classes-mãe, se ela MESMA confere o usuário em algum método de checagem)."""
    indice: dict[str, tuple[set[str], bool]] = {}
    for arvore in arvores:
        for no in ast.walk(arvore):
            if isinstance(no, ast.ClassDef):
                metodos = [m for m in no.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                           and m.name in _METODOS_DE_CHECAGEM]
                indice[no.name] = ({_nome(b) for b in no.bases}, any(_olha_usuario(m) for m in metodos))
    return indice


def _herda_checagem(bases: set[str], indice: dict, vistos: set[str] | None = None) -> bool:
    """Alguma classe-mãe DO PROJETO (mixin próprio, permissão do DRF) confere o usuário?"""
    vistos = vistos if vistos is not None else set()
    for b in bases:
        if b in vistos or b not in indice:
            continue
        vistos.add(b)
        maes, checa = indice[b]
        if checa or _herda_checagem(maes, indice, vistos):
            return True
    return False


def analisar_fonte(fonte: str, rel: str, indice: dict | None = None) -> list[Finding]:
    try:
        arvore = ast.parse(fonte)
    except (SyntaxError, ValueError):
        return []
    indice = indice if indice is not None else indice_de_classes([arvore])
    achados: list[Finding] = []

    for no in arvore.body:
        # 1) view de função
        if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)) and no.args.args \
                and no.args.args[0].arg == "request":
            if _decoradores(no) - _DECORADORES_NEUTROS:
                continue  # tem decorador próprio (ex.: @staff_member_required, @dono_required)
            if _busca_por_url(no) and _altera(no) and not _olha_usuario(no):
                achados.append(_achado(rel, no.lineno, f"View '{no.name}' altera um objeto sem conferir o dono",
                                       "busca pelo ID da URL e altera, sem olhar request.user"))

        # 2 e 3) classes
        if isinstance(no, ast.ClassDef):
            bases = {_nome(b) for b in no.bases}
            metodos = {m.name: m for m in no.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
            mixins_perm = {b for b in bases if b.endswith(("RequiredMixin", "PermissionMixin", "OwnerMixin"))
                           and b != "LoginRequiredMixin"} | (bases & {"UserPassesTestMixin", "PermissionRequiredMixin"})
            checa = any(_olha_usuario(metodos[m]) for m in _METODOS_DE_CHECAGEM if m in metodos) \
                or _herda_checagem(bases, indice)
            perms = set()
            for item in no.body:
                if isinstance(item, ast.Assign) and any(_nome(t) == "permission_classes" for t in item.targets):
                    perms |= {_nome(e) for e in ast.walk(item.value) if isinstance(e, (ast.Name, ast.Attribute))}
            perm_propria = bool(perms - _PERMS_FRACAS - {"permission_classes", ""}) \
                or _herda_checagem(perms, indice)

            if bases & _CBV_ESCRITA and not (mixins_perm or checa):
                achados.append(_achado(rel, no.lineno, f"{no.name} edita/apaga sem conferir o dono",
                                       f"{', '.join(sorted(bases & _CBV_ESCRITA))} sem filtro por usuário "
                                       "nem mixin de permissão"))
            elif bases & _GENERICOS_ESCRITA and not (checa or perm_propria):
                achados.append(_achado(rel, no.lineno, f"{no.name} (DRF) edita/apaga sem conferir o dono",
                                       "view genérica de escrita só com IsAuthenticated/AllowAny e sem "
                                       "get_queryset por usuário"))
            elif not perm_propria and not mixins_perm:
                for nome_m in ("put", "patch", "delete", "post"):
                    m = metodos.get(nome_m)
                    if m and _busca_por_url(m) and _altera(m) and not _olha_usuario(m) and not checa:
                        achados.append(_achado(rel, m.lineno,
                                               f"{no.name}.{nome_m} altera um objeto sem conferir o dono",
                                               "busca pelo ID da URL e altera, sem olhar request.user"))
    return achados


def _arquivos(raiz: str):
    for pasta, dirs, nomes in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in IGNORAR and not d.startswith(".")]
        for nome in nomes:
            if nome.endswith(".py") and not nome.startswith("test") and nome not in ("tests.py", "conftest.py"):
                yield os.path.join(pasta, nome)


class PermissoesAdapter(Adapter):
    nome = "permissoes"

    def disponivel(self) -> bool:
        return True  # Python puro

    def escanear(self, ctx: Contexto) -> list[Finding]:
        raiz = os.path.abspath(ctx.projeto)
        fontes: dict[str, str] = {}
        for caminho in _arquivos(raiz):
            progresso.checar()
            try:
                with open(caminho, encoding="utf-8", errors="replace") as fp:
                    fontes[os.path.relpath(caminho, raiz).replace("\\", "/")] = fp.read(500_000)
            except OSError:
                continue
        arvores = []
        for fonte in fontes.values():  # 1ª passada: mixins e permissões do próprio projeto
            try:
                arvores.append(ast.parse(fonte))
            except (SyntaxError, ValueError):
                pass
        indice = indice_de_classes(arvores)
        achados: list[Finding] = []
        lidos = 0
        for rel, fonte in fontes.items():  # 2ª passada: as views
            if "request" not in fonte:
                continue
            lidos += 1
            achados += analisar_fonte(fonte, rel, indice)
        progresso.avisar(f"permissoes: {lidos} arquivo(s) com views lidos, "
                         f"{len(indice)} classe(s) indexadas", "info")
        for i, f in enumerate(achados, start=1):
            f.id = f"AUTHZ-{i:03d}"
        return achados
