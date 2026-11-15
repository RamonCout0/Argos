"""
Argos — laboratório Django (roda DENTRO do Python do projeto atacado).

Não importa nada do Argos: é executado com o venv do projeto, com o settings
sobreposto pelo Argos (banco SQLite novo e descartável, cache em memória,
sem e-mail/rede de verdade). Fala com o Argos por JSON no stdout.

  python lab_django.py preparar   -> migra, cria argos_a/argos_b, semeia dados
                                     de mentira, abre sessões e mapeia as URLs
  python lab_django.py estado     -> (JSON no stdin) os objetos ainda existem?
                                     o texto deles mudou?
"""
import datetime
import decimal
import json
import os
import random
import re
import string
import sys
import uuid
from importlib import import_module

import django

django.setup()

from django.apps import apps  # noqa: E402
from django.conf import settings  # noqa: E402
from django.contrib.auth import get_user_model, SESSION_KEY, BACKEND_SESSION_KEY, HASH_SESSION_KEY  # noqa: E402
from django.core.files.base import ContentFile  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.db import models, transaction  # noqa: E402
from django.urls import get_resolver, reverse, NoReverseMatch, URLPattern, URLResolver  # noqa: E402

User = get_user_model()
MODELOS_DO_PROJETO: set = set()
RAIZ = os.path.abspath(os.environ.get("ARGOS_PROJETO", os.getcwd()))
R = os.environ.get("ARGOS_MARCADOR") or "".join(random.choices("abcdef0123456789", k=6))
XSS = f"<argos-xss-{R}>"
TEXTO = f"argos {R} {XSS}"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000"
                    "1f15c4890000000d49444154789c6300010000050001a5f645400000000049454e44ae426082")
DONO_NOMES = ("user", "author", "autor", "created_by", "owner", "dono", "usuario", "sender", "remetente",
              "uploaded_by", "criado_por", "profile_user")
MUTACAO = re.compile(r"(edit|editar|update|atualiz|delete|apagar|excluir|remov|destroy|deletar|"
                     r"alterar|change|toggle|pin|fixar)", re.I)
EVITAR_ROTA = re.compile(r"(logout|sair|signout|static|media|__debug__|ws/|websocket|\.xml$|\.txt$|"
                         r"jsi18n|password/reset|confirm-email)", re.I)


def _rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def apps_do_projeto():
    for app in apps.get_app_configs():
        caminho = os.path.abspath(app.path)
        if caminho.startswith(RAIZ) and "site-packages" not in caminho:
            yield app


def campo_dono(model):
    fks = [f for f in model._meta.concrete_fields
           if isinstance(f, models.ForeignKey) and f.related_model is not None
           and issubclass(f.related_model, User)]
    for nome in DONO_NOMES:
        for f in fks:
            if f.name == nome:
                return f
    return fks[0] if fks else None


def valor(f):
    """Valor de mentira válido pro campo (texto sempre leva o marcador de XSS)."""
    if f.choices:
        return f.choices[0][0]
    if isinstance(f, models.EmailField):
        return f"argos-{_rand()}@example.invalid"
    if isinstance(f, models.URLField):
        return "https://example.com/argos"
    if isinstance(f, models.SlugField):
        return f"argos-{R}-{_rand(5)}"[: f.max_length or 50]
    if isinstance(f, (models.CharField, models.TextField)):
        maximo = getattr(f, "max_length", None) or 2000
        t = TEXTO if maximo >= len(TEXTO) + 6 else f"argos{R}"
        return (t + " " + _rand(4))[:maximo] if f.unique else t[:maximo]
    if isinstance(f, models.BooleanField):
        return False
    if isinstance(f, (models.PositiveIntegerField, models.PositiveSmallIntegerField,
                      models.PositiveBigIntegerField)):
        return random.randint(1, 900) if f.unique else 1
    if isinstance(f, models.IntegerField):
        return random.randint(1, 900) if f.unique else 1
    if isinstance(f, models.DecimalField):
        return decimal.Decimal("1")
    if isinstance(f, models.FloatField):
        return 1.0
    if isinstance(f, models.DateTimeField):
        from django.utils import timezone
        return timezone.now()
    if isinstance(f, models.DateField):
        return datetime.date.today()
    if isinstance(f, models.TimeField):
        return datetime.time(12, 0)
    if isinstance(f, models.DurationField):
        return datetime.timedelta(minutes=1)
    if isinstance(f, models.UUIDField):
        return uuid.uuid4()
    if isinstance(f, models.JSONField):
        return {}
    if isinstance(f, models.GenericIPAddressField):
        return "127.0.0.1"
    if isinstance(f, models.BinaryField):
        return b"argos"
    return None


def criar(model, dono, criados, prof=0):
    """Cria um objeto do modelo, dono = A. Devolve o objeto ou None (e o motivo)."""
    if prof > 3:
        return None, "profundidade"
    if model in criados:
        return criados[model], None
    kw = {}
    fdono = campo_dono(model)
    arquivos = {}
    for f in model._meta.concrete_fields:
        if f.primary_key or getattr(f, "auto_now", False) or getattr(f, "auto_now_add", False):
            continue
        if isinstance(f, models.ForeignKey):
            if fdono is not None and f.name == fdono.name:
                kw[f.name] = dono
            elif issubclass(f.related_model, User):
                kw[f.name] = dono if not f.null else None
                if kw[f.name] is None:
                    kw.pop(f.name)
            elif f.null:
                if f.related_model in criados:
                    kw[f.name] = criados[f.related_model]
            elif f.related_model not in MODELOS_DO_PROJETO:
                existente = f.related_model._default_manager.first()  # ex.: ContentType, Site, Group
                if existente is None:
                    return None, f"{f.name}: sem {f.related_model.__name__} pra usar"
                kw[f.name] = existente
            else:
                pai, motivo = criar(f.related_model, dono, criados, prof + 1)
                if pai is None:
                    return None, f"{f.name}: {motivo}"
                kw[f.name] = pai
            continue
        if isinstance(f, models.FileField):
            if not f.blank:
                arquivos[f.name] = ContentFile(PNG, name="argos.png")
            continue
        if f.has_default() and not isinstance(f, (models.CharField, models.TextField)):
            continue
        if f.null and not isinstance(f, (models.CharField, models.TextField)):
            continue  # opcional fica vazio (ex.: deleted_at preenchido = objeto já "apagado")
        v = valor(f)
        if v is None:
            if f.null or f.blank:
                continue
            return None, f"campo {f.name} ({type(f).__name__}) sem valor de teste"
        kw[f.name] = v
    try:
        with transaction.atomic():
            obj = model(**kw)
            for nome, conteudo in arquivos.items():
                getattr(obj, nome).save(conteudo.name, conteudo, save=False)
            obj.save()
    except Exception as e:  # noqa: BLE001 - modelo com regra própria: só não semeia
        return None, f"{type(e).__name__}: {str(e)[:120]}"
    criados[model] = obj
    return obj, None


def sessao(user):
    engine = import_module(settings.SESSION_ENGINE)
    s = engine.SessionStore()
    s[SESSION_KEY] = str(user.pk)
    s[BACKEND_SESSION_KEY] = settings.AUTHENTICATION_BACKENDS[0]
    s[HASH_SESSION_KEY] = user.get_session_auth_hash()
    s.create()
    return s.session_key


_REF_MODELO = [re.compile(r"get_object_or_404\(\s*(\w+)"), re.compile(r"\bmodel\s*=\s*(\w+)"),
               re.compile(r"\bqueryset\s*=\s*(\w+)\."), re.compile(r"\b(\w+)\.(?:objects|_default_manager)\b")]


def modelos_da_view(callback, por_nome):
    """Quais modelos a view busca? Lê o código da view (função ou classe) e acha
    get_object_or_404(Modelo...), model = Modelo, Modelo.objects..."""
    import inspect
    alvo = getattr(callback, "view_class", None) or getattr(callback, "cls", None) or callback
    alvo = getattr(alvo, "__wrapped__", alvo)
    try:
        fonte = inspect.getsource(alvo)
    except (OSError, TypeError):
        return []
    achados = []
    for rx in _REF_MODELO:
        for nome in rx.findall(fonte):
            m = por_nome.get(nome)
            if m is not None and m not in achados:
                achados.append(m)
    return achados


def padroes(resolver=None, prefixo="", ns=None):
    resolver = resolver or get_resolver()
    for p in resolver.url_patterns:
        rota = prefixo + str(p.pattern)
        if isinstance(p, URLResolver):
            novo_ns = ":".join(x for x in (ns, p.namespace) if x) or None
            yield from padroes(p, rota, novo_ns)
        elif isinstance(p, URLPattern) and p.name:
            nome = f"{ns}:{p.name}" if ns else p.name
            chaves = set(re.findall(r"<(?:\w+:)?(\w+)>", rota)) | set(re.findall(r"\(\?P<(\w+)>", rota))
            yield nome, rota, sorted(chaves), p.callback


def _valores(obj, chave, dono):
    """Valores candidatos pra uma chave da URL a partir do objeto (e dos pais dele)."""
    vals = []
    nome_modelo = obj._meta.model_name
    if chave in ("pk", "id") or chave in (f"{nome_modelo}_id", f"{nome_modelo}_pk"):
        vals.append(obj.pk)
    if chave in ("username", "user", "usuario") and dono is not None:
        vals.append(dono.get_username())
    if hasattr(obj, chave):
        v = getattr(obj, chave, None)
        if isinstance(v, (str, int)) and not callable(v):
            vals.append(v)
    for f in obj._meta.concrete_fields:
        if isinstance(f, models.ForeignKey):
            pai = getattr(obj, f.name, None)
            if pai is None:
                continue
            if chave in (f"{f.name}_id", f"{pai._meta.model_name}_id"):
                vals.append(pai.pk)
            if hasattr(pai, chave) and not issubclass(type(pai), User):
                v = getattr(pai, chave, None)
                if isinstance(v, (str, int)):
                    vals.append(v)
    if chave.endswith("_id") and not vals:
        vals.append(obj.pk)
    return list(dict.fromkeys(vals))


def preparar():
    call_command("migrate", interactive=False, verbosity=0, run_syncdb=True)
    senha = "Argos-" + _rand(12) + "!9"
    users = {}
    for nome in ("a", "b"):
        u = User.objects.create_user(username=f"argos_{nome}_{R}", email=f"argos-{nome}-{R}@example.invalid",
                                     password=senha)
        if nome == "a":
            # A é staff/superusuário só pra conseguir abrir os formulários de edição e copiar os
            # campos; quem ataca é o B, que é usuário comum.
            u.is_staff = u.is_superuser = True
            u.save(update_fields=["is_staff", "is_superuser"])
        users[nome] = u
    criados, falhas = {}, {}
    modelos = [m for app in apps_do_projeto() for m in app.get_models()
               if not m._meta.abstract and not m._meta.proxy and m._meta.managed]
    MODELOS_DO_PROJETO.update(modelos)
    for _ in range(3):  # algumas passadas: um modelo pode depender de outro criado depois
        for m in modelos:
            if m in criados:
                continue
            obj, motivo = criar(m, users["a"], criados)
            if obj is None:
                falhas[m._meta.label] = motivo
            else:
                falhas.pop(m._meta.label, None)
    objetos = []
    for m, obj in criados.items():
        fdono = campo_dono(m)
        dono_id = getattr(obj, fdono.attname) if fdono else None
        objetos.append({"modelo": m._meta.label, "pk": str(obj.pk), "dono_a": dono_id == users["a"].pk,
                        "textos": [f.name for f in m._meta.concrete_fields
                                   if isinstance(f, (models.CharField, models.TextField)) and not f.choices
                                   and not isinstance(f, (models.SlugField, models.EmailField, models.URLField))]})

    candidatos, sem_args = [], []
    vistos = set()
    por_nome = {m.__name__: m for m in apps.get_models()}
    for nome, rota, chaves, callback in padroes():
        if EVITAR_ROTA.search(rota) or EVITAR_ROTA.search(nome):
            continue
        if nome.startswith("admin:") or rota.startswith("admin/"):
            if not chaves and nome == "admin:index":
                sem_args.append({"url": reverse(nome), "nome": nome})
            continue  # o admin do Django é só staff: B e anônimo nem entram
        if not chaves:
            try:
                url = reverse(nome)
            except NoReverseMatch:
                continue
            if url not in vistos:
                vistos.add(url)
                sem_args.append({"url": url, "nome": nome})
            continue
        alvos = modelos_da_view(callback, por_nome)
        for m, obj in criados.items():
            if not alvos or not any(issubclass(m, a) for a in alvos[:2]):
                continue  # só o(s) modelo(s) que a view realmente busca
            fdono = campo_dono(m)
            dono = getattr(obj, fdono.name) if fdono else None
            kwargs = {}
            for c in chaves:
                vals = _valores(obj, c, dono)
                if not vals:
                    break
                kwargs[c] = vals[0]
            if len(kwargs) != len(chaves):
                continue
            try:
                url = reverse(nome, kwargs=kwargs)
            except NoReverseMatch:
                continue
            if url in vistos:
                continue
            vistos.add(url)
            candidatos.append({"url": url, "nome": nome, "rota": rota, "modelo": m._meta.label,
                               "pk": str(obj.pk), "dono_a": bool(dono is not None and dono.pk == users["a"].pk),
                               "mutacao": bool(MUTACAO.search(nome) or MUTACAO.search(rota)),
                               "api": "/api/" in url})

    login = None
    for nome in ("login", "account_login", "accounts:login", "users:login", "portal:login"):
        try:
            login = reverse(nome)
            break
        except NoReverseMatch:
            continue
    if login is None and str(getattr(settings, "LOGIN_URL", "")).startswith("/"):
        login = settings.LOGIN_URL
    print(json.dumps({
        "marcador": R, "xss": XSS, "senha": senha, "login_url": login,
        "usuarios": {k: {"id": u.pk, "username": u.get_username(), "email": u.email, "sessao": sessao(u)}
                     for k, u in users.items()},
        "objetos": objetos, "falhas_seed": falhas, "candidatos": candidatos, "rotas": sem_args,
        "sessao_cookie": settings.SESSION_COOKIE_NAME, "csrf_cookie": settings.CSRF_COOKIE_NAME,
    }, default=str))


def estado():
    pedidos = json.loads(sys.stdin.read() or "[]")
    saida = {}
    for p in pedidos:
        m = apps.get_model(p["modelo"])
        obj = m._default_manager.filter(pk=p["pk"]).first()
        if obj is None:
            saida[f"{p['modelo']}:{p['pk']}"] = {"existe": False, "texto": {}}
            continue
        texto = {f.name: str(getattr(obj, f.name, ""))[:500] for f in m._meta.concrete_fields
                 if isinstance(f, (models.CharField, models.TextField))}
        apagado = any(getattr(obj, n, None) for n in ("deleted_at", "is_deleted", "deleted", "apagado_em"))
        saida[f"{p['modelo']}:{p['pk']}"] = {"existe": not apagado, "texto": texto}
    print(json.dumps(saida, default=str))


if __name__ == "__main__":
    {"preparar": preparar, "estado": estado}[sys.argv[1]]()
