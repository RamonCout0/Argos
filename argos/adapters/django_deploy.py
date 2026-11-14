"""
Argos — `manage.py check --deploy` do próprio Django (v2.2).

O Django sabe melhor que ninguém o que falta pra ele ir pra produção: cookies
só por HTTPS, HSTS, DEBUG, SECRET_KEY fraca, ALLOWED_HOSTS... Aqui o Argos:
  1. acha o manage.py (até 3 pastas abaixo);
  2. usa o Python do venv DO PROJETO (venv/.venv/env), porque é lá que está o
     Django dele; se não achar, tenta o Python atual;
  3. roda `check --deploy` e traduz os avisos security.W0xx.

Modo dev x produção: rodando com o settings de desenvolvimento, quase todos os
avisos aparecem (DEBUG=True é normal no teu PC). Pra não travar o selo à toa,
no modo dev a gravidade fica no máximo MÉDIO e o título diz "em produção".
Pra checar o settings de verdade, defina ARGOS_DJANGO_SETTINGS (ex.:
core.settings.prod) no .env do Argos: aí a gravidade real vale.

Isso EXECUTA o código do teu projeto (o settings.py) — por isso só pasta local.
"""
from __future__ import annotations

import os
import re
import sys

from .base import Adapter, Contexto
from ..config import carregar
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

C, A, M, B = Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO, Severidade.BAIXO
IGNORAR = {"node_modules", ".git", "venv", ".venv", "env", "dist", "build", "__pycache__", "site-packages"}

# código -> (título, gravidade real, categoria, correção)
AVISOS = {
    "W001": ("SecurityMiddleware fora do MIDDLEWARE", M, "CWE-693",
             "Adicionar 'django.middleware.security.SecurityMiddleware' no topo do MIDDLEWARE."),
    "W002": ("Sem proteção contra clickjacking (XFrameOptionsMiddleware)", M, "CWE-1021",
             "Adicionar 'django.middleware.clickjacking.XFrameOptionsMiddleware' no MIDDLEWARE."),
    "W003": ("Proteção CSRF desligada (CsrfViewMiddleware)", A, "CWE-352",
             "Recolocar 'django.middleware.csrf.CsrfViewMiddleware' no MIDDLEWARE."),
    "W004": ("HSTS não configurado (SECURE_HSTS_SECONDS)", B, "CWE-319",
             "Em produção: SECURE_HSTS_SECONDS = 31536000 (comece com 3600 pra testar)."),
    "W005": ("HSTS sem subdomínios", B, "CWE-319", "SECURE_HSTS_INCLUDE_SUBDOMAINS = True."),
    "W006": ("Sem X-Content-Type-Options: nosniff", B, "CWE-693", "SECURE_CONTENT_TYPE_NOSNIFF = True."),
    "W008": ("HTTP não redireciona pra HTTPS (SECURE_SSL_REDIRECT)", M, "CWE-319",
             "Em produção: SECURE_SSL_REDIRECT = True (no Railway, junto de "
             "SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https'))."),
    "W009": ("SECRET_KEY fraca, curta ou a padrão 'django-insecure'", A, "CWE-330",
             "Gerar uma chave nova (get_random_secret_key()) e ler de variável de ambiente."),
    "W012": ("Cookie de sessão pode ir por HTTP (SESSION_COOKIE_SECURE)", M, "CWE-614",
             "Em produção: SESSION_COOKIE_SECURE = True."),
    "W016": ("Cookie CSRF pode ir por HTTP (CSRF_COOKIE_SECURE)", M, "CWE-614",
             "Em produção: CSRF_COOKIE_SECURE = True."),
    "W018": ("DEBUG=True", A, "CWE-489",
             "DEBUG lido de variável de ambiente, padrão False: "
             "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'."),
    "W019": ("X_FRAME_OPTIONS não é DENY", B, "CWE-1021", "X_FRAME_OPTIONS = 'DENY'."),
    "W020": ("ALLOWED_HOSTS vazio", M, "CWE-16", "Listar os domínios reais em ALLOWED_HOSTS."),
    "W021": ("HSTS sem preload", B, "CWE-319", "SECURE_HSTS_PRELOAD = True (só depois de testar o HSTS)."),
    "W022": ("Sem Referrer-Policy", B, "CWE-200", "SECURE_REFERRER_POLICY = 'same-origin'."),
    "W024": ("Cross-Origin-Opener-Policy inválida", B, "CWE-693",
             "SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'."),
}
_LINHA = re.compile(r"\((security\.[WE]\d{3})\)\s*(.+?)(?=\n\S|\n\n|\Z)", re.S)


def parse_check(texto: str, producao: bool) -> list[Finding]:
    achados: list[Finding] = []
    vistos = set()
    for m in _LINHA.finditer(texto or ""):
        codigo = m.group(1).split(".")[1]
        if codigo in vistos:
            continue
        vistos.add(codigo)
        msg_original = " ".join(m.group(2).split())
        titulo, sev, cat, fix = AVISOS.get(codigo, (msg_original[:110], B, "CWE-16", "Ver a dica do Django."))
        if not producao and sev in (C, A):
            sev = M  # settings de dev: alerta, mas não trava o deploy
        achados.append(Finding(
            id=f"DJ-{len(achados) + 1:03d}",
            titulo=titulo + ("" if producao else " (em produção)"),
            severidade=sev, categoria=cat, origem="django-check",
            local=f"settings · security.{codigo}",
            evidencia=msg_original[:220],
            lentes=[Lente.CRITICO], fix=Fix(FixTipo.IA, fix),
            verificacao="python manage.py check --deploy -> aviso some"))
    return achados


def achar_manage(raiz: str, profundidade: int = 3) -> str | None:
    base = raiz.rstrip(os.sep).count(os.sep)
    for pasta, dirs, nomes in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in IGNORAR and not d.startswith(".")]
        if "manage.py" in nomes:
            return os.path.join(pasta, "manage.py")
        if pasta.count(os.sep) - base >= profundidade:
            dirs[:] = []
    return None


def python_do_projeto(raiz: str, pasta_manage: str) -> str:
    """O Python do venv do projeto (é onde o Django dele está instalado)."""
    rel = ("Scripts", "python.exe") if os.name == "nt" else ("bin", "python")
    atual = pasta_manage
    while True:
        for nome in ("venv", ".venv", "env"):
            candidato = os.path.join(atual, nome, *rel)
            if os.path.isfile(candidato):
                return candidato
        if os.path.normcase(atual) == os.path.normcase(raiz) or os.path.dirname(atual) == atual:
            break
        atual = os.path.dirname(atual)
    return sys.executable


class DjangoDeployAdapter(Adapter):
    nome = "django-check"

    def disponivel(self) -> bool:
        return True  # só usa o Python; se não houver Django no projeto, não faz nada

    def escanear(self, ctx: Contexto) -> list[Finding]:
        raiz = os.path.abspath(ctx.projeto)
        manage = achar_manage(raiz)
        if not manage:
            progresso.avisar("django-check: sem manage.py, não é projeto Django", "info")
            return []
        pasta = os.path.dirname(manage)
        py = python_do_projeto(raiz, pasta)
        ambiente = dict(os.environ)
        settings = carregar("ARGOS_DJANGO_SETTINGS", "")
        if settings:
            ambiente["DJANGO_SETTINGS_MODULE"] = settings
        progresso.avisar(f"django-check: {os.path.relpath(manage, raiz)} com "
                         f"{'o venv do projeto' if py != sys.executable else 'o Python do Argos'}"
                         + (f" · settings {settings}" if settings else " · settings de dev"), "info")
        proc = progresso.rodar([py, "manage.py", "check", "--deploy"], timeout=180, cwd=pasta, env=ambiente)
        texto = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if "No module named 'django'" in texto:
            raise RuntimeError("não achei o Django no Python do projeto: crie o venv dele "
                               "(venv/.venv na pasta do projeto) e instale as dependências")
        falta = re.search(r"No module named '([\w.]+)'", texto)
        if falta:
            raise RuntimeError(f"o settings do projeto pede '{falta.group(1)}', que não está instalado no "
                               "Python usado: instale as dependências do projeto no venv dele")
        achados = parse_check(texto, producao=bool(settings))
        if proc.returncode not in (0, 1) or (proc.returncode == 1 and not achados):
            ultima = [l for l in texto.strip().splitlines() if l.strip()][-1:] or ["?"]
            raise RuntimeError(f"manage.py check falhou: {ultima[0][:200]}")
        return achados
