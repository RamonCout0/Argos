"""
Argos — monta e desmonta o laboratório de ataque de um projeto Django.

  - settings SOBREPOSTO num módulo temporário: banco SQLite novo e
    descartável, cache em memória, e-mail em memória, arquivos numa pasta
    temporária, DEBUG=False (como em produção), sem HTTPS obrigatório (é local);
  - as chaves do .env do projeto ficam EM BRANCO no processo do app: o
    python-dotenv não sobrescreve variável que já existe, então Cloudinary,
    Brevo, Sentry, Google... ficam desligados e nada de verdade é tocado;
  - saída pra internet bloqueada (proxy morto): o app atacado não consegue
    falar com nenhum serviço de fora durante o teste;
  - o servidor sobe em 127.0.0.1, numa porta livre, e é morto no fim.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from ..core import progresso

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_django.py")

SOBREPOSTO = '''\
import os
from {original} import *  # noqa: F401,F403

DATABASES = {{"default": {{"ENGINE": "django.db.backends.sqlite3", "NAME": os.environ["ARGOS_DB"]}}}}
CACHES = {{"default": {{"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}}}
SESSION_ENGINE = "django.contrib.sessions.backends.db"
DEBUG = False
SECRET_KEY = os.environ["ARGOS_SECRET"]
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:" + os.environ["ARGOS_PORTA"]]
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
MEDIA_ROOT = os.environ["ARGOS_MEDIA"]
STORAGES = {{"default": {{"BACKEND": "django.core.files.storage.FileSystemStorage"}},
            "staticfiles": {{"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}}}}
DEFAULT_FILE_STORAGE = "django.core.files.storage.FileSystemStorage"
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = True
CHANNEL_LAYERS = {{"default": {{"BACKEND": "channels.layers.InMemoryChannelLayer"}}}}
LOGGING = {{"version": 1, "disable_existing_loggers": True}}
'''


class LabFalhou(Exception):
    pass


def modulo_settings(projeto: str) -> str:
    """O DJANGO_SETTINGS_MODULE que o manage.py usa."""
    try:
        with open(os.path.join(projeto, "manage.py"), encoding="utf-8") as fp:
            texto = fp.read()
    except OSError as e:
        raise LabFalhou("sem manage.py na raiz do projeto: o modo ataque é pra projeto Django") from e
    m = re.search(r"DJANGO_SETTINGS_MODULE['\"]\s*,\s*['\"]([\w.]+)['\"]", texto)
    if not m:
        raise LabFalhou("não achei o DJANGO_SETTINGS_MODULE no manage.py")
    return m.group(1)


def chaves_do_env(projeto: str) -> list[str]:
    nomes = []
    for arq in (".env", ".env.local"):
        try:
            with open(os.path.join(projeto, arq), encoding="utf-8", errors="replace") as fp:
                for linha in fp:
                    m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", linha)
                    if m:
                        nomes.append(m.group(1))
        except OSError:
            continue
    return nomes


def porta_livre() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Laboratorio:
    def __init__(self, projeto: str, python: str):
        self.projeto = os.path.abspath(projeto)
        self.python = python
        self.porta = porta_livre()
        self.base = f"http://127.0.0.1:{self.porta}"
        self.dados: dict = {}
        self._servidor = None
        self._tmp = None

    # ------------------------------------------------------------ ambiente
    def _ambiente(self) -> dict:
        env = dict(os.environ)
        for nome in chaves_do_env(self.projeto):  # .env do projeto: tudo em branco
            env[nome] = ""
        env.update({
            "DJANGO_SETTINGS_MODULE": "argos_lab_settings",
            "PYTHONPATH": os.pathsep.join([self._tmp, self.projeto]),
            "ARGOS_DB": os.path.join(self._tmp, "lab.sqlite3"),
            "ARGOS_MEDIA": os.path.join(self._tmp, "media"),
            "ARGOS_SECRET": secrets.token_urlsafe(50),
            "SECRET_KEY": secrets.token_urlsafe(50),
            "DEBUG": "False",
            "DATABASE_URL": "sqlite:///" + os.path.join(self._tmp, "lab.sqlite3").replace("\\", "/"),
            "ARGOS_PORTA": str(self.porta),
            "ARGOS_PROJETO": self.projeto,
            "PYTHONUTF8": "1",
            # sem saída pra internet: qualquer chamada do app pra fora bate num proxy morto
            "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
        })
        return env

    # ------------------------------------------------------------ ciclo de vida
    def __enter__(self):
        self._tmp = tempfile.mkdtemp(prefix="argos_lab_")
        os.makedirs(os.path.join(self._tmp, "media"), exist_ok=True)
        original = modulo_settings(self.projeto)
        with open(os.path.join(self._tmp, "argos_lab_settings.py"), "w", encoding="utf-8") as fp:
            fp.write(SOBREPOSTO.format(original=original))
        env = self._ambiente()
        progresso.avisar("ataque: criando banco novo, usuários argos_a/argos_b e dados de mentira…", "trilha")
        proc = progresso.rodar([self.python, LAB, "preparar"], timeout=600, cwd=self.projeto, env=env)
        saida = (proc.stdout or "").strip().splitlines()
        if proc.returncode != 0 or not saida:
            ultima = [l for l in (proc.stderr or "").splitlines() if l.strip()][-1:] or ["?"]
            raise LabFalhou(f"o laboratório não subiu: {ultima[0][:240]}")
        self.dados = json.loads(saida[-1])
        progresso.avisar(f"ataque: {len(self.dados['objetos'])} modelo(s) semeados, "
                         f"{len(self.dados['candidatos'])} URL(s) ligadas a objetos, "
                         f"{len(self.dados['rotas'])} rota(s) sem parâmetro", "info")
        self._subir(env)
        return self

    def _subir(self, env):
        progresso.avisar(f"ataque: subindo o app em {self.base}", "info")
        log = open(os.path.join(self._tmp, "servidor.log"), "w", encoding="utf-8")
        self._servidor = subprocess.Popen(
            [self.python, "manage.py", "runserver", f"127.0.0.1:{self.porta}", "--noreload"],
            cwd=self.projeto, env=env, stdout=log, stderr=subprocess.STDOUT)
        s = progresso.atual()
        if s is not None:
            s._registrar(self._servidor)  # cancelar também derruba o servidor
        limite = time.monotonic() + 90
        while time.monotonic() < limite:
            progresso.checar()
            if self._servidor.poll() is not None:
                raise LabFalhou("o servidor do laboratório fechou ao subir: " + self.log_servidor()[-300:])
            try:
                urllib.request.urlopen(self.base + "/", timeout=3)  # noqa: S310 - 127.0.0.1
                return
            except urllib.error.HTTPError:
                return  # respondeu (mesmo 404/500): está de pé
            except OSError:
                time.sleep(0.5)
        raise LabFalhou("o servidor do laboratório não respondeu em 90 s")

    def vivo(self) -> bool:
        return self._servidor is not None and self._servidor.poll() is None

    def log_servidor(self) -> str:
        try:
            with open(os.path.join(self._tmp, "servidor.log"), encoding="utf-8", errors="replace") as fp:
                return fp.read()[-20000:]
        except OSError:
            return ""

    def reiniciar(self):
        """Depois do teste de carga derrubar o servidor, sobe de novo pros testes seguintes."""
        if self.vivo():
            return
        self._subir(self._ambiente())

    def estado(self, objetos: list[dict]) -> dict:
        proc = progresso.rodar([self.python, LAB, "estado"], timeout=120, cwd=self.projeto,
                               env=self._ambiente(), input=json.dumps(objetos))
        try:
            return json.loads((proc.stdout or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise LabFalhou("não consegui ler o estado do banco: " + (proc.stderr or "")[-200:]) from None

    def __exit__(self, *exc):
        if self._servidor is not None and self._servidor.poll() is None:
            self._servidor.kill()
            try:
                self._servidor.wait(10)
            except subprocess.TimeoutExpired:
                pass
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
        return False
