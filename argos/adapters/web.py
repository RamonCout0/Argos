"""
Argos — trilha web (v2.1): o app rodando, visto como um visitante curioso veria.

Passivo e leve de propósito: algumas dezenas de GETs (teto de 80 por alvo),
com pausa entre eles. Nada de força bruta, nada de formulário enviado.

O que olha:
  - arquivos que nunca deviam estar publicados (.env, .git, banco, backups...)
  - listagem de pastas (/media/, /static/, /uploads/...)
  - página de erro com DEBUG ligado (Django, Werkzeug)
  - admin do Django no endereço padrão e documentação da API exposta
  - cabeçalhos de segurança, versão do servidor, CORS, cookies de sessão
  - o JavaScript que vai pro navegador: segredo no bundle e source map exposto

Anti falso positivo: um SPA (Angular, React) devolve a página inicial pra
QUALQUER endereço com status 200. Por isso um arquivo só conta como achado se
o conteúdo bater com a assinatura real dele ("ref: refs/" num .git/HEAD,
"SQLite format 3" num banco...). O conteúdo nunca vai pro relatório: só o que
foi encontrado, mascarado.

Alvo: passa pela trava (local) ou pela verificação de dono (produção).
Redirecionamento pra outro domínio é recusado.
"""
from __future__ import annotations

import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .. import __version__
from .base import Adapter, Contexto
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo
from ..guard.target_lock import autorizar_alvo
from ..config import carregar_segredo

UA = f"Argos/{__version__} (auditoria do proprio projeto)"
LIMITE_CORPO = 512_000
CRIT, ALTO, MEDIO, BAIXO, INFO = (Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO,
                                  Severidade.BAIXO, Severidade.INFO)


@dataclass
class Resposta:
    status: int
    headers: dict
    corpo: bytes
    url: str

    def h(self, nome: str) -> str:
        return (self.headers.get(nome.lower()) or [""])[0]

    def todos(self, nome: str) -> list[str]:
        return self.headers.get(nome.lower(), [])

    @property
    def texto(self) -> str:
        return self.corpo[:200_000].decode("utf-8", "replace")

    @property
    def html(self) -> bool:
        return "html" in self.h("content-type").lower()


class _SoMesmoHost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, novo):
        if urlsplit(novo).hostname != urlsplit(req.full_url).hostname:
            return None  # nao segue redirecionamento pra outro dominio
        return super().redirect_request(req, fp, code, msg, headers, novo)


class Cliente:
    def __init__(self, base: str, pausa: float = 0.05, limite: int = 80, timeout: int = 8):
        self.base = base.rstrip("/")
        self.pausa, self.restantes, self.timeout = pausa, limite, timeout
        self.enviadas = 0
        self._abridor = urllib.request.build_opener(_SoMesmoHost())

    def pedir(self, caminho: str, metodo: str = "GET", headers: dict | None = None):
        progresso.checar()
        if self.restantes <= 0:
            return None
        self.restantes -= 1
        self.enviadas += 1
        url = caminho if caminho.startswith("http") else self.base + caminho
        req = urllib.request.Request(url, method=metodo, headers={"User-Agent": UA, **(headers or {})})
        try:
            with self._abridor.open(req, timeout=self.timeout) as r:  # noqa: S310 (alvo autorizado)
                status, hdrs, corpo, final = r.status, r.headers, r.read(LIMITE_CORPO), r.geturl()
        except urllib.error.HTTPError as e:
            status, hdrs, final = e.code, e.headers, url
            try:
                corpo = e.read(LIMITE_CORPO)
            except Exception:  # noqa: BLE001
                corpo = b""
        except (urllib.error.URLError, OSError, ValueError) as e:
            progresso.avisar(f"{metodo} {urlsplit(url).path or '/'} → sem resposta ({getattr(e, 'reason', e)})", "req")
            return None
        finally:
            time.sleep(self.pausa)
        hd: dict = {}
        for k, v in (hdrs.items() if hdrs else []):
            hd.setdefault(k.lower(), []).append(v)
        progresso.avisar(f"{metodo} {urlsplit(url).path or '/'} → {status}", "req")
        return Resposta(status, hd, corpo, final)


# ------------------------------------------------------------------ assinaturas

def _tem(*padroes):
    regs = [re.compile(p, re.I | re.M) for p in padroes]
    return lambda r: any(x.search(r.texto[:30000]) for x in regs)


def _comeca(prefixo: bytes):
    return lambda r: r.corpo.startswith(prefixo)


_LINHA_ENV = re.compile(r"^\s*([A-Z][A-Z0-9_]{1,60})\s*=", re.M)


def _env(r) -> bool:
    return (not r.html) and len(_LINHA_ENV.findall(r.texto[:20000])) >= 2


def _ev_env(r) -> str:
    nomes = list(dict.fromkeys(_LINHA_ENV.findall(r.texto[:20000])))
    return f"{len(nomes)} variável(is) legível(is), ex.: {', '.join(nomes[:4])} (valores ocultos)"


FIX_ARQ = ("Tirar o arquivo da pasta publicada e bloquear no servidor web. Se era segredo, "
           "TROCAR (já foi exposto).")

# (caminho, titulo, severidade, categoria, assinatura)
ARQUIVOS = [
    ("/.env", ".env publicado: senhas e chaves do projeto", CRIT, "CWE-538", _env),
    ("/.env.local", ".env.local publicado", CRIT, "CWE-538", _env),
    ("/.env.production", ".env.production publicado", CRIT, "CWE-538", _env),
    ("/.env.bak", "Cópia de .env publicada", CRIT, "CWE-538", _env),
    ("/.git/HEAD", "Pasta .git publicada: dá pra baixar o código e o histórico", CRIT, "CWE-527",
     _tem(r"^ref: refs/")),
    ("/.git/config", "Configuração do .git publicada", CRIT, "CWE-527", _tem(r"^\[core\]")),
    ("/db.sqlite3", "Banco SQLite disponível pra download", CRIT, "CWE-538", _comeca(b"SQLite format 3")),
    ("/backup.zip", "Backup .zip disponível pra download", ALTO, "CWE-538", _comeca(b"PK\x03\x04")),
    ("/site.zip", "Pacote .zip do site disponível pra download", ALTO, "CWE-538", _comeca(b"PK\x03\x04")),
    ("/backup.sql", "Dump do banco disponível pra download", CRIT, "CWE-538", _tem(r"CREATE TABLE|INSERT INTO")),
    ("/dump.sql", "Dump do banco disponível pra download", CRIT, "CWE-538", _tem(r"CREATE TABLE|INSERT INTO")),
    ("/database.sql", "Dump do banco disponível pra download", CRIT, "CWE-538", _tem(r"CREATE TABLE|INSERT INTO")),
    ("/id_rsa", "Chave SSH privada publicada", CRIT, "CWE-538", _tem(r"BEGIN [A-Z ]*PRIVATE KEY")),
    ("/.ssh/id_rsa", "Chave SSH privada publicada", CRIT, "CWE-538", _tem(r"BEGIN [A-Z ]*PRIVATE KEY")),
    ("/.htpasswd", "Arquivo de senhas .htpasswd publicado", ALTO, "CWE-538", _tem(r"^[^:\s<]+:(\$apr1\$|\$2[aby]\$|\{SHA\})")),
    ("/.vscode/sftp.json", "Config de deploy do VS Code (com senha) publicada", ALTO, "CWE-538", _tem(r'"password"\s*:')),
    ("/docker-compose.yml", "docker-compose.yml publicado (revela serviços e às vezes senhas)", MEDIO, "CWE-538",
     _tem(r"^services:\s*$")),
    ("/.DS_Store", ".DS_Store publicado (lista os arquivos da pasta)", BAIXO, "CWE-538",
     lambda r: r.corpo[4:8] == b"Bud1"),
    ("/phpinfo.php", "phpinfo() publicado (mostra toda a configuração)", MEDIO, "CWE-497", _tem(r"phpinfo\(\)|PHP Version")),
    ("/server-status", "Status do Apache publicado", MEDIO, "CWE-497", _tem(r"Apache Server Status")),
    ("/actuator/env", "Actuator do Spring expõe variáveis de ambiente", ALTO, "CWE-497", _tem(r'"propertySources"')),
]

_LISTAGEM = _tem(r"<title>\s*Index of", r"Directory listing for", r"<h1>\s*Index of")
PASTAS = [("/media/", ALTO), ("/uploads/", ALTO), ("/static/", MEDIO), ("/assets/", MEDIO), ("/files/", ALTO)]

DOCS_API = ["/api/docs/", "/api/schema/", "/swagger/", "/redoc/", "/docs"]
_DOCS = _tem(r"swagger-ui", r"<redoc", r'"openapi"\s*:', r"^openapi:\s")
_ADMIN = _tem(r"Django administration", r"Administração do Django", r'id="id_username"', r"django-admin")

_DJANGO_DEBUG = re.compile(r"you have <code>DEBUG = True</code>|DEBUG = True</code> in your Django", re.I)
_WERKZEUG = re.compile(r"Werkzeug Debugger|The debugger caught an exception", re.I)
_DJDT = re.compile(r'id="djDebug"|djdt', re.I)

_SCRIPT = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")

SEGREDOS_JS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "chave da AWS", ALTO),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "token do GitHub", ALTO),
    (re.compile(r"sk_live_[0-9A-Za-z]{20,}"), "chave secreta do Stripe", CRIT),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "token do Slack", ALTO),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "chave privada", CRIT),
    (re.compile(r"""(?i)["']?(client_?secret|secret_?key|api_?secret|senha|password)["']?\s*[:=]\s*["']([^"'\s]{8,})["']"""),
     "segredo nomeado", ALTO),
]

SESSAO = re.compile(r"^(sessionid|session|sid|jwt|token|auth|access_token|refresh_token|connect\.sid|"
                    r"laravel_session|phpsessid|jsessionid)$", re.I)


def _mascarar(s: str) -> str:
    return (s[:4] + "***") if len(s) > 4 else "***"


# ------------------------------------------------------------------ varredura

class Varredura:
    def __init__(self, base: str, local: bool, cliente: Cliente | None = None):
        self.base = base.rstrip("/")
        self.local = local
        self.https = self.base.startswith("https://")
        self.c = cliente or Cliente(self.base, pausa=0.05 if local else 0.25)
        self.achados: list[Finding] = []

    def _add(self, titulo, sev, cat, onde, evidencia, fix, verificacao="", lentes=None):
        self.achados.append(Finding(
            id=f"WEB-{len(self.achados) + 1:03d}", titulo=titulo, severidade=sev, categoria=cat,
            origem="argos-web", local=f"{self.base}{onde}", evidencia=evidencia,
            lentes=list(lentes or []), fix=Fix(FixTipo.IA, fix) if fix else None,
            verificacao=verificacao or "re-rodar 'python cli.py web <url>' -> achado some"))

    def rodar(self) -> list[Finding]:
        home = self.c.pedir("/", headers={"Origin": "https://argos-origem-teste.invalid"})
        if home is None:
            raise RuntimeError(f"{self.base} não respondeu (o app está rodando?)")
        self._debug()
        self._cabecalhos(home)
        self._cors(home, "/")
        api = self.c.pedir("/api/", headers={"Origin": "https://argos-origem-teste.invalid"})
        if api is not None and api.status < 400 and not api.html:
            self._cors(api, "/api/")
        self._cookies(home, "/")
        self._arquivos()
        self._pastas()
        self._admin()
        self._docs()
        if home.html:
            self._javascript(home)
            if _DJDT.search(home.texto):
                self._add("Django Debug Toolbar ativa", ALTO, "CWE-489", "/",
                          "a página inicial carrega a barra de debug (SQL, settings, headers)",
                          "Desligar o debug toolbar fora do teu PC (INTERNAL_IPS só com 127.0.0.1 e DEBUG=False).")
        if self.local:
            self._trace()
        if not self.https and not self.local:
            self._add("Site sem HTTPS", ALTO, "CWE-319", "/", "o endereço público responde em HTTP puro",
                      "Servir só por HTTPS e redirecionar o HTTP (no Django: SECURE_SSL_REDIRECT=True).")
        return self.achados

    def _debug(self):
        r = self.c.pedir(f"/argos-naoexiste-{secrets.token_hex(4)}/")
        if r is None:
            return
        if _WERKZEUG.search(r.texto):
            self._add("Debugger do Werkzeug ativo: console que executa código", CRIT, "CWE-489", "/<erro>",
                      "a página de erro abre o debugger interativo do Flask/Werkzeug",
                      "Nunca rodar com debug=True fora do teu PC; em produção, FLASK_DEBUG=0.")
        elif _DJANGO_DEBUG.search(r.texto):
            rotas = len(re.findall(r"<li>", r.texto))
            self._add("DEBUG=True: a página de erro revela rotas e configurações", ALTO, "CWE-489", "/<erro>",
                      f"página 404 do Django em modo debug ({rotas} item(ns) de rota listados)",
                      "DEBUG lido de variável de ambiente com padrão False; em produção sempre False.")

    def _cabecalhos(self, home):
        if not home.html:
            return
        csp = home.h("content-security-policy")
        xfo = home.h("x-frame-options")
        if not csp:
            self._add("Sem Content-Security-Policy", BAIXO, "CWE-693", " · cabeçalho CSP",
                      "a página não define CSP (limita o estrago de um XSS)",
                      "Definir uma CSP (no Django: django-csp ou SECURE_CSP no Django 6).")
        if not xfo and "frame-ancestors" not in csp.lower():
            self._add("Página pode ser embutida em outro site (clickjacking)", BAIXO, "CWE-1021",
                      " · cabeçalho X-Frame-Options", "sem X-Frame-Options e sem frame-ancestors na CSP",
                      "X-Frame-Options: DENY (no Django vem do XFrameOptionsMiddleware).")
        if home.h("x-content-type-options").lower() != "nosniff":
            self._add("Sem X-Content-Type-Options: nosniff", BAIXO, "CWE-693", " · cabeçalho nosniff",
                      "o navegador pode 'adivinhar' o tipo do arquivo",
                      "Enviar X-Content-Type-Options: nosniff (Django: SECURE_CONTENT_TYPE_NOSNIFF=True).")
        if self.https and not home.h("strict-transport-security"):
            self._add("Sem HSTS no HTTPS", MEDIO, "CWE-319", " · cabeçalho HSTS",
                      "o navegador aceita voltar pro HTTP (ataque de rebaixamento)",
                      "Strict-Transport-Security (Django: SECURE_HSTS_SECONDS).")
        for nome in ("server", "x-powered-by"):
            v = home.h(nome)
            if re.search(r"\d+\.\d+", v):
                self._add(f"Cabeçalho {nome.title()} revela a versão do software", BAIXO, "CWE-497",
                          f" · cabeçalho {nome}", f"{nome}: {v[:60]}",
                          "Esconder a versão no servidor web / proxy (em produção, Gunicorn atrás de proxy).")

    def _cors(self, r, onde):
        acao = r.h("access-control-allow-origin")
        cred = r.h("access-control-allow-credentials").lower() == "true"
        if acao == "https://argos-origem-teste.invalid":
            sev = ALTO if cred else MEDIO
            self._add("CORS aceita qualquer origem" + (" e ainda manda credenciais" if cred else ""),
                      sev, "CWE-942", f"{onde} · CORS",
                      f"um site estranho foi aceito como origem{' com Allow-Credentials: true' if cred else ''}",
                      "Listar só as origens do teu front (django-cors-headers: CORS_ALLOWED_ORIGINS) "
                      "e nunca refletir a Origin recebida.")
        elif acao == "*" and cred:
            self._add("CORS com '*' e credenciais", MEDIO, "CWE-942", f"{onde} · CORS",
                      "Allow-Origin: * junto com Allow-Credentials: true",
                      "Trocar o '*' pela lista de origens permitidas.")

    def _cookies(self, r, onde):
        for linha in r.todos("set-cookie"):
            nome = linha.split("=", 1)[0].strip()
            attrs = linha.lower()
            if SESSAO.match(nome):
                if "httponly" not in attrs:
                    self._add(f"Cookie de sessão '{nome}' sem HttpOnly", MEDIO, "CWE-1004", f"{onde} · cookie {nome}",
                              "o JavaScript da página consegue ler o cookie de sessão (um XSS rouba a conta)",
                              "Marcar HttpOnly (Django: SESSION_COOKIE_HTTPONLY=True, que é o padrão).")
                if "samesite" not in attrs:
                    self._add(f"Cookie de sessão '{nome}' sem SameSite", BAIXO, "CWE-1275", f"{onde} · cookie {nome}",
                              "o cookie vai junto em requisições vindas de outros sites",
                              "SameSite=Lax (Django: SESSION_COOKIE_SAMESITE='Lax', o padrão).")
            if self.https and "secure" not in attrs and (SESSAO.match(nome) or nome.lower() == "csrftoken"):
                self._add(f"Cookie '{nome}' sem Secure no HTTPS", MEDIO, "CWE-614", f"{onde} · cookie {nome}",
                          "o cookie pode vazar se o navegador cair pra HTTP",
                          "SESSION_COOKIE_SECURE=True e CSRF_COOKIE_SECURE=True em produção.")

    def _arquivos(self):
        for caminho, titulo, sev, cat, assinatura in ARQUIVOS:
            r = self.c.pedir(caminho)
            if r is None or r.status not in (200, 206) or not assinatura(r):
                continue
            evid = _ev_env(r) if assinatura is _env else f"{caminho} respondeu {r.status} com o conteúdo real do arquivo"
            self._add(titulo, sev, cat, caminho, evid, FIX_ARQ, f"abrir {caminho} -> 404")

    def _pastas(self):
        for caminho, sev in PASTAS:
            r = self.c.pedir(caminho)
            if r is not None and r.status == 200 and _LISTAGEM(r):
                n = len(re.findall(r"<a href=", r.texto, re.I))
                self._add(f"Listagem de arquivos aberta em {caminho}", sev, "CWE-548", caminho,
                          f"o servidor lista o conteúdo da pasta (~{n} link(s))",
                          "Desligar a listagem de diretórios; em produção, servir media/static pelo proxy "
                          "ou storage, nunca pelo próprio Django com show_indexes.")

    def _admin(self):
        r = self.c.pedir("/admin/")
        if r is not None and r.status == 200 and _ADMIN(r):
            self._add("Admin do Django no endereço padrão /admin/", BAIXO, "ARGOS-ADMIN-PADRAO", "/admin/",
                      "o painel de admin responde no caminho que todo bot testa primeiro",
                      "Mudar o caminho (ex.: path('painel-x7/', admin.site.urls)), limitar tentativas "
                      "(django-axes) e usar senha forte/2FA.", lentes=[Lente.BOT])

    def _docs(self):
        for caminho in DOCS_API:
            r = self.c.pedir(caminho)
            if r is not None and r.status == 200 and _DOCS(r):
                sev = BAIXO if self.local else MEDIO
                self._add("Documentação da API acessível sem login", sev, "ARGOS-API-DOCS", caminho,
                          "o mapa completo dos endpoints está público (bom pra testar, ruim em produção)",
                          "Em produção, exigir login pra ver a documentação (ou não publicar).")
                return

    def _javascript(self, home):
        host = urlsplit(self.base).hostname
        scripts = []
        for src in _SCRIPT.findall(home.texto):
            url = urljoin(self.base + "/", src)
            if urlsplit(url).hostname == host and url not in scripts:
                scripts.append(url)
        for url in scripts[:6]:
            r = self.c.pedir(url)
            if r is None or r.status != 200:
                continue
            caminho = urlsplit(url).path
            for padrao, nome, sev in SEGREDOS_JS:
                m = padrao.search(r.texto)
                if m:
                    valor = m.group(m.lastindex or 0) if m.lastindex else m.group(0)
                    self._add(f"Segredo dentro do JavaScript que vai pro navegador ({nome})", sev, "CWE-798",
                              caminho, f"{nome}: {_mascarar(valor)} — qualquer visitante vê isso",
                              "Tudo que está no front é público. Mover o segredo pro backend e TROCAR a chave.")
                    break
            mapa = _SOURCEMAP.search(r.texto[-3000:])
            alvo = urljoin(url, mapa.group(1)) if mapa and not mapa.group(1).startswith("data:") else url + ".map"
            if urlsplit(alvo).hostname == host:
                m = self.c.pedir(alvo)
                if m is not None and m.status == 200 and b'"sources"' in m.corpo[:5000]:
                    self._add("Source map publicado: o código-fonte original fica legível", MEDIO, "CWE-540",
                              urlsplit(alvo).path, "o .map reconstrói o código do front com nomes e comentários",
                              "Não publicar source maps em produção (Angular: \"sourceMap\": false na configuração production).")

    def _trace(self):
        r = self.c.pedir("/", metodo="TRACE")
        if r is not None and r.status == 200 and "TRACE / HTTP" in r.texto:
            self._add("Método TRACE habilitado", BAIXO, "CWE-693", " · método TRACE",
                      "o servidor ecoa a requisição de volta", "Desabilitar TRACE no servidor web.")


class WebAdapter(Adapter):
    nome = "web"

    def disponivel(self) -> bool:
        return True  # Python puro

    def escanear(self, ctx: Contexto) -> list[Finding]:
        urls = ctx.opcoes.get("urls") or []
        if not urls:
            return []
        segredo = ctx.opcoes.get("segredo") or carregar_segredo()
        achados: list[Finding] = []
        for url in urls:
            url = url.strip().rstrip("/")
            if "://" not in url:
                url = "http://" + url
            tipo, _ = autorizar_alvo(url, segredo)  # local, ou dono verificado; senao levanta
            progresso.avisar(f"web: {url} ({'local' if tipo == 'local' else 'dono verificado'})", "inicio")
            achados += Varredura(url, local=(tipo == "local")).rodar()
        for i, f in enumerate(achados, start=1):
            f.id = f"WEB-{i:03d}"
        return achados
