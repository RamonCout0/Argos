"""
Argos — os ataques de verdade (Fase 7), contra o laboratório em 127.0.0.1.

Cada ataque CONFIRMA antes de acusar: IDOR e CSRF só viram achado se o banco
mostrar que o objeto do A sumiu ou mudou; XSS só se o marcador voltar SEM
escape no HTML; vazamento só se o e-mail do A aparecer pra quem não devia.
"""
from __future__ import annotations

import http.client
import json
import re
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urlencode, urlsplit

from ..core import progresso
from ..guard.ativo import exigir_loopback
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

C, A, M, B, I = (Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO, Severidade.BAIXO, Severidade.INFO)
SOCIAL = re.compile(r"(curtir|like|seguir|follow|favorit|entrar|join|react|votar|vote|digitando|typing|"
                    r"lido|read|seen|visto|denunciar|report|inscrever|subscribe)", re.I)
APAGAR = re.compile(r"(delete|apagar|excluir|remov|destroy|deletar)", re.I)
EDITAR = re.compile(r"(edit|editar|update|atualiz|alterar|change)", re.I)
ERRO_BANCO = re.compile(r"(OperationalError|ProgrammingError|syntax error|sqlite3\.|psycopg|"
                        r"unterminated quoted|You have an error in your SQL)", re.I)


# ------------------------------------------------------------------ cliente HTTP

class Resposta:
    def __init__(self, status, headers, corpo):
        self.status, self.headers, self.corpo = status, headers, corpo

    @property
    def texto(self) -> str:
        return self.corpo.decode("utf-8", "replace")

    @property
    def html(self) -> bool:
        return "html" in self.headers.get("content-type", "")


class Sessao:
    """Uma identidade (anônimo, A ou B) com seus cookies. Nunca segue redirect, só fala com loopback."""

    def __init__(self, base: str, nome: str, cookies: dict | None = None, csrf_cookie="csrftoken"):
        exigir_loopback(base)
        partes = urlsplit(base)
        self.host, self.porta, self.nome = partes.hostname, partes.port, nome
        self.cookies = dict(cookies or {})
        self.csrf_cookie = csrf_cookie
        self.base = base

    def pedir(self, metodo, caminho, dados=None, json_=None, headers=None, csrf=True, timeout=20,
              arquivos=None) -> Resposta | None:
        if not caminho.startswith("/"):
            raise ValueError("o ataque só usa caminhos relativos ao laboratório")
        progresso.checar()
        h = {"User-Agent": "Argos-ataque (laboratorio local)", "Accept": "text/html,application/json"}
        corpo = None
        if json_ is not None:
            corpo = json.dumps(json_).encode()
            h["Content-Type"] = "application/json"
        elif dados is not None or arquivos:
            dados = dict(dados or {})
            dados.pop("csrfmiddlewaretoken", None)  # token copiado de outro form/sessão não vale
            if csrf and self.cookies.get(self.csrf_cookie):
                dados["csrfmiddlewaretoken"] = self.cookies[self.csrf_cookie]
            if arquivos:
                corpo, h["Content-Type"] = _multipart(dados, arquivos)
            else:
                corpo = urlencode(dados, doseq=True).encode()
                h["Content-Type"] = "application/x-www-form-urlencoded"
        if csrf and metodo not in ("GET", "HEAD") and self.cookies.get(self.csrf_cookie):
            h["X-CSRFToken"] = self.cookies[self.csrf_cookie]
            h["Referer"] = self.base + "/"
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        h.update(headers or {})
        con = http.client.HTTPConnection(self.host, self.porta, timeout=timeout)
        try:
            con.request(metodo, caminho, body=corpo, headers=h)
            r = con.getresponse()
            dados_r = r.read(2_000_000)
            for valor in r.headers.get_all("Set-Cookie") or []:
                nome_v = valor.split(";", 1)[0]
                if "=" in nome_v:
                    k, v = nome_v.split("=", 1)
                    self.cookies[k.strip()] = v.strip()
            return Resposta(r.status, {k.lower(): v for k, v in r.getheaders()}, dados_r)
        except (OSError, http.client.HTTPException):
            return None
        finally:
            con.close()

    def garantir_csrf(self, caminho="/"):
        if not self.cookies.get(self.csrf_cookie):
            self.pedir("GET", caminho)
        if not self.cookies.get(self.csrf_cookie):
            # o site não entregou o cookie (nenhum form nessa página): o Django aceita um segredo
            # gerado pelo cliente no formato certo, desde que cookie e token batam
            import secrets
            import string
            self.cookies[self.csrf_cookie] = "".join(secrets.choice(string.ascii_letters + string.digits)
                                                     for _ in range(32))


def _multipart(dados: dict, arquivos: dict) -> tuple[bytes, str]:
    import secrets as _s
    borda = "argos" + _s.token_hex(12)
    partes = []
    for k, v in dados.items():
        for item in (v if isinstance(v, list) else [v]):
            partes.append(f'--{borda}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{item}\r\n'.encode())
    for k, (nome, conteudo, tipo) in arquivos.items():
        partes.append(f'--{borda}\r\nContent-Disposition: form-data; name="{k}"; filename="{nome}"\r\n'
                      f'Content-Type: {tipo}\r\n\r\n'.encode() + conteudo + b"\r\n")
    partes.append(f"--{borda}--\r\n".encode())
    return b"".join(partes), f"multipart/form-data; boundary={borda}"


class _Forms(HTMLParser):
    """Todos os <form method=post>: ação, campos (com valor atual) e campos de arquivo."""

    def __init__(self):
        super().__init__()
        self.forms, self._atual, self._area, self._select = [], None, None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and (a.get("method") or "").lower() == "post":
            self._atual = {"acao": a.get("action") or "", "campos": {}, "arquivos": []}
            self.forms.append(self._atual)
            return
        f = self._atual
        if f is None:
            return
        nome = a.get("name")
        if tag == "input" and nome:
            tipo = (a.get("type") or "text").lower()
            if tipo == "file":
                f["arquivos"].append(nome)
            elif tipo not in ("submit", "button", "image") and (tipo not in ("checkbox", "radio") or "checked" in a):
                f["campos"][nome] = a.get("value", "on" if tipo == "checkbox" else "")
        elif tag == "textarea" and nome:
            self._area, f["campos"][nome] = nome, ""
        elif tag == "select" and nome:
            self._select = nome
        elif tag == "option" and self._select and (self._select not in f["campos"] or "selected" in a
                                                   or (f["campos"][self._select] == "" and a.get("value"))):
            f["campos"][self._select] = a.get("value", "")  # pula o "---------" vazio

    def handle_data(self, data):
        if self._area and self._atual is not None:
            self._atual["campos"][self._area] += data

    def handle_endtag(self, tag):
        if tag == "textarea":
            self._area = None
        elif tag == "select":
            self._select = None
        elif tag == "form":
            self._atual = None


def ler_forms(html: str) -> list[dict]:
    p = _Forms()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001
        pass
    return p.forms


class _Form(HTMLParser):
    """Pega o primeiro <form method=post> e os valores atuais dos campos."""

    def __init__(self):
        super().__init__()
        self.campos, self.em_form, self.achou, self._area, self._select = {}, False, False, None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and not self.achou and (a.get("method") or "").lower() == "post":
            self.em_form = self.achou = True
        if not self.em_form:
            return
        nome = a.get("name")
        if tag == "input" and nome and (a.get("type") or "text").lower() not in ("file", "submit", "button", "image"):
            tipo = (a.get("type") or "text").lower()
            if tipo in ("checkbox", "radio") and "checked" not in a:
                return
            self.campos[nome] = a.get("value", "on" if tipo == "checkbox" else "")
        elif tag == "textarea" and nome:
            self._area, self.campos[nome] = nome, ""
        elif tag == "select" and nome:
            self._select = nome
        elif tag == "option" and self._select and (self._select not in self.campos or "selected" in a):
            self.campos[self._select] = a.get("value", "")

    def handle_data(self, data):
        if self._area:
            self.campos[self._area] += data

    def handle_endtag(self, tag):
        if tag == "textarea":
            self._area = None
        elif tag == "select":
            self._select = None
        elif tag == "form" and self.em_form:
            self.em_form = False


def _form_de_conteudo(html: str, url: str) -> dict:
    from .ataques_extra import forms_de_conteudo
    forms = forms_de_conteudo(html, url, maximo=1)
    return dict(forms[0]["campos"]) if forms else {}


def ler_form(html: str) -> dict:
    p = _Form()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001 - HTML quebrado: segue com o que deu pra ler
        pass
    return p.campos


# ------------------------------------------------------------------ o ataque

class Ataque:
    def __init__(self, lab, carga_max: int = 512, sem_carga: bool = False):
        self.lab, self.d = lab, lab.dados
        self.R = self.d["marcador"]
        ck, cs = self.d["sessao_cookie"], self.d["csrf_cookie"]
        u = self.d["usuarios"]
        self.anon = Sessao(lab.base, "anônimo", csrf_cookie=cs)
        self.a = Sessao(lab.base, "A", {ck: u["a"]["sessao"]}, cs)
        self.b = Sessao(lab.base, "B", {ck: u["b"]["sessao"]}, cs)
        self.email_a = u["a"]["email"]
        self.achados: list[Finding] = []
        self.erros500: set[str] = set()
        self.quebra_sempre: set[str] = set()
        self.carga_max, self.sem_carga = carga_max, sem_carga
        self._vistos: set[tuple] = set()

    def _add(self, chave, titulo, sev, cat, local, evid, fix, lentes=(Lente.CRITICO,)):
        if chave in self._vistos:
            return
        self._vistos.add(chave)
        self.achados.append(Finding(
            id=f"ATK-{len(self.achados) + 1:03d}", titulo=titulo, severidade=sev, categoria=cat,
            origem="argos-ataque", local=local, evidencia=evid[:240], lentes=list(lentes),
            fix=Fix(FixTipo.IA, fix), verificacao="python cli.py atacar <pasta> -> achado some"))
        progresso.avisar(f"CONFIRMADO: {titulo} ({local})", "erro")

    def _pedir(self, sessao, metodo, url, **kw):
        r = sessao.pedir(metodo, url, **kw)
        if r is not None and r.status >= 500:
            self.erros500.add(f"{metodo} {url}")
        return r

    # ---------------------------------------------------------------- 1) IDOR e CSRF
    def idor_e_csrf(self):
        alvos = [c for c in self.d["candidatos"] if c["mutacao"] and not SOCIAL.search(c["nome"] + c["rota"])]
        edicoes = [c for c in alvos if EDITAR.search(c["nome"] + c["rota"]) and not APAGAR.search(c["nome"])]
        apagamentos = [c for c in alvos if APAGAR.search(c["nome"] + c["rota"])]
        textos = {o["modelo"]: o["textos"] for o in self.d["objetos"]}
        progresso.avisar(f"ataque/IDOR: B tenta editar {len(edicoes)} e apagar {len(apagamentos)} "
                         "objeto(s) do A", "trilha")
        self.b.garantir_csrf(self.d.get("login_url") or "/")
        self.a.garantir_csrf(self.d.get("login_url") or "/")

        # foto do banco ANTES: só conta o que mudou por causa do ataque
        antes = self.lab.estado([{"modelo": c["modelo"], "pk": c["pk"]} for c in edicoes + apagamentos]) \
            if (edicoes or apagamentos) else {}
        apagamentos = [c for c in apagamentos if (antes.get(f"{c['modelo']}:{c['pk']}") or {}).get("existe")]

        marcas = {}
        for i, c in enumerate(edicoes):
            marca = f"ARGOS-B-{i}-{self.R}"
            dados = {}
            if not c["api"]:
                r = self.a.pedir("GET", c["url"])
                if r is not None and r.status == 200 and r.html:
                    dados = _form_de_conteudo(r.texto, c['url'])
            for campo in textos.get(c["modelo"], []):
                dados[campo] = marca
            for campo in list(dados):
                if campo not in textos.get(c["modelo"], []) and isinstance(dados[campo], str) and \
                        campo in ("title", "titulo", "name", "nome", "body", "text", "texto", "content",
                                  "conteudo", "description", "descricao"):
                    dados[campo] = marca
            if c["api"]:
                self._pedir(self.b, "PATCH", c["url"], json_={k: marca for k in textos.get(c["modelo"], [])})
                self._pedir(self.b, "PUT", c["url"], json_={k: marca for k in textos.get(c["modelo"], [])})
            else:
                self._pedir(self.b, "POST", c["url"], dados=dados)
            marcas[f"{c['modelo']}:{c['pk']}"] = (marca, c)
        self._conferir_marcas(marcas)  # antes do CSRF, que mexe nos mesmos objetos
        marcas = {}

        # CSRF: o próprio A (que PODE editar) manda o form SEM token. Tem que ser recusado.
        csrf_testes = [c for c in edicoes if not c["api"]][:12]
        for j, c in enumerate(csrf_testes):
            r = self.a.pedir("GET", c["url"])
            if r is None or r.status != 200 or not r.html:
                continue
            dados = _form_de_conteudo(r.texto, c['url'])
            dados.pop("csrfmiddlewaretoken", None)
            marca = f"ARGOS-CSRF-{j}-{self.R}"
            for campo in textos.get(c["modelo"], []):
                dados[campo] = marca
            self._pedir(self.a, "POST", c["url"], dados=dados, csrf=False)
            marcas.setdefault(f"{c['modelo']}:{c['pk']}#csrf", (marca, c))

        self._conferir_marcas(marcas)
        self._apagar(apagamentos)

    def _conferir_marcas(self, marcas):
        if marcas:
            estado = self.lab.estado([{"modelo": c["modelo"], "pk": c["pk"]} for _, c in marcas.values()])
            for chave, (marca, c) in marcas.items():
                st = estado.get(f"{c['modelo']}:{c['pk']}") or {}
                mudou = any(marca in str(v) for v in (st.get("texto") or {}).values())
                if not mudou:
                    continue
                if chave.endswith("#csrf"):
                    self._add(("csrf", c["nome"]), f"Formulário aceita POST sem token CSRF ({c['nome']})", A,
                              "CWE-352", f"POST {c['url']}",
                              "o próprio dono mandou o formulário sem csrfmiddlewaretoken e o objeto mudou",
                              "Tirar o @csrf_exempt / manter o CsrfViewMiddleware; em API com sessão, usar "
                              "SessionAuthentication (que cobra CSRF).")
                else:
                    self._add(("idor-edit", c["nome"]), f"IDOR: outro usuário EDITA o que é do dono ({c['nome']})",
                              A if not c["api"] else C, "CWE-639", f"{'PATCH' if c['api'] else 'POST'} {c['url']}",
                              f"B (usuário comum) mudou o texto de {c['modelo']} #{c['pk']} do A para '{marca}'",
                              "Conferir o dono antes de salvar (obj.user == request.user ou staff) ou buscar já "
                              "filtrando pelo usuário. Escrever o teste: B tenta e recebe 403/404.",
                              lentes=(Lente.CRITICO, Lente.LGPD))

    def _apagar(self, apagamentos):
        # apagar por último (é destrutivo), UM POR VEZ: confere se o alvo ainda existe antes do
        # ataque, porque apagar um post pode levar os comentários junto (cascata não é IDOR)
        existe: dict[str, bool] = {}
        for i, c in enumerate(apagamentos):
            chave = f"{c['modelo']}:{c['pk']}"
            if not existe.get(chave, True):
                continue  # já sumiu em cascata (ex.: comentário do post apagado antes)
            if c["api"]:
                self._pedir(self.b, "DELETE", c["url"])
            else:
                self._pedir(self.b, "POST", c["url"], dados={})
            estado = self.lab.estado([{"modelo": x["modelo"], "pk": x["pk"]} for x in apagamentos[i:]])
            existe = {k: v.get("existe", False) for k, v in estado.items()}
            if not existe.get(chave, True):
                self._add(("idor-del", c["nome"]), f"IDOR: outro usuário APAGA o que é do dono ({c['nome']})",
                          C, "CWE-639", f"{'DELETE' if c['api'] else 'POST'} {c['url']}",
                          f"B (usuário comum) apagou {c['modelo']} #{c['pk']} do A",
                          "Conferir o dono antes de apagar (obj.user == request.user ou staff/moderador) e "
                          "testar: B tenta apagar e recebe 403/404.", lentes=(Lente.CRITICO, Lente.LGPD))

    # ---------------------------------------------------------------- 2) vazamento e XSS armazenado
    def vazamento_e_xss(self):
        urls = [r["url"] for r in self.d["rotas"]] + \
               [c["url"] for c in self.d["candidatos"] if not c["mutacao"] and not c["api"]]
        urls = list(dict.fromkeys(urls))[:250]
        progresso.avisar(f"ataque/vazamento+XSS: {len(urls)} página(s) como anônimo e como B", "trilha")
        xss = self.d["xss"]
        for url in urls:
            for quem in (self.anon, self.b, self.a):
                r = self._pedir(quem, "GET", url)
                if r is None or r.status != 200:
                    continue
                texto = r.texto
                if quem is not self.a and self.email_a in texto:
                    anon = quem is self.anon
                    self._add(("vaza", url, quem.nome), f"E-mail de outro usuário aparece pra {quem.nome}",
                              A if anon else M, "CWE-359", f"GET {url}",
                              f"o e-mail do usuário A apareceu na página vista por {quem.nome}",
                              "Não mostrar e-mail (dado pessoal) de outros usuários; mostrar só o nome público.",
                              lentes=(Lente.LGPD,))
                if r.html and xss in texto:
                    self._add(("xss", url), "XSS armazenado: texto do usuário volta SEM escape", A, "CWE-79",
                              f"GET {url}", f"o marcador {xss} gravado pelo A aparece cru no HTML",
                              "Nunca usar |safe/mark_safe em texto de usuário; Markdown com HTML cru desligado e "
                              "sanitização (bleach/nh3).")

    # ---------------------------------------------------------------- 3) XSS refletido e injeção
    def refletido_e_injecao(self):
        rotas = [r["url"] for r in self.d["rotas"]][:120]
        progresso.avisar(f"ataque/XSS refletido + injeção: {len(rotas)} rota(s)", "trilha")
        marca = f"<argos-rx-{self.R}>"
        for url in rotas:
            base = self.b.pedir("GET", url)
            if base is not None and base.status >= 500:
                self.quebra_sempre.add(url)  # já quebra sem nada estranho: não é sobre as aspas
                continue
            sep = "&" if "?" in url else "?"
            q = urlencode({"q": marca, "busca": marca, "search": marca, "next": marca, "tipo": marca})
            r = self._pedir(self.b, "GET", f"{url}{sep}{q}")
            if r is not None and r.html and marca in r.texto:
                self._add(("rx", url), "XSS refletido: parâmetro da URL volta SEM escape", A, "CWE-79",
                          f"GET {url}?q=…", f"{marca} enviado na URL apareceu cru na página",
                          "Escapar tudo que vem da URL antes de mostrar (o template do Django já escapa; "
                          "procure |safe, mark_safe ou HTML montado em Python/JS).")
            q = urlencode({"q": "argos'\"", "page": "1'", "id": "1'", "ordem": "'", "order": "'"})
            r = self._pedir(self.b, "GET", f"{url}{sep}{q}")
            if r is not None and (r.status >= 500 or ERRO_BANCO.search(r.texto)):
                self._add(("sqli", url), "Aspas na URL quebram a página (possível injeção SQL)",
                          M if r.status >= 500 else A, "CWE-89", f"GET {url}?q='",
                          f"com aspas nos parâmetros a resposta foi {r.status}"
                          + (" e mostrou erro de banco" if ERRO_BANCO.search(r.texto) else ""),
                          "Usar sempre o ORM/parametros (%s), nunca f-string em SQL; validar int() de página/ID.")

    # ---------------------------------------------------------------- 4) login: open redirect e força bruta
    def login(self):
        url = self.d.get("login_url")
        if not url:
            progresso.avisar("ataque/login: não achei a página de login, pulando", "pulado")
            return
        visitante = Sessao(self.lab.base, "visitante", csrf_cookie=self.d["csrf_cookie"])
        r = visitante.pedir("GET", url)
        if r is None or r.status != 200:
            return
        campos = _form_de_conteudo(r.texto, url)
        usuario = next((k for k in campos if re.search(r"(user|login|email)", k, re.I)), "username")
        senha = next((k for k in campos if re.search(r"(pass|senha)", k, re.I)), "password")
        dados = dict(campos)
        dados.update({usuario: self.d["usuarios"]["a"]["username"], senha: self.d["senha"],
                      "next": "https://argos-malicioso.invalid/roubo"})
        r = visitante.pedir("POST", f"{url}?next=https://argos-malicioso.invalid/roubo", dados=dados)
        destino = (r.headers.get("location", "") if r is not None else "")
        if destino.startswith(("http://", "https://", "//")) and "argos-malicioso" in destino:
            self._add(("redir",), "Open redirect no login: manda o usuário pra outro site", M, "CWE-601",
                      f"POST {url}?next=…", f"depois do login o servidor redirecionou pra {destino[:80]}",
                      "Validar o next com url_has_allowed_host_and_scheme antes de redirecionar.")

        progresso.avisar("ataque/força bruta: 25 senhas erradas seguidas no login", "trilha")
        bloqueou = False
        atacante = Sessao(self.lab.base, "atacante", csrf_cookie=self.d["csrf_cookie"])
        atacante.pedir("GET", url)
        aviso = re.compile(r"(muitas tentativas|too many|tente novamente (mais tarde|em)|temporariamente bloquead|"
                           r"rate limit|limite de tentativas)", re.I)
        primeira = None
        for n in range(25):
            dados = dict(campos)
            dados.update({usuario: self.d["usuarios"]["b"]["username"], senha: f"errada-{n}"})
            r = atacante.pedir("POST", url, dados=dados)
            if r is None:
                continue
            if primeira is None:
                primeira = set(m.group(0).lower() for m in aviso.finditer(r.texto))
            novos = set(m.group(0).lower() for m in aviso.finditer(r.texto)) - primeira
            if r.status in (403, 429) or novos:  # aviso que NÃO existia na 1ª tentativa
                bloqueou = True
                break
        if not bloqueou:
            self._add(("forca",), "Login sem limite de tentativas (força bruta)", M, "CWE-307", f"POST {url}",
                      "25 senhas erradas seguidas e nenhum bloqueio (403/429 ou aviso)",
                      "Limitar tentativas por usuário e IP (django-ratelimit ou django-axes).", lentes=(Lente.BOT,))

    # ---------------------------------------------------------------- 5) carga até quebrar
    def carga(self):
        if self.sem_carga:
            return
        paginas = [r["url"] for r in self.d["rotas"] if r["url"] in ("/",)] or ["/"]
        extras = [r["url"] for r in self.d["rotas"] if r["url"] != "/"][:12]
        for url in extras:
            r = self.anon.pedir("GET", url)
            if r is not None and r.status == 200:
                paginas.append(url)
            if len(paginas) >= 4:
                break
        progresso.avisar(f"ataque/carga: rampa de acessos simultâneos até {self.carga_max} em "
                         f"{', '.join(paginas)}", "trilha")
        estavel, quebra, resumo = 0, None, []
        nivel = 1
        inicio = time.monotonic()
        while nivel <= self.carga_max and time.monotonic() - inicio < 150:
            progresso.checar()
            tempos, falhas = [], 0
            trava = threading.Lock()
            total = max(20, nivel * 6)

            def um(i):
                nonlocal falhas
                s = Sessao(self.lab.base, "carga")
                t0 = time.monotonic()
                r = s.pedir("GET", paginas[i % len(paginas)], timeout=15)
                dt = time.monotonic() - t0
                with trava:
                    if r is None or r.status >= 500:
                        falhas += 1
                    else:
                        tempos.append(dt)

            t0 = time.monotonic()
            with ThreadPoolExecutor(max_workers=nivel) as ex:
                list(ex.map(um, range(total)))
            duracao = time.monotonic() - t0
            taxa_erro = falhas / total
            p95 = statistics.quantiles(tempos, n=20)[-1] if len(tempos) >= 20 else (max(tempos) if tempos else 99)
            resumo.append(f"{nivel} simultâneos: {total / duracao:.0f} req/s, p95 {p95 * 1000:.0f} ms, "
                          f"{taxa_erro * 100:.0f}% erro")
            progresso.avisar("ataque/carga: " + resumo[-1], "req")
            if taxa_erro > 0.05 or p95 > 5 or not self.lab.vivo():
                quebra = nivel
                break
            estavel = nivel
            nivel *= 2
        caiu = not self.lab.vivo()
        detalhe = " | ".join(resumo[-4:])
        if caiu:
            self._add(("carga-caiu",), f"Servidor CAIU com {quebra} acessos simultâneos e não voltou", A, "CWE-400",
                      "carga · " + ", ".join(paginas), detalhe,
                      "Ver o log do servidor; em produção, rodar com workers suficientes e limitar requisições "
                      "por IP no proxy (Cloudflare/nginx).", lentes=(Lente.BOT,))
        elif quebra is not None and quebra <= 8:
            self._add(("carga",), f"Aguenta pouca carga: degrada com {quebra} acessos simultâneos", M, "CWE-400",
                      "carga · " + ", ".join(paginas), detalhe,
                      "Procurar consultas repetidas (N+1) e páginas pesadas; cache das páginas públicas.",
                      lentes=(Lente.BOT,))
        else:
            fim = f"degradou em {quebra}" if quebra else f"aguentou até {estavel} (limite do teste)"
            self._add(("carga-info",), f"Carga: estável até {estavel} acessos simultâneos, {fim}", I, "CWE-400",
                      "carga · " + ", ".join(paginas), detalhe,
                      "Número do servidor de desenvolvimento na tua máquina: serve pra comparar antes/depois, "
                      "não é a capacidade de produção.", lentes=(Lente.BOT,))

    # ---------------------------------------------------------------- tudo
    def rodar(self) -> list[Finding]:
        from . import ataques_extra as ex
        etapas = [
            # 1) só leem
            self.vazamento_e_xss, lambda: ex.vazamento_privado(self), lambda: ex.websocket(self),
            self.refletido_e_injecao, self.login,
            # 2) criam coisas (B ainda é usuário comum)
            lambda: ex.privilegio(self), lambda: ex.upload(self), lambda: ex.logica(self),
            # 3) editam e APAGAM o que é do A
            self.idor_e_csrf,
            # 4) pode transformar o B em admin: por isso depois de tudo que precisa do B comum
            lambda: ex.mass_assignment(self),
            lambda: ex.mapa_lgpd(self),
            self.carga,
        ]
        for etapa in etapas:
            progresso.checar()
            if not self.lab.vivo():
                self.lab.reiniciar()
            try:
                etapa()
            except Exception as e:  # noqa: BLE001 - um ataque que quebra não derruba os outros
                progresso.avisar(f"ataque: uma etapa falhou ({type(e).__name__}: {str(e)[:120]})", "erro")
        self.erros500 = {e for e in self.erros500
                         if e.split(" ", 1)[1].split("?")[0] not in self.quebra_sempre}
        if self.quebra_sempre:
            lista = sorted(self.quebra_sempre)
            self._add(("500-sempre",), f"{len(lista)} rota(s) dão erro 500 até sem entrada estranha no laboratório",
                      I, "CWE-755", lista[0], "; ".join(lista[:6]),
                      "No laboratório as chaves do .env ficam em branco: rota que depende delas (ex.: login com "
                      "Google sem configurar) quebra aqui. Confira se em produção ela responde certo.")
        if self.erros500:
            exemplos = sorted(self.erros500)[:6]
            self._add(("500",), f"{len(self.erros500)} rota(s) dão erro 500 com entrada inesperada", B, "CWE-755",
                      exemplos[0], "; ".join(exemplos),
                      "Tratar entrada inválida com 400/404 em vez de deixar estourar exceção.")
        return self.achados
