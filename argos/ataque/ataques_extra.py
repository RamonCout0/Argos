"""
Argos — ataques do v3.1: privilégio, mass assignment, vazamento por API e
WebSocket, upload malicioso, abuso de lógica e mapa de dados pessoais.

Mesma regra do resto: só acusa o que CONFIRMOU (banco, arquivo gravado,
resposta com o dado de outro). O que é só suspeita vem com "(revisar)".
"""
from __future__ import annotations

import base64
import os
import re
import secrets
import socket
from urllib.parse import urlsplit

from ..core import progresso
from ..schema import Severidade, Lente
from .ataques import Sessao, ler_forms

C, A, M, B, I = (Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO, Severidade.BAIXO, Severidade.INFO)
# rotas que estragariam a sessão do B ou mexem na conta dele de um jeito que atrapalha o resto
PERIGOSAS_PRO_B = re.compile(r"(password|senha|logout|sair|excluir.?conta|delete.?account|desativar|deactivate|"
                             r"/email|privacidade/excluir|meus-dados/apagar)", re.I)
CAMPOS_TEXTO = ("text", "texto", "content", "conteudo", "body", "comment", "comentario", "mensagem", "message",
                "title", "titulo", "name", "nome", "description", "descricao", "bio")
CAMPOS_PRIVILEGIO = {"is_staff": "on", "is_superuser": "on", "is_admin": "on", "is_developer": "on",
                     "is_moderator": "on", "role": "admin", "papel": "admin", "staff": "on", "admin": "on",
                     "verified": "on", "is_verified": "on"}
CAMPOS_DONO = ("user", "owner", "author", "autor", "created_by", "dono", "usuario", "sender")
PRIVADO_WS = re.compile(r"(dm|chat|mensag|message|notif|grupo|group|privad|private|inbox)", re.I)
CRIAR = re.compile(r"(comentar|comment|responder|reply|enviar|send|novo|nova|new|criar|create|publicar)", re.I)


def _preencher(campos: dict, marca: str) -> dict:
    dados = dict(campos)
    for k in list(dados):
        if k.lower() in CAMPOS_TEXTO or any(t in k.lower() for t in ("text", "titul", "conteud", "coment")):
            dados[k] = marca
    for k in CAMPOS_TEXTO[:6]:
        dados.setdefault(k, marca)
    return dados


def _png_1x1() -> bytes:
    """PNG 1x1 de verdade (assinatura, IHDR, IDAT e IEND com CRC certo): o Pillow aceita."""
    import struct
    import zlib

    def bloco(tipo, dados):
        return struct.pack(">I", len(dados)) + tipo + dados + struct.pack(">I", zlib.crc32(tipo + dados) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x99\x66\xff")
    return b"\x89PNG\r\n\x1a\n" + bloco(b"IHDR", ihdr) + bloco(b"IDAT", idat) + bloco(b"IEND", b"")


PNG_VALIDO = _png_1x1()


def _arquivos_validos(form) -> dict:
    """Imagem 1x1 de verdade pros campos de arquivo (sem ela, form com capa obrigatória é inválido)."""
    return {campo: (f"argos-{i}.png", PNG_VALIDO, "image/png") for i, campo in enumerate(form["arquivos"])}


def forms_de_conteudo(html: str, url: str, maximo: int = 2) -> list[dict]:
    """Os formulários que importam: sem logout/senha e com mais campos primeiro (o 'Sair' da barra de
    navegação costuma ser o primeiro POST de toda página)."""
    bons = [f for f in ler_forms(html)
            if (f["acao"] or url).startswith("/") and not PERIGOSAS_PRO_B.search(f["acao"] or url)
            and (len(f["campos"]) + len(f["arquivos"])) > 1]
    bons.sort(key=lambda f: len(f["campos"]) + len(f["arquivos"]), reverse=True)
    return bons[:maximo]


def _paginas_com_form(atq, sessao, urls, limite=40):
    """(url, form) dos formulários POST que a sessão consegue abrir."""
    saida = []
    for url in urls:
        if len(saida) >= limite:
            break
        r = sessao.pedir("GET", url)
        if r is None or r.status != 200 or not r.html:
            continue
        for f in forms_de_conteudo(r.texto, url, maximo=3):
            saida.append((url, f["acao"] or url, f))
    return saida


# ------------------------------------------------------------------ 1) privilégio e mass assignment

def privilegio(atq):
    """Escalada: rota que RECUSA o B na tela (GET) mas aceita o POST dele = proteção só no visual."""
    rotas = [r for r in atq.d["rotas"] if r.get("privilegiada") and not PERIGOSAS_PRO_B.search(r["url"])]
    rotas += [c for c in atq.d["candidatos"] if c.get("privilegiada") and not c["mutacao"]
              and not PERIGOSAS_PRO_B.search(c["url"])]
    progresso.avisar(f"ataque/privilégio: B (usuário comum) tenta {len(rotas)} rota(s) de staff/dev/moderador",
                     "trilha")
    marcas = {}
    for i, rota in enumerate(rotas[:60]):
        url = rota["url"]
        rb = atq.b.pedir("GET", url)
        if rb is None or rb.status == 200:
            continue  # o B abre normalmente: a função é dele também, não há o que escalar
        ra = atq.a.pedir("GET", url)  # A é staff: abre o formulário de verdade
        forms = forms_de_conteudo(ra.texto, url) if ra is not None and ra.status == 200 and ra.html else []
        for f in forms:
            acao = f["acao"] or url
            if not acao.startswith("/") or PERIGOSAS_PRO_B.search(acao):
                continue
            marca = f"ARGOS-PRIV-{i}-{atq.R}"
            atq._pedir(atq.b, "POST", acao, dados=_preencher(f["campos"], marca),
                       arquivos=_arquivos_validos(f) or None)
            marcas[marca] = acao
        if not forms and rota.get("api"):
            marca = f"ARGOS-PRIV-{i}-{atq.R}"
            atq._pedir(atq.b, "POST", url, json_={k: marca for k in CAMPOS_TEXTO[:8]})
            marcas[marca] = url
    if not marcas:
        return
    achou = atq.lab.buscar(marcas=list(marcas))["marcas"]
    for marca, objetos in achou.items():
        if objetos:
            acao = marcas[marca]
            atq._add(("priv", acao), "Escalada de privilégio: a tela barra o usuário comum, mas o POST passa", C,
                     "CWE-269", f"POST {acao}", f"o B não abre a página (GET recusado), mas o POST dele criou/alterou "
                     f"{objetos[0]['modelo']}",
                     "A checagem de staff/dev/moderador tem que valer no POST também (o mesmo mixin/decorador na "
                     "view inteira). Teste: usuário comum faz o POST e recebe 403.", lentes=(Lente.CRITICO,))


def mass_assignment(atq):
    urls = [r["url"] for r in atq.d["rotas"] if not r.get("privilegiada") and not PERIGOSAS_PRO_B.search(r["url"])]
    forms = _paginas_com_form(atq, atq.b, urls)
    api = [r["url"] for r in atq.d["rotas"] if r.get("api") and not PERIGOSAS_PRO_B.search(r["url"])]
    progresso.avisar(f"ataque/mass assignment: {len(forms)} formulário(s) e {len(api)} rota(s) de API com "
                     "campos a mais (is_staff, user=A...)", "trilha")
    a_id = atq.d["usuarios"]["a"]["id"]
    marcas = {}
    extras = dict(CAMPOS_PRIVILEGIO)
    extras.update({k: str(a_id) for k in CAMPOS_DONO})
    for i, (pagina, acao, f) in enumerate(forms):
        marca = f"ARGOS-MASS-{i}-{atq.R}"
        dados = _preencher(f["campos"], marca)
        dados.update(extras)  # por cima do que a tela trouxe: é o atacante quem escolhe o valor
        atq._pedir(atq.b, "POST", acao, dados=dados, arquivos=_arquivos_validos(f) or None)
        marcas[marca] = acao
        fuzz = {k: ("x" * 12000 if isinstance(v, str) and v else "-1") for k, v in f["campos"].items()
                if k != "csrfmiddlewaretoken"}
        if fuzz:
            atq._pedir(atq.b, "POST", acao, dados=fuzz)  # entrada absurda: só não pode dar 500
    for j, url in enumerate(api[:30]):
        marca = f"ARGOS-MASSAPI-{j}-{atq.R}"
        corpo = {k: marca for k in CAMPOS_TEXTO[:8]}
        corpo.update({k: True for k in ("is_staff", "is_superuser", "is_admin", "is_developer")})
        corpo.update({k: a_id for k in CAMPOS_DONO})
        for metodo in ("POST", "PATCH"):
            atq._pedir(atq.b, metodo, url, json_=corpo)
        marcas[marca] = url
    b_id = atq.d["usuarios"]["b"]["id"]
    res = atq.lab.buscar(marcas=list(marcas), usuarios=[b_id])
    u = (res.get("usuarios") or {}).get(str(b_id)) or {}
    if u.get("is_staff") or u.get("is_superuser"):
        atq._add(("mass-staff",), "Mass assignment: usuário comum vira staff/admin mandando campo a mais", C,
                 "CWE-915", "POST (formulário/API do usuário)", f"depois do ataque o B ficou com is_staff="
                 f"{u.get('is_staff')} e is_superuser={u.get('is_superuser')}",
                 "No form/serializer, listar só os campos permitidos (fields = [...]) e nunca '__all__'; "
                 "is_staff e afins como read_only.", lentes=(Lente.CRITICO,))
    for marca, objetos in (res.get("marcas") or {}).items():
        for o in objetos:
            if any(str(v) == str(a_id) for v in (o.get("donos") or {}).values()) and \
                    not any(str(v) == str(b_id) for v in (o.get("donos") or {}).values()):
                atq._add(("mass-dono", marcas[marca]), "Mass assignment: B cria/edita em nome do A", A, "CWE-915",
                         f"POST {marcas[marca]}", f"{o['modelo']} #{o['pk']} foi gravado com o dono = A, "
                         "mas quem mandou foi o B (campo user/autor veio do formulário)",
                         "O dono tem que vir do servidor (obj.user = request.user), nunca do que o cliente manda.",
                         lentes=(Lente.CRITICO,))
                break


# ------------------------------------------------------------------ 2) vazamento por API e WebSocket

def vazamento_privado(atq):
    privados = atq.d.get("privados") or []
    if not privados:
        return
    urls = [r["url"] for r in atq.d["rotas"]] + [c["url"] for c in atq.d["candidatos"] if not c["mutacao"]]
    urls = list(dict.fromkeys(urls))[:300]
    marcas = {m: f"argos {atq.R} {m}" for m in privados}
    progresso.avisar(f"ataque/vazamento privado: procurando {', '.join(privados)} do A em {len(urls)} "
                     "resposta(s) (HTML e JSON)", "trilha")
    for url in urls:
        for quem in (atq.anon, atq.b):
            r = atq._pedir(quem, "GET", url)
            if r is None or r.status != 200:
                continue
            texto = r.texto
            for modelo, marca in marcas.items():
                if marca in texto:
                    atq._add(("priv-vaza", modelo, url, quem.nome),
                             f"Conteúdo privado ({modelo}) do A aparece pra {quem.nome}", C if quem is atq.anon else A,
                             "CWE-639", f"GET {url}", f"o texto de um(a) {modelo} do usuário A apareceu "
                             f"na resposta {'JSON' if not r.html else 'HTML'} vista por {quem.nome}",
                             "Filtrar a consulta pelo usuário logado (ex.: mensagens onde sender/receiver = "
                             "request.user) também nos endpoints da API.", lentes=(Lente.CRITICO, Lente.LGPD))


def _ws_aceita(base, caminho, cookies) -> bool:
    host, porta = urlsplit(base).hostname, urlsplit(base).port
    chave = base64.b64encode(secrets.token_bytes(16)).decode()
    req = (f"GET {caminho} HTTP/1.1\r\nHost: {host}:{porta}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {chave}\r\nSec-WebSocket-Version: 13\r\nOrigin: {base}\r\n")
    if cookies:
        req += "Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items()) + "\r\n"
    try:
        with socket.create_connection((host, porta), timeout=6) as s:
            s.sendall((req + "\r\n").encode())
            resposta = s.recv(512).decode("latin-1", "replace")
            if " 101 " not in resposta.split("\r\n", 1)[0]:
                return False
            s.settimeout(1.5)  # o consumidor pode aceitar e fechar logo em seguida (close = recusou)
            try:
                quadro = s.recv(2)
            except socket.timeout:
                return True
            return not (quadro and (quadro[0] & 0x0F) == 0x8)
    except OSError:
        return False


def websocket(atq):
    rotas = atq.d.get("ws") or []
    if not rotas:
        return
    progresso.avisar(f"ataque/WebSocket: {len(rotas)} rota(s)", "trilha")
    for r in rotas:
        url = r["url"]
        if not PRIVADO_WS.search(url):
            continue  # sala pública (ex.: comentários ao vivo) pode aceitar qualquer um
        if r.get("proprio"):
            if _ws_aceita(atq.lab.base, url, {}):
                atq._add(("ws-anon", url), "WebSocket privado aceita conexão sem login", A, "CWE-306", f"WS {url}",
                         "um visitante sem login abriu e manteve a conexão num canal de chat/notificação",
                         "No connect() do consumer: se o scope['user'] não está logado, close().",
                         lentes=(Lente.CRITICO, Lente.LGPD))
        elif _ws_aceita(atq.lab.base, url, atq.b.cookies):
            atq._add(("ws-idor", url), "B entra no canal WebSocket privado do A", A, "CWE-639", f"WS {url}",
                     f"o B abriu e manteve a conexão no canal que leva o ID/nome do A ({r.get('modelo', '')})",
                     "No connect(): conferir que o usuário do scope é dono/participante do canal antes do accept().",
                     lentes=(Lente.CRITICO, Lente.LGPD))


# ------------------------------------------------------------------ 3) upload malicioso

def upload(atq):
    urls = [r["url"] for r in atq.d["rotas"] if not PERIGOSAS_PRO_B.search(r["url"])]
    urls += [c["url"] for c in atq.d["candidatos"] if not PERIGOSAS_PRO_B.search(c["url"])
             and re.search(r"(edit|editar|novo|nova|new|criar|create|upload|enviar|perfil|avatar|banner)",
                           c["nome"] + c["rota"], re.I)]
    alvos = []
    for quem in (atq.b, atq.a):
        for pagina, acao, f in _paginas_com_form(atq, quem, list(dict.fromkeys(urls)), limite=120):
            if f["arquivos"] and len(alvos) < 6:
                alvos.append((quem, acao, f))
    if not alvos:
        return
    progresso.avisar(f"ataque/upload: {len(alvos)} formulário(s) com arquivo: SVG com script, HTML disfarçado, "
                     "nome com ../ e arquivo gigante", "trilha")
    R = atq.R
    png = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489")
    cargas = [
        ("svg", f"argos-svg-{R}.svg",
         f'<svg xmlns="http://www.w3.org/2000/svg"><script>/*argos-svg-{R}*/</script></svg>'.encode(), "image/svg+xml"),
        ("html", f"argos-html-{R}.png", f"<html><script>/*argos-html-{R}*/</script></html>".encode(), "image/png"),
        ("trav", f"../../argos-trav-{R}.txt", f"argos-trav-{R}".encode(), "text/plain"),
        ("grande", f"argos-grande-{R}.png", png + b"\0" * (25 * 1024 * 1024), "image/png"),
    ]
    for i, (quem, acao, f) in enumerate(alvos):
        papel = "comum" if quem is atq.b else "staff"
        for tipo, nome, conteudo, ctype in cargas:
            nome = nome.replace(f"-{R}", f"-{R}-{papel}", 1)
            dados = _preencher(f["campos"], f"ARGOS-UP-{i}-{R}")
            atq._pedir(quem, "POST", acao, dados=dados,
                       arquivos={campo: (nome, conteudo, ctype) for campo in f["arquivos"][:1]}, timeout=60)
    _conferir_uploads(atq)


def _conferir_uploads(atq):
    R = atq.R
    tmp = atq.lab.pasta_temporaria
    media = os.path.join(tmp, "media")
    vistos = {"svg": None, "html": None, "grande": None}
    fora = []
    for raiz in (tmp, atq.lab.projeto):
        for pasta, dirs, nomes in os.walk(raiz):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "venv", ".venv")]
            for n in nomes:
                if R not in n:
                    continue
                caminho = os.path.join(pasta, n)
                dentro = os.path.abspath(caminho).startswith(os.path.abspath(media) + os.sep)
                if f"argos-trav-{R}" in n and not dentro:
                    fora.append(caminho)
                if not dentro:
                    continue
                try:
                    tamanho = os.path.getsize(caminho)
                    with open(caminho, "rb") as fp:
                        inicio = fp.read(4096)
                except OSError:
                    continue
                if n.lower().endswith(".svg") and b"<script" in inicio:
                    vistos["svg"] = n
                if b"<html" in inicio and b"argos-html" in inicio:
                    vistos["html"] = n
                if tamanho >= 20 * 1024 * 1024:
                    vistos["grande"] = f"{n} ({tamanho // (1024 * 1024)} MB)"
        if atq.lab.projeto == tmp:
            break
    if fora:
        atq._add(("up-trav",), "Upload grava arquivo FORA da pasta de mídia (path traversal)", C, "CWE-22",
                 "upload", f"um arquivo com ../ no nome foi parar em {fora[0]}",
                 "Nunca usar o nome enviado pelo cliente como caminho; deixar o storage do Django gerar o nome.")
    if vistos["svg"]:
        comum = "-comum" in vistos["svg"]
        atq._add(("up-svg",), "Upload aceita SVG com script dentro" + ("" if comum else " (só staff consegue)"),
                 M if comum else B, "CWE-434", "upload",
                 f"o arquivo {vistos['svg']} foi gravado com <script>; se for servido do mesmo domínio do site, "
                 "o script roda pra quem abrir" + ("" if comum else ". Só quem é staff consegue enviar, então o "
                                                   "risco é uma conta de staff invadida ou mal-intencionada"),
                 "Aceitar só JPG/PNG/WebP e reprocessar com Pillow; se precisar de SVG, servir de outro domínio "
                 "(ex.: Cloudinary) ou como download, nunca do domínio principal.")
    if vistos["html"]:
        atq._add(("up-html",), "Upload não confere se a imagem é imagem de verdade", B, "CWE-434", "upload",
                 f"um HTML com extensão .png foi gravado como está ({vistos['html']})",
                 "Validar com ImageField/Pillow (abrir e reprocessar a imagem) em vez de confiar na extensão.")
    if vistos["grande"]:
        atq._add(("up-grande",), "Upload sem limite de tamanho", B, "CWE-770", "upload",
                 f"um arquivo de 25 MB foi aceito e gravado: {vistos['grande']}",
                 "Limitar o tamanho no form (validator) e no proxy (client_max_body_size / limite do Railway).",
                 lentes=(Lente.BOT,))


# ------------------------------------------------------------------ 4) abuso de lógica

def logica(atq):
    progresso.avisar("ataque/lógica: enumeração de e-mail, ação consigo mesmo e spam sem limite", "trilha")
    _enumeracao_email(atq)
    _consigo_mesmo(atq)
    _spam(atq)


def _normalizar(texto: str) -> str:
    texto = re.sub(r'name="csrfmiddlewaretoken" value="[^"]+"', "", texto)
    texto = re.sub(r"argos-\w+-[0-9a-f]{6}@example\.invalid|naoexiste-[0-9a-f]+@example\.invalid", "EMAIL", texto)
    return re.sub(r"\s+", " ", texto)


def _enumeracao_email(atq):
    url = atq.d.get("reset_url")
    if not url:
        return
    respostas = []
    for email in (atq.email_a, f"naoexiste-{atq.R}@example.invalid"):
        s = Sessao(atq.lab.base, "visitante", csrf_cookie=atq.d["csrf_cookie"])
        r = s.pedir("GET", url)
        if r is None or r.status != 200:
            return
        forms = forms_de_conteudo(r.texto, url, maximo=1)
        campos = dict(forms[0]["campos"]) if forms else {}
        campo = next((k for k in campos if "mail" in k.lower()), "email")
        campos[campo] = email
        r = s.pedir("POST", url, dados=campos)
        if r is None:
            return
        respostas.append((r.status, r.headers.get("location", ""), _normalizar(r.texto)))
    (s1, l1, t1), (s2, l2, t2) = respostas
    if s1 in (403, 429) or s2 in (403, 429):
        return  # o limite de tentativas entrou no meio: não dá pra comparar
    if s1 != s2 or l1 != l2 or abs(len(t1) - len(t2)) > max(80, 0.03 * max(len(t1), len(t2))):
        atq._add(("enum",), "\"Esqueci a senha\" revela se um e-mail tem conta", M, "CWE-204", f"POST {url}",
                 f"e-mail existente: {s1} {l1 or ''} / inexistente: {s2} {l2 or ''} (respostas diferentes)",
                 "Responder sempre igual (\"se o e-mail existir, enviamos um link\"), exista ou não a conta.",
                 lentes=(Lente.LGPD, Lente.BOT))


def _consigo_mesmo(atq):
    ua, ub = atq.d["usuarios"]["a"], atq.d["usuarios"]["b"]
    feitos = 0
    for c in atq.d["candidatos"]:
        if ua["username"] not in c["url"] or c["mutacao"] or \
                not re.search(r"(seguir|follow|mensag|message|dm|convidar|invite)", c["nome"] + c["rota"], re.I):
            continue  # só ação social (seguir, mandar mensagem); nunca remover/editar
        url = c["url"].replace(ua["username"], ub["username"])
        atq._pedir(atq.b, "POST", url, dados={"text": f"argos {atq.R}", "texto": f"argos {atq.R}"})
        feitos += 1
    if not feitos:
        return
    auto = atq.lab.buscar(autorrelacao=[ub["id"]]).get("autorrelacao") or []
    if auto:
        atq._add(("auto",), "Dá pra fazer ação consigo mesmo (seguir a si mesmo, mensagem pra si...)", B, "CWE-840",
                 "seguir/mensagem com o próprio usuário", "registros com o B nos dois lados: " + ", ".join(auto[:4]),
                 "Bloquear no servidor (e com CheckConstraint no modelo) a relação de um usuário com ele mesmo.")


def _spam(atq):
    rotas = [c for c in atq.d["candidatos"] if not c["mutacao"] and CRIAR.search(c["nome"] + c["rota"])
             and not c["api"]][:2]
    for c in rotas:
        marcas = [f"ARGOS-SPAM-{n}-{atq.R}" for n in range(40)]
        for m in marcas:
            atq._pedir(atq.b, "POST", c["url"], dados={k: m for k in CAMPOS_TEXTO})
        achou = atq.lab.buscar(marcas=marcas)["marcas"]
        criados = sum(1 for m in marcas if achou.get(m))
        if criados >= 38:
            atq._add(("spam", c["nome"]), f"Sem limite de criação: 40 envios seguidos em {c['nome']}, todos aceitos",
                     B, "CWE-770", f"POST {c['url']}", f"{criados} de 40 registros criados em segundos pelo mesmo usuário",
                     "Limitar por usuário (django-ratelimit, ex.: 10/min) pra segurar spam de robô.",
                     lentes=(Lente.BOT,))


# ------------------------------------------------------------------ 5) mapa de dados pessoais (LGPD)

def mapa_lgpd(atq):
    for item in atq.d.get("pessoais") or []:
        tipos = ", ".join(dict.fromkeys(c["tipo"] for c in item["campos"]))
        campos = ", ".join(c["campo"] for c in item["campos"])
        atq._add(("lgpd", item["modelo"]), f"Dado pessoal guardado em {item['modelo']}: {tipos}", I, "LGPD-MAPA",
                 item["modelo"], f"campos: {campos}",
                 "Registrar no inventário de dados (finalidade e base legal), mostrar só pra quem precisa e "
                 "incluir no 'baixar/excluir meus dados'.", lentes=(Lente.LGPD,))
