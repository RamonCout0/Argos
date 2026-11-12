"""
App INSEGURO DE PROPOSITO pra testar a trilha web do Argos.

Escuta SO em 127.0.0.1 (nunca na rede). Tudo aqui e falso: chaves, senhas, .env.

    python exemplos/web_inseguro.py           # sobe em http://127.0.0.1:8766
    python cli.py web http://127.0.0.1:8766   # noutro terminal

O que ele erra de proposito (o Argos deve achar):
  - .env e .git publicados              - listagem de /media/
  - chave "AWS" falsa no main.js        - source map publicado
  - cookie de sessao sem HttpOnly       - CORS que reflete qualquer origem com credenciais
  - versao do servidor no cabecalho     - sem CSP / X-Frame-Options / nosniff
  - pagina de erro do Django em DEBUG   - /admin/ no caminho padrao
  - metodo TRACE ecoando a requisicao
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORTA = "127.0.0.1", 8766

HOME = b"""<!doctype html><html><head><title>Loja Exemplo</title></head>
<body><h1>Loja Exemplo</h1><script src="/main.js"></script></body></html>"""

MAIN_JS = (b"const cfg = { regiao: 'sa-east-1', chave: 'AKIA" + b"FALSAFALSAFALSA1" + b"' };\n"
           b"console.log('ola');\n//# sourceMappingURL=main.js.map\n")
MAPA = b'{"version":3,"sources":["src/app/loja.ts"],"mappings":"AAAA"}'
ENV = b"DEBUG=True\nSECRET_KEY=falsa-nao-use\nDATABASE_URL=postgres://u:falsa@localhost/db\n"
GIT_HEAD = b"ref: refs/heads/main\n"
MEDIA = b"""<html><head><title>Index of /media/</title></head>
<body><h1>Index of /media/</h1><ul><li><a href="rg_cliente.pdf">rg_cliente.pdf</a></li></ul></body></html>"""
ADMIN = b"""<html><head><title>Log in | Django site admin</title></head><body>
<h1>Django administration</h1><form><input id="id_username" name="username"></form></body></html>"""
ERRO_DEBUG = b"""<html><body><h1>Page not found (404)</h1>
<ol><li>admin/</li><li>api/</li><li>api/clientes/</li></ol>
<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>
</body></html>"""

ROTAS = {
    "/": ("text/html; charset=utf-8", HOME),
    "/main.js": ("application/javascript", MAIN_JS),
    "/main.js.map": ("application/json", MAPA),
    "/.env": ("text/plain", ENV),
    "/.git/HEAD": ("text/plain", GIT_HEAD),
    "/media/": ("text/html", MEDIA),
    "/admin/login/": ("text/html", ADMIN),
}


class Inseguro(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"   # versao exposta de proposito
    sys_version = ""

    def log_message(self, *a):  # silencioso
        pass

    def _cors(self):
        origem = self.headers.get("Origin")
        if origem:
            self.send_header("Access-Control-Allow-Origin", origem)
            self.send_header("Access-Control-Allow-Credentials", "true")

    def _responder(self, status, tipo, corpo, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self._cors()
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corpo)

    def do_GET(self):
        caminho = self.path.split("?")[0]
        if caminho == "/admin/":
            self.send_response(302)
            self.send_header("Location", "/admin/login/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if caminho in ROTAS:
            tipo, corpo = ROTAS[caminho]
            extra = [("Set-Cookie", "sessionid=abc123falso; Path=/")] if caminho == "/" else None
            self._responder(200, tipo, corpo, extra)
        else:
            self._responder(404, "text/html", ERRO_DEBUG)

    do_HEAD = do_GET

    def do_TRACE(self):
        eco = f"TRACE {self.path} HTTP/1.1\r\n{self.headers}".encode()
        self._responder(200, "message/http", eco)


def criar(porta: int = PORTA) -> ThreadingHTTPServer:
    """Fabrica usada pelos testes (porta 0 = qualquer livre)."""
    return ThreadingHTTPServer((HOST, porta), Inseguro)


if __name__ == "__main__":
    porta = int(sys.argv[1]) if len(sys.argv) > 1 else PORTA
    srv = criar(porta)
    print(f"App inseguro (de proposito) em http://{HOST}:{srv.server_address[1]}  — Ctrl+C pra parar")
    print(f"Teste: python cli.py web http://{HOST}:{srv.server_address[1]}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
