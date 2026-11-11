"""
Servidor de TESTE pra trilha nativa do Argos.

    python exemplos/servidor_exposto.py            -> escuta em 0.0.0.0:8765 (o erro classico)
    python exemplos/servidor_exposto.py --seguro   -> escuta so em 127.0.0.1:8765

Em outro terminal:
    python cli.py nativo --porta 8765
    python cli.py nativo --porta 8765 --rede       (com nmap: confirma pelo IP da rede)

Responde so um texto fixo (nao serve arquivo nenhum). Ctrl+C pra parar.
No modo exposto, o Firewall do Windows pode perguntar se libera a rede: isso
ja e a licao — negue, e veja que o certo e nem precisar perguntar.
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORTA = 8765


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        corpo = b"Argos: servidor de teste.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    host = "127.0.0.1" if "--seguro" in sys.argv else "0.0.0.0"
    print(f"servidor de teste em {host}:{PORTA}  (Ctrl+C pra parar)")
    try:
        HTTPServer((host, PORTA), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
