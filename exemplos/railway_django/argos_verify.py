"""
Endpoint de verificacao do Argos pra um site Django (ex.: hospedado no Railway).

Como usar:
  1. Copie este arquivo pro teu app Django (ex.: core/argos_verify.py).
  2. No urls.py do projeto:
         from core.argos_verify import argos_verify
         urlpatterns += [path(".well-known/argos-verify.txt", argos_verify)]
  3. No Railway, em Variables do servico, crie ARGOS_SECRET com o MESMO
     valor do .env do Argos.

Seguranca:
  - O segredo NUNCA sai do servidor: so o HMAC da semana e publicado.
  - Sem ARGOS_SECRET definido, a rota responde 404 (interruptor de emergencia:
    apagou a variavel no Railway, o Argos para de aceitar o site).
  - O token muda sozinho toda semana ISO (UTC).
"""
import datetime
import hashlib
import hmac
import os

from django.http import Http404, HttpResponse


def argos_verify(request):
    segredo = os.environ.get("ARGOS_SECRET")
    if not segredo:
        raise Http404()
    host = request.get_host().split(":")[0].lower()
    ano, semana, _ = datetime.datetime.now(datetime.timezone.utc).date().isocalendar()
    msg = f"argos-verify|{host}|{ano}-W{semana:02d}".encode()
    token = hmac.new(segredo.encode(), msg, hashlib.sha256).hexdigest()
    resp = HttpResponse(token, content_type="text/plain")
    resp["Cache-Control"] = "no-store"
    return resp
