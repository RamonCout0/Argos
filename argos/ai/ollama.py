"""
Argos — cliente do Ollama, preso ao local.

O endereço do Ollama passa pela MESMA trava dos alvos: só loopback ou rede
privada. Se alguém apontar OLLAMA_URL pra um servidor na internet, o Argos
recusa — teu código não sai da tua máquina/rede.

Configuração (variável de ambiente ou .env):
  OLLAMA_URL    padrão http://localhost:11434
  ARGOS_MODELO  padrão llama3.1:8b   (pra código, qwen2.5-coder:7b costuma ir bem)
"""
from __future__ import annotations

import json
import urllib.request
from typing import Optional

from ..config import carregar
from ..guard.target_lock import validar_alvo, AlvoNaoLocal

URL_PADRAO = "http://localhost:11434"
MODELO_PADRAO = "llama3.1:8b"


class OllamaIndisponivel(Exception):
    pass


class Ollama:
    def __init__(self, url: Optional[str] = None, modelo: Optional[str] = None, timeout: int = 120):
        self.url = (url or carregar("OLLAMA_URL", URL_PADRAO)).rstrip("/")
        self.modelo = modelo or carregar("ARGOS_MODELO", MODELO_PADRAO)
        self.timeout = timeout

    def _garantir_local(self) -> None:
        try:
            validar_alvo(self.url)
        except AlvoNaoLocal as e:
            raise OllamaIndisponivel(
                f"OLLAMA_URL precisa ser local ({self.url}). O codigo nao sai da maquina. {e}"
            ) from e

    def _req(self, caminho: str, payload: Optional[dict] = None, timeout: Optional[int] = None) -> dict:
        self._garantir_local()
        dados = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.url + caminho,
            data=dados,
            headers={"Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read().decode("utf-8"))
        except OSError as e:
            raise OllamaIndisponivel(f"nao consegui falar com o Ollama em {self.url}: {e}") from e

    def modelos(self) -> list[str]:
        return [m.get("name", "") for m in self._req("/api/tags", timeout=5).get("models", [])]

    def status(self) -> tuple[bool, str]:
        try:
            nomes = self.modelos()
        except OllamaIndisponivel as e:
            return False, str(e)
        if self.modelo in nomes or f"{self.modelo}:latest" in nomes:
            return True, f"Ollama ok em {self.url}, modelo {self.modelo}."
        lista = ", ".join(nomes) or "nenhum"
        return False, (
            f"Modelo {self.modelo} nao encontrado (instalados: {lista}). "
            f"Rode: ollama pull {self.modelo}  ou defina ARGOS_MODELO."
        )

    def gerar_json(self, sistema: str, prompt: str) -> dict:
        """Uma resposta em JSON, com temperatura 0 e seed fixa (o mais estavel possivel)."""
        resp = self._req("/api/generate", {
            "model": self.modelo,
            "system": sistema,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0, "seed": 42},
        })
        try:
            return json.loads(resp.get("response", ""))
        except json.JSONDecodeError as e:
            raise OllamaIndisponivel(f"modelo nao devolveu JSON valido: {e}") from e
