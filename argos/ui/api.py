"""
Argos UI — a ponte entre a tela (HTML/JS) e o motor (Python).

O pywebview expõe os métodos PÚBLICOS desta classe pro JavaScript como
window.pywebview.api.<metodo>(). Tudo que começa com "_" fica escondido.

Os scans rodam numa thread; a tela pergunta `status()` a cada 400 ms.
Esta classe não importa o pywebview no topo: dá pra testar sem janela.
"""
from __future__ import annotations

import os
import re
import threading
import webbrowser
from pathlib import Path
from typing import Optional

from .. import __version__
from ..schema import Finding, Severidade, Status, FixTipo
from ..scorer import calcular
from ..config import carregar
from ..core.aceitos import fingerprint
from ..core import aceitos as mod_aceitos
from ..core import orchestrator as orq
from ..core import progresso
from ..ai.narrator import narrar
from ..ai.ollama import Ollama, MODELO_PADRAO
from ..report.html import render_html
from ..lenses.lgpd_manual import CHECKLIST_LGPD, AVISO
from ..gui import estado as est
from ..adapters.prompt_injection import gerar_canario

RAIZ = Path(__file__).resolve().parents[2]
_ORDEM = {Severidade.CRITICO: 0, Severidade.ALTO: 1, Severidade.MEDIO: 2,
          Severidade.BAIXO: 3, Severidade.INFO: 4}


def humor(findings: list[Finding]) -> str:
    """O estado do olho: alerta (bloqueia) · ressalva (passa com pendências) · ok."""
    if not calcular(findings).aprovado:
        return "alerta"
    return "ressalva" if any(est.conta(f) for f in findings) else "ok"


class ApiArgos:
    def __init__(self, demo: Optional[list[Finding]] = None, arquivo_estado: str = est.ARQUIVO):
        self._janela = None
        self._trava = threading.Lock()
        self._arquivo = arquivo_estado
        self._estado = est.carregar(arquivo_estado)
        self._conj: dict = {"auditoria": None, "ia": None}
        self._ocupado: Optional[str] = None
        self._evento: Optional[dict] = None
        self._sessao: Optional[progresso.Sessao] = None
        if demo is not None:
            self._conj["auditoria"] = {
                "findings": demo, "chave": "demo", "resolvidos": [],
                "meta": {"alvo": "demonstração (dados de exemplo)", "rodaram": ["demo"],
                         "pulados": [], "avisos": [], "fundidos": 0, "nota_ia": ""}}

    # ------------------------------------------------------------ dados pra tela

    def _f(self, f: Finding, chave: str) -> dict:
        fp = fingerprint(f)
        conta = est.conta(f)
        return {
            "fp": fp, "id": f.id, "titulo": f.titulo, "sev": f.severidade.value,
            "categoria": f.categoria, "local": f.local, "origem": f.origem,
            "evidencia": f.evidencia, "lentes": [l.value for l in f.lentes],
            "fix": f.fix.to_dict() if f.fix else None,
            "explicacao": f.explicacao, "fonte": f.fonte_explicacao, "sugestao": f.sugestao_ia,
            "verificacao": f.verificacao, "conta": conta,
            "feito": conta and est.marcado(self._estado, chave, fp),
        }

    def _lgpd(self, chave: str) -> list[dict]:
        return [{"titulo": t, "texto": x, "feito": est.lgpd_marcado(self._estado, chave, i)}
                for i, (t, x) in enumerate(CHECKLIST_LGPD)]

    def _pacote(self, nome: str) -> Optional[dict]:
        c = self._conj.get(nome)
        if not c:
            return None
        fs, chave = c["findings"], c["chave"]
        p = calcular(fs)
        feitos, total = est.progresso(self._estado, chave, fs)
        visiveis = sorted((f for f in fs if f.status is not Status.IGNORADO),
                          key=lambda f: _ORDEM[f.severidade])
        return {
            "humor": humor(fs),
            "placar": {"score": p.score, "aprovado": p.aprovado, "bloqueantes": len(p.bloqueantes),
                       "por_severidade": p.por_severidade, "feitos": feitos, "total": total},
            "findings": [self._f(f, chave) for f in visiveis],
            "aceitos": [{"titulo": f.titulo, "justificativa": f.justificativa,
                         "sev": f.severidade.value} for f in p.riscos_aceitos],
            "lgpd": self._lgpd(chave),
            "resolvidos": c["resolvidos"],
            "chave": chave,
            "meta": {**c["meta"], "pulados": [list(x) for x in c["meta"].get("pulados", [])]},
        }

    # ------------------------------------------------------------ chamadas da tela

    def inicio(self) -> dict:
        return {
            "versao": __version__,
            "modelo": carregar("ARGOS_MODELO", MODELO_PADRAO),
            "auditoria": self._pacote("auditoria"),
            "ia": self._pacote("ia"),
            "ocupado": self._ocupado,
            "lgpd": self._lgpd("geral"),
            "aviso_lgpd": AVISO,
        }

    def status(self, desde: int = 0) -> dict:
        """Estado da varredura + as linhas novas do log (a partir da posição `desde`)."""
        sessao = self._sessao
        log, pos = sessao.desde(desde) if sessao else ([], 0)
        extra = {"log": log, "pos": pos,
                 "cancelando": bool(sessao and sessao.cancelado.is_set())}
        with self._trava:
            if self._ocupado:
                return {"ocupado": self._ocupado, **extra}
            ev, self._evento = self._evento, None
        if not ev:
            return {"ocupado": None, **extra}
        if ev.get("cancelado"):
            return {"ocupado": None, "conj": ev["conj"], "cancelado": True, **extra}
        if ev.get("erro"):
            return {"ocupado": None, "conj": ev["conj"], "erro": ev["erro"], **extra}
        return {"ocupado": None, "conj": ev["conj"], "dados": self._pacote(ev["conj"]), **extra}

    def cancelar(self) -> dict:
        """Para a varredura em andamento (scanners externos são encerrados)."""
        with self._trava:
            sessao = self._sessao if self._ocupado else None
        if sessao is None:
            return {"erro": "Não tem nenhuma varredura rodando."}
        sessao.cancelar()
        return {"ok": True}

    def auditar(self, p: dict) -> dict:
        pasta = (p.get("pasta") or "").strip()
        pcap = (p.get("pcap") or "").strip()
        try:
            portas = [int(x) for x in str(p.get("portas") or "").replace(";", ",").split(",") if x.strip()]
        except ValueError:
            return {"erro": "Portas devem ser números separados por vírgula, ex.: 8000, 4200"}
        urls = [u.strip().rstrip("/") for u in str(p.get("urls") or "").replace(";", ",").replace(" ", ",").split(",")
                if u.strip()]
        for u in urls:
            if not re.match(r"^https?://[^\s/]+", u):
                return {"erro": f"URL inválida: {u} (use http:// ou https://, ex.: http://127.0.0.1:8000)"}
        if not (pasta or portas or pcap or urls):
            return {"erro": "Diga o que vigiar: uma pasta, portas, URLs do app rodando ou uma captura .pcap."}
        if pasta and not os.path.isdir(pasta):
            return {"erro": f"Pasta não encontrada: {pasta}"}
        if pcap and not os.path.isfile(pcap):
            return {"erro": f"Captura não encontrada: {pcap}"}
        chave = est.chave_alvo(pasta, portas, pcap) + ("|web:" + ",".join(sorted(urls)) if urls else "")
        alvo = " + ".join(filter(None, [pasta, ("portas " + ", ".join(map(str, portas))) if portas else "", pcap,
                                        ", ".join(urls)]))

        def trabalho():
            nativo = {"portas": portas, "processo": None, "rede": bool(p.get("rede"))} if portas else None
            trafego = {"pcap": pcap} if pcap else None
            web = {"urls": urls} if urls else None
            return orq.auditar(pasta or None, nativo, trafego, web)
        return self._iniciar("auditoria", trabalho, chave, alvo, bool(p.get("ia")))

    def testar_ia(self, p: dict) -> dict:
        modo = p.get("modo") or "ollama"
        if modo == "http":
            url = (p.get("url") or "").strip()
            if not url:
                return {"erro": "Informe a URL local do teu app (ex.: http://127.0.0.1:5000/chat)."}
            opcoes = {"modo": "http", "url": url, "campo_entrada": p.get("campo_entrada") or "mensagem",
                      "campo_saida": p.get("campo_saida") or "", "canario": (p.get("canario") or "").strip() or None}
            alvo = url
        else:
            sistema = p.get("sistema") or ""
            if not sistema.strip():
                return {"erro": "Cole o prompt de sistema da tua IA (ou carregue um exemplo)."}
            opcoes = {"modo": "ollama", "modelo": (p.get("modelo") or "").strip() or None, "sistema": sistema}
            alvo = f"Ollama · {opcoes['modelo'] or carregar('ARGOS_MODELO', MODELO_PADRAO)}"
        chave = "ia:" + alvo
        return self._iniciar("ia", lambda: orq.testar_ia(opcoes), chave, alvo, False)

    def _iniciar(self, nome, trabalho, chave, alvo, usar_ia) -> dict:
        with self._trava:
            if self._ocupado:
                return {"erro": "Já tem uma varredura em andamento."}
            self._ocupado = nome
            self._sessao = progresso.Sessao()
        threading.Thread(target=self._executar, args=(nome, trabalho, chave, alvo, usar_ia), daemon=True).start()
        return {"ok": True}

    def _executar(self, nome, trabalho, chave, alvo, usar_ia):
        sessao = self._sessao
        with progresso.sessao(sessao):
            evento = self._trabalhar(nome, trabalho, chave, alvo, usar_ia, sessao)
        with self._trava:
            self._evento = evento
            self._ocupado = None

    def _trabalhar(self, nome, trabalho, chave, alvo, usar_ia, sessao) -> dict:
        sessao.avisar(f"alvo: {alvo}", "trilha")
        try:
            res = trabalho()
            progresso.checar()
            avisos = mod_aceitos.aplicar(res.findings)
            nota = ""
            if usar_ia:
                sessao.avisar("IA: procurando o Ollama…", "ia")
                cliente = Ollama()
                ok, msg = cliente.status()
                sessao.avisar("IA: " + msg, "ia" if ok else "pulado")
                if ok:
                    e = narrar(res.findings, cliente)
                    nota = f"{msg} {e.gerados} novas, {e.do_cache} do cache, {e.falhas} falha(s)."
                else:
                    narrar(res.findings, None)
                    nota = f"indisponível ({msg}); usando as explicações base."
            else:
                narrar(res.findings, None)
            with self._trava:
                resolvidos = est.resolvidos(self._estado, chave, res.findings)
                est.registrar_scan(self._estado, chave, res.findings)
                est.salvar(self._estado, self._arquivo)
            est.salvar_ultimo(res.findings)
            self._conj[nome] = {
                "findings": res.findings, "chave": chave, "resolvidos": resolvidos,
                "meta": {"alvo": alvo, "rodaram": res.rodaram, "pulados": res.pulados,
                         "avisos": avisos, "fundidos": res.fundidos, "nota_ia": nota}}
            n = len(res.findings)
            sessao.avisar(f"pronto: {n} achado(s), {len(res.rodaram)} scanner(s) rodaram", "fim")
            return {"conj": nome}
        except progresso.Cancelado:
            sessao.avisar("cancelado. Os resultados anteriores continuam na tela.", "aviso")
            return {"conj": nome, "cancelado": True}
        except Exception as e:  # noqa: BLE001 - qualquer erro vira mensagem na tela
            sessao.avisar(f"erro: {e}", "erro")
            return {"conj": nome, "erro": str(e)}

    def alternar(self, nome: str, fp: str) -> Optional[dict]:
        c = self._conj.get(nome)
        if not c:
            return None
        with self._trava:
            feito = est.alternar(self._estado, c["chave"], fp)
            est.salvar(self._estado, self._arquivo)
            feitos, total = est.progresso(self._estado, c["chave"], c["findings"])
        return {"feito": feito, "feitos": feitos, "total": total}

    def alternar_lgpd(self, i: int) -> dict:
        c = self._conj.get("auditoria")
        chave = c["chave"] if c else "geral"
        with self._trava:
            feito = est.alternar_lgpd(self._estado, chave, int(i))
            est.salvar(self._estado, self._arquivo)
        return {"feito": feito}

    def aceitar(self, fp: str, titulo: str, motivo: str, dias) -> dict:
        try:
            n = int(str(dias).strip())
        except ValueError:
            return {"erro": "Dias deve ser um número de 1 a 90."}
        try:
            novo = mod_aceitos.aceitar(fp, motivo, n, titulo=titulo)
        except mod_aceitos.AceiteInvalido as e:
            return {"erro": str(e)}
        return {"ok": True, "ate": novo["ate"]}

    def gerar_canario(self) -> str:
        return gerar_canario()

    def exemplo_prompt(self, nome: str) -> str:
        if nome not in ("fraco", "reforcado"):
            return ""
        arq = RAIZ / "exemplos" / "ia" / f"prompt_{nome}.txt"
        return arq.read_text(encoding="utf-8") if arq.exists() else ""

    # ------------------------------------------------------------ janelas do sistema

    def _dialogo(self, tipo: str, **kw):
        if self._janela is None:
            return ""
        import webview
        fd = getattr(webview, "FileDialog", None)
        mapa = {"pasta": "FOLDER", "abrir": "OPEN", "salvar": "SAVE"}
        const = getattr(fd, mapa[tipo]) if fd else getattr(webview, mapa[tipo] + "_DIALOG")
        r = self._janela.create_file_dialog(const, **kw)
        if not r:
            return ""
        return r if isinstance(r, str) else r[0]

    def escolher(self, tipo: str) -> str:
        if tipo == "pasta":
            return self._dialogo("pasta")
        return self._dialogo("abrir", file_types=("Capturas (*.pcap;*.pcapng)", "Todos os arquivos (*.*)"))

    def abrir_texto(self) -> dict:
        caminho = self._dialogo("abrir", file_types=("Texto (*.txt;*.md;*.prompt)", "Todos os arquivos (*.*)"))
        if not caminho:
            return {}
        try:
            with open(caminho, encoding="utf-8", errors="replace") as fp:
                return {"texto": fp.read(200_000)}
        except OSError as e:
            return {"erro": f"Não consegui ler: {e}"}

    def texto_ia(self, nome: str = "auditoria") -> dict:
        """O relatório em Markdown pra colar no Claude (a tela copia pra área de transferência)."""
        from ..report.prompt_ia import render_prompt
        c = self._conj.get(nome)
        if not c:
            return {"erro": "Rode uma auditoria antes de exportar."}
        return {"texto": render_prompt(c["findings"], c["meta"])}

    def exportar_ia(self, nome: str = "auditoria") -> dict:
        """Salva o mesmo Markdown num arquivo .md."""
        r = self.texto_ia(nome)
        if "erro" in r:
            return r
        destino = self._dialogo("salvar", save_filename="argos_pra_ia.md")
        if not destino:
            return {}
        with open(destino, "w", encoding="utf-8") as fp:
            fp.write(r["texto"])
        return {"ok": destino}

    def exportar_html(self, nome: str = "auditoria") -> dict:
        c = self._conj.get(nome)
        if not c:
            return {"erro": "Rode uma auditoria antes de exportar."}
        destino = self._dialogo("salvar", save_filename="relatorio_argos.html")
        if not destino:
            return {}
        with open(destino, "w", encoding="utf-8") as fp:
            fp.write(render_html(c["findings"], c["meta"]))
        webbrowser.open(Path(destino).resolve().as_uri())
        return {"ok": destino}
