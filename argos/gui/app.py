"""
Argos GUI — a janela.

    python cli.py gui          -> abre a interface
    python cli.py gui --demo   -> abre com dados de exemplo (sem scanner)

Tkinter puro (já vem com o Python; no Linux: sudo apt install python3-tk).
Leve de propósito: roda bem em notebook de 4 GB.
O scan roda numa thread separada; a janela nunca congela.
"""
from __future__ import annotations

import os
import queue
import threading
import time
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font as tkfont

from .. import __version__
from ..schema import Severidade, Lente, FixTipo
from ..scorer import calcular
from ..core.aceitos import fingerprint
from ..core import aceitos as mod_aceitos
from ..core.orchestrator import auditar
from ..ai.narrator import narrar
from ..ai.ollama import Ollama
from ..report.html import render_html
from ..lenses.lgpd_manual import CHECKLIST_LGPD, AVISO
from . import arte, estado as est
from .arte import CORES as C, SEV_COR, SEV_ROTULO

FILTROS = [("todas", "Todas"), ("critico", "Crítico"), ("lgpd", "LGPD"), ("bot", "Bot"), ("info", "Info / ok")]


class App:
    def __init__(self, root: tk.Tk, demo=None):
        self.root = root
        root.title("Argos — o vigia de cem olhos")
        larg = min(1220, root.winfo_screenwidth() - 40)
        alt = min(800, root.winfo_screenheight() - 70)
        root.geometry(f"{larg}x{alt}+{max(0, (root.winfo_screenwidth() - larg) // 2)}+10")
        root.minsize(1100, 620)
        root.configure(bg=C["bg"])
        self._fontes()
        self._estilo()

        self.estado = est.carregar()
        self.findings, self.meta, self.chave = [], {}, "geral"
        self.filtro, self.selecionado = "todas", None
        self.fila: queue.Queue = queue.Queue()
        self.varrendo, self.fase = False, 0.0
        self.cor_iris = C["acento"]
        self._piscar_em, self._piscando = time.time() + 3, None
        self._agendados: dict = {}

        self._montar()
        if demo is not None:
            self._mostrar(demo, {"alvo": "demonstração (dados de exemplo)", "rodaram": ["demo"],
                                 "pulados": [], "fundidos": 0, "avisos": []}, [], "demo")
        self.root.after(40, self._loop)

    # ------------------------------------------------------------ aparência
    def _fontes(self):
        fams = set(tkfont.families(self.root))
        sans = next((f for f in ("Inter", "Segoe UI", "Ubuntu", "Cantarell", "Noto Sans",
                                 "DejaVu Sans", "Helvetica") if f in fams), "TkDefaultFont")
        mono = next((f for f in ("JetBrains Mono", "Cascadia Mono", "Consolas", "Ubuntu Mono",
                                 "DejaVu Sans Mono", "Courier New") if f in fams), "TkFixedFont")
        self.f = {
            "logo": (sans, 21, "bold"), "h1": (sans, 15, "bold"), "h2": (sans, 12, "bold"),
            "txt": (sans, 10), "txtb": (sans, 10, "bold"), "pq": (sans, 9), "pqb": (sans, 9, "bold"),
            "num": (sans, 30, "bold"), "mono": (mono, 9),
        }

    def _estilo(self):
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Argos.Vertical.TScrollbar", background=C["card3"], troughcolor=C["bg"],
                    bordercolor=C["bg"], lightcolor=C["card3"], darkcolor=C["card3"],
                    arrowcolor=C["sub"], gripcount=0, relief="flat", arrowsize=11)
        s.map("Argos.Vertical.TScrollbar", background=[("active", C["borda2"])])

    def _entrada(self, pai, largura=None):
        e = tk.Entry(pai, bg=C["card2"], fg=C["txt"], insertbackground=C["txt"], relief="flat",
                     highlightthickness=1, highlightbackground=C["borda2"], highlightcolor=C["acento"],
                     font=self.f["txt"], disabledbackground=C["card2"])
        if largura:
            e.configure(width=largura)
        return e

    def _rotulo(self, pai, texto, fonte="pqb", cor="sub", **kw):
        return tk.Label(pai, text=texto, bg=pai["bg"], fg=C[cor], font=self.f[fonte], anchor="w", **kw)

    # ------------------------------------------------------------ montagem
    def _montar(self):
        self.topo = tk.Canvas(self.root, height=68, bg=C["bg"], highlightthickness=0)
        self.topo.pack(fill="x")
        self.topo.bind("<Configure>", lambda e: self._desenhar_topo())

        corpo = tk.Frame(self.root, bg=C["bg"])
        corpo.pack(fill="both", expand=True, padx=20, pady=(8, 14))
        esq = tk.Frame(corpo, bg=C["bg"], width=350)
        esq.pack(side="left", fill="y")
        esq.pack_propagate(False)
        dir_ = tk.Frame(corpo, bg=C["bg"])
        dir_.pack(side="left", fill="both", expand=True, padx=(18, 0))

        self._montar_formulario(esq)
        self._montar_placar(esq)
        self._montar_direita(dir_)

    def _montar_formulario(self, pai):
        card = arte.Cartao(pai)
        card.pack(fill="x")
        d = card.dentro
        self._rotulo(d, "Nova auditoria", "h2", "txt").pack(fill="x", pady=(0, 6))

        self.e_pasta = self._campo(d, "PASTA DO PROJETO", escolher=self._escolher_pasta)
        self.e_portas = self._campo(d, "PORTAS DO APP RODANDO  ·  ex.: 8000, 4200")
        self.e_pcap = self._campo(d, "CAPTURA .PCAP  ·  opcional", escolher=self._escolher_pcap)

        self.sw_rede = arte.Interruptor(d, "Olhar também pela rede (nmap)", self.f["txt"], C["card"])
        self.sw_rede.pack(fill="x", pady=(2, 0))
        self.sw_ia = arte.Interruptor(d, "Explicar com IA local (Ollama)", self.f["txt"], C["card"])
        self.sw_ia.pack(fill="x", pady=(0, 10))

        self.b_auditar = arte.Botao(d, "Auditar", self._auditar, self.f["h2"], altura=42, fundo_pai=C["card"])
        self.b_auditar.pack(fill="x")
        self.l_status = self._rotulo(d, "Pronto. Só alvos locais ou teus.", "pq", wraplength=290, justify="left")
        self.l_status.pack(fill="x", pady=(8, 0))

    def _campo(self, pai, titulo, escolher=None):
        self._rotulo(pai, titulo, "pqb").pack(fill="x", pady=(2, 3))
        linha = tk.Frame(pai, bg=pai["bg"])
        linha.pack(fill="x", pady=(0, 6))
        e = self._entrada(linha)
        e.pack(side="left", fill="x", expand=True, ipady=5)
        if escolher:
            arte.Botao(linha, "Escolher", escolher, self.f["pqb"], variante="fantasma", altura=30,
                       largura=84, fundo_pai=pai["bg"], raio=9).pack(side="left", padx=(8, 0))
        return e

    def _montar_placar(self, pai):
        card = arte.Cartao(pai)
        card.pack(fill="x", pady=(12, 0))
        self.placar = tk.Canvas(card.dentro, height=152, bg=C["card"], highlightthickness=0)
        self.placar.pack(fill="x")
        self.placar.bind("<Configure>", lambda e: self._agendar("placar", self._desenhar_placar))

    def _montar_direita(self, pai):
        abas = tk.Frame(pai, bg=C["bg"])
        abas.pack(fill="x")
        self.b_exportar = arte.Botao(abas, "Exportar HTML", self._exportar, self.f["txtb"],
                                     variante="fantasma", altura=36, largura=140)
        self.b_exportar.pack(side="right")
        self.abas = {}
        for chave, nome in (("brechas", "Checklist de brechas"), ("lgpd", "Checklist LGPD"), ("scanners", "Scanners")):
            b = arte.Botao(abas, nome, lambda k=chave: self._aba(k), self.f["txtb"], variante="aba",
                           altura=36, largura=190 if chave == "brechas" else 150)
            b.pack(side="left", padx=(0, 8))
            self.abas[chave] = b
        self.area = tk.Frame(pai, bg=C["bg"])
        self.area.pack(fill="both", expand=True, pady=(12, 0))

        self.v_brechas = self._montar_brechas(self.area)
        self.v_lgpd = self._montar_lgpd(self.area)
        self.v_scanners = self._montar_scanners(self.area)
        self._aba("brechas")

    def _lista_rolavel(self, pai, altura=None):
        moldura = tk.Frame(pai, bg=C["bg"])
        c = tk.Canvas(moldura, bg=C["bg"], highlightthickness=0)
        if altura:
            c.configure(height=altura)
        sb = ttk.Scrollbar(moldura, orient="vertical", command=c.yview, style="Argos.Vertical.TScrollbar")
        c.configure(yscrollcommand=sb.set)
        c.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y", padx=(6, 0))

        def rolar(e):
            if e.num == 4:
                passo = -3
            elif e.num == 5:
                passo = 3
            else:
                passo = -3 if e.delta > 0 else 3
            c.yview_scroll(passo, "units")

        def ligar(_):
            for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                c.bind_all(ev, rolar)

        def desligar(_):
            for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                c.unbind_all(ev)

        c.bind("<Enter>", ligar)
        c.bind("<Leave>", desligar)
        return moldura, c

    def _montar_brechas(self, pai):
        v = tk.Frame(pai, bg=C["bg"])
        barra = tk.Frame(v, bg=C["bg"])
        barra.pack(fill="x")
        self.b_filtros = {}
        for chave, nome in FILTROS:
            b = arte.Botao(barra, nome, lambda k=chave: self._filtrar(k), self.f["pqb"], variante="aba",
                           altura=30, largura=max(70, 10 * len(nome) + 24))
            b.pack(side="left", padx=(0, 6))
            self.b_filtros[chave] = b
        self.b_filtros["todas"].ativo(True)
        self.l_prog = self._rotulo(barra, "", "pq")
        self.l_prog.pack(side="right")

        self.banner = tk.Canvas(v, height=0, bg=C["bg"], highlightthickness=0)
        self.banner.pack(fill="x", pady=(10, 0))

        meio = tk.Frame(v, bg=C["bg"])
        meio.pack(fill="both", expand=True, pady=(8, 0))
        det = arte.Cartao(meio, pad=16, expandir=True)
        det.configure(width=370)
        det.pack(side="right", fill="y", padx=(12, 0))
        moldura, self.lista = self._lista_rolavel(meio)
        moldura.pack(side="left", fill="both", expand=True)
        self.lista.bind("<Configure>", lambda e: self._agendar("lista", self._desenhar_lista))

        rodape = tk.Frame(det.dentro, bg=C["card"])
        rodape.pack(side="bottom", fill="x", pady=(10, 0))
        self.detalhe = tk.Text(det.dentro, height=4, bg=C["card"], fg=C["txt"], relief="flat",
                               wrap="word", font=self.f["txt"], highlightthickness=0, padx=2, pady=2,
                               cursor="arrow", selectbackground=C["acento_esc"])
        self.detalhe.pack(fill="both", expand=True)
        t = self.detalhe
        t.tag_configure("h", font=self.f["h1"], foreground=C["txt"], spacing3=2)
        t.tag_configure("meta", font=self.f["pq"], foreground=C["sub"], spacing3=8)
        t.tag_configure("rot", font=self.f["pqb"], foreground=C["acento"], spacing1=6)
        t.tag_configure("rot_ia", font=self.f["pqb"], foreground=C["medio"], spacing1=6)
        t.tag_configure("corpo", foreground=C["txt"], spacing1=2, spacing3=2)
        t.tag_configure("code", font=self.f["mono"], foreground=C["code"], background=C["card2"],
                        lmargin1=10, lmargin2=10, spacing1=3, spacing3=3)
        t.tag_configure("vazio", foreground=C["fraco"], font=self.f["txt"], spacing3=6)
        self.b_aceitar = arte.Botao(rodape, "Aceitar como falso positivo…", self._dialogo_aceitar,
                                    self.f["pqb"], variante="fantasma", altura=32, fundo_pai=C["card"])
        self.b_aceitar.pack(fill="x")
        self.b_aceitar.habilitado(False)
        self._mostrar_detalhe(None)
        return v

    def _montar_lgpd(self, pai):
        v = tk.Frame(pai, bg=C["bg"])
        self._rotulo(v, "O que a lei pede e nenhum scanner confere sozinho", "h2", "txt").pack(fill="x")
        self._rotulo(v, AVISO, "pq", wraplength=760, justify="left").pack(fill="x", pady=(2, 8))
        moldura, self.lista_lgpd = self._lista_rolavel(v)
        moldura.pack(fill="both", expand=True)
        self.lista_lgpd.bind("<Configure>", lambda e: self._agendar("lgpd", self._desenhar_lgpd))
        return v

    def _montar_scanners(self, pai):
        v = tk.Frame(pai, bg=C["bg"])
        card = arte.Cartao(v)
        card.pack(fill="both", expand=True)
        self.t_scan = tk.Text(card.dentro, bg=C["card"], fg=C["txt"], relief="flat", wrap="word",
                              font=self.f["txt"], highlightthickness=0, height=24, cursor="arrow")
        self.t_scan.pack(fill="both", expand=True)
        self.t_scan.tag_configure("rot", font=self.f["pqb"], foreground=C["acento"], spacing1=8, spacing3=2)
        self.t_scan.tag_configure("ok", foreground=C["ok"])
        self.t_scan.tag_configure("pulo", foreground=C["medio"])
        self.t_scan.tag_configure("sub", foreground=C["sub"])
        self._preencher_scanners()
        return v

    # ------------------------------------------------------------ desenho
    def _desenhar_topo(self):
        c = self.topo
        c.delete("fundo")
        w = c.winfo_width()
        for (fx, y, s) in ((60, 26, 0.5), (122, 50, 0.4), (178, 22, 0.36), (236, 48, 0.32),
                           (290, 24, 0.28), (340, 48, 0.25), (388, 26, 0.22), (432, 46, 0.2)):
            if w - fx > 560:
                arte.olho_fraco(c, w - fx, y, s)
        c.create_text(104, 25, text="ARGOS", anchor="w", fill=C["txt"], font=self.f["logo"], tags="fundo")
        c.create_text(105, 49, text=f"o vigia de cem olhos  ·  v{__version__}  ·  só dev/local",
                      anchor="w", fill=C["sub"], font=self.f["pq"], tags="fundo")
        c.create_line(20, 66, w - 20, 66, fill=C["borda"], tags="fundo")
        self._desenhar_olho()

    def _desenhar_olho(self, dx=0.0, abertura=1.0):
        self.topo.delete("olho")
        arte.olho(self.topo, 52, 37, s=1.1, dx=dx, abertura=abertura, iris=self.cor_iris)

    def _desenhar_placar(self):
        c = self.placar
        c.delete("all")
        w = max(c.winfo_width(), 200)
        c.create_text(0, 4, text="HP DO DEPLOY", anchor="nw", fill=C["sub"], font=self.f["pqb"])
        if not self.meta:
            c.create_text(w, -2, text="—", anchor="ne", fill=C["fraco"], font=self.f["num"])
            arte.barra_hp(c, 0, 46, w, 14, 0)
            c.create_text(w / 2, 118, text="Nenhuma auditoria ainda.\nO veredito aparece aqui.",
                          fill=C["fraco"], font=self.f["txt"], justify="center")
            return
        p = calcular(self.findings)
        cor = arte.cor_hp(p.score)
        c.create_text(w - 34, -2, text=str(p.score), anchor="ne", fill=cor, font=self.f["num"])
        c.create_text(w, 22, text="/100", anchor="ne", fill=C["sub"], font=self.f["pq"])
        arte.barra_hp(c, 0, 46, w, 14, p.score)

        # selo + contadores por severidade na mesma linha
        if p.aprovado:
            _, y1, x2, y2 = arte.pilula(c, 0, 76, "OK PRA PROD", C["ok"], C["ok_esc"], self.f["pqb"])
        else:
            _, y1, x2, y2 = arte.pilula(c, 0, 76, "BLOQUEADO", C["critico"], C["perigo_esc"], self.f["pqb"])
        yc = (y1 + y2) / 2
        passo = max(40, (w - x2 - 12) / 4)
        x = x2 + 16
        for sev in ("critico", "alto", "medio", "baixo"):
            n = p.por_severidade.get(sev, 0)
            arte.icone_sev(c, x + 6, yc, sev, t=6.5)
            c.create_text(x + 17, yc, text=str(n), anchor="w",
                          fill=C["txt"] if n else C["fraco"], font=self.f["txtb"])
            x += passo

        # anel de progresso do checklist
        feitos, total = est.progresso(self.estado, self.chave, self.findings)
        frac = feitos / total if total else 1.0
        arte.anel(c, 25, 126, 22, frac, C["ok"] if frac >= 1 else C["acento"], largura=6)
        c.create_text(25, 126, text=f"{int(frac * 100)}%", fill=C["txt"], font=self.f["pqb"])
        c.create_text(60, 116, text=f"Checklist: {feitos} de {total} marcados", anchor="w",
                      fill=C["txt"], font=self.f["txtb"])
        c.create_text(60, 136, text="a nota muda quando o re-scan confirma", anchor="w",
                      fill=C["sub"], font=self.f["pq"], width=w - 64)

    def _desenhar_banner(self, resolvidos):
        c = self.banner
        c.delete("all")
        if not resolvidos:
            c.configure(height=0)
            return
        c.configure(height=46)
        w = max(c.winfo_width(), 400)
        arte.ret(c, 1, 1, w - 1, 45, r=12, fill=C["ok_esc"], outline=C["ok"])
        arte.caixa(c, 14, 12, True, t=22)
        nomes = ", ".join(resolvidos[:3]) + ("…" if len(resolvidos) > 3 else "")
        c.create_text(48, 23, anchor="w", fill=C["txt"], font=self.f["txtb"], width=w - 60,
                      text=f"{len(resolvidos)} brecha(s) resolvida(s) desde o último scan: {nomes}")

    def _estado_vazio(self, c, w, titulo, sub):
        h = max(c.winfo_height(), 300)
        cx, cy = w / 2, h / 2 - 30
        for i, (dx, dy, s) in enumerate(((-120, -40, .5), (120, -30, .45), (-80, 50, .4), (95, 60, .38))):
            arte.olho_fraco(c, cx + dx, cy + dy, s, tags="vazio")
        arte.olho(c, cx, cy, s=1.9, iris=C["acento"], tags="vazio")
        c.create_text(cx, cy + 70, text=titulo, fill=C["txt"], font=self.f["h2"])
        c.create_text(cx, cy + 94, text=sub, fill=C["sub"], font=self.f["txt"], width=440, justify="center")

    def _desenhar_lista(self):
        c = self.lista
        c.delete("all")
        w = max(c.winfo_width(), 320)
        if not self.meta:
            self._estado_vazio(c, w, "Os cem olhos estão esperando",
                               "Escolha a pasta do projeto, as portas do app rodando ou uma captura, "
                               "e clique em Auditar.")
            c.configure(scrollregion=(0, 0, w, c.winfo_height()))
            return
        itens = est.filtrar(self.findings, self.filtro)
        if not itens:
            msg = "Nenhuma brecha encontrada." if not self.findings else "Nada nesta lente."
            self._estado_vazio(c, w, msg, "Os scanners que rodaram não acharam nada aqui.")
            c.configure(scrollregion=(0, 0, w, c.winfo_height()))
            return

        y = 4
        self._fundos = {}
        for i, f in enumerate(itens):
            fp = fingerprint(f)
            sev = f.severidade.value
            feito = est.conta(f) and est.marcado(self.estado, self.chave, fp)
            sel = self.selecionado is not None and fingerprint(self.selecionado) == fp
            tag = f"card{i}"
            x1, x2 = 2, w - 4
            tx = x1 + 80
            larg_txt = x2 - tx - 96
            t1 = c.create_text(tx, y + 14, text=f.titulo, anchor="nw", width=larg_txt,
                               fill=C["sub"] if feito else C["txt"], font=self.f["txtb"], tags=(tag,))
            yb = c.bbox(t1)[3] + 4
            t2 = c.create_text(tx, yb, text=f"{f.local}    ·    {f.origem}", anchor="nw",
                               width=larg_txt, fill=C["fraco"] if feito else C["sub"],
                               font=self.f["pq"], tags=(tag,))
            h = max(c.bbox(t2)[3] - y + 14, 66)
            fundo = arte.ret(c, x1, y, x2, y + h, r=14,
                             fill=C["card2"] if sel else C["card"],
                             outline=C["acento"] if sel else C["borda"], width=1.4 if sel else 1,
                             tags=(tag,))
            c.tag_lower(fundo)
            self._fundos[tag] = (fundo, sel)
            arte.ret(c, x1 + 10, y + 14, x1 + 14, y + h - 14, r=2, fill=SEV_COR[sev], outline="", tags=(tag,))
            if est.conta(f):
                arte.caixa(c, x1 + 24, y + h / 2 - 11, feito, t=22, tags=(tag, f"chk{i}"))
            arte.icone_sev(c, x1 + 62, y + h / 2, sev, t=8, tags=(tag,))
            arte.pilula(c, x2 - 14, y + 12, SEV_ROTULO[sev], SEV_COR[sev], C["card3"], self.f["pqb"],
                        ancora="ne", pad=(9, 3), tags=(tag,))
            if feito:
                arte.pilula(c, x2 - 14, y + 40, "marcado", C["ok"], C["ok_esc"], self.f["pq"],
                            ancora="ne", pad=(8, 2), tags=(tag,))
            c.tag_bind(tag, "<Button-1>", lambda e, f=f, i=i: self._clique_card(f, i))
            c.tag_bind(tag, "<Enter>", lambda e, t=tag: self._hover(t, True))
            c.tag_bind(tag, "<Leave>", lambda e, t=tag: self._hover(t, False))
            y += h + 10
        c.configure(scrollregion=(0, 0, w, y))

    def _hover(self, tag, dentro):
        fundo, sel = self._fundos.get(tag, (None, False))
        if fundo is None or sel:
            return
        self.lista.itemconfigure(fundo, fill=C["card2"] if dentro else C["card"],
                                 outline=C["borda2"] if dentro else C["borda"])
        self.lista.configure(cursor="hand2" if dentro else "")

    def _desenhar_lgpd(self):
        c = self.lista_lgpd
        c.delete("all")
        w = max(c.winfo_width(), 320)
        y = 4
        for i, (titulo, texto) in enumerate(CHECKLIST_LGPD):
            feito = est.lgpd_marcado(self.estado, self.chave, i)
            tag = f"lg{i}"
            t1 = c.create_text(64, y + 14, text=titulo, anchor="nw", width=w - 90,
                               fill=C["sub"] if feito else C["txt"], font=self.f["txtb"], tags=(tag,))
            t2 = c.create_text(64, c.bbox(t1)[3] + 4, text=texto, anchor="nw", width=w - 90,
                               fill=C["sub"], font=self.f["pq"], tags=(tag,))
            h = max(c.bbox(t2)[3] - y + 14, 60)
            fundo = arte.ret(c, 2, y, w - 4, y + h, r=14, fill=C["card"], outline=C["borda"], tags=(tag,))
            c.tag_lower(fundo)
            arte.caixa(c, 22, y + h / 2 - 11, feito, t=22, tags=(tag,))
            c.tag_bind(tag, "<Button-1>", lambda e, i=i: self._alternar_lgpd(i))
            y += h + 10
        feitos = sum(1 for i in range(len(CHECKLIST_LGPD)) if est.lgpd_marcado(self.estado, self.chave, i))
        c.create_text(4, y + 10, anchor="nw", fill=C["sub"], font=self.f["pq"],
                      text=f"{feitos} de {len(CHECKLIST_LGPD)} confirmados para: {self.chave}")
        c.configure(scrollregion=(0, 0, w, y + 40))

    def _mostrar_detalhe(self, f):
        t = self.detalhe
        t.configure(state="normal")
        t.delete("1.0", "end")
        if f is None:
            t.insert("end", "Clique numa brecha pra ver o porquê, a correção e como confirmar.\n", "vazio")
            t.insert("end", "A caixinha marca o que você já corrigiu; o re-scan é quem confirma.", "vazio")
            t.configure(state="disabled")
            return
        t.insert("end", f.titulo + "\n", "h")
        meta = f"{SEV_ROTULO[f.severidade.value]}   ·   {f.categoria}   ·   {f.local}   ·   achado por {f.origem}"
        t.insert("end", meta + "\n", "meta")
        if f.evidencia:
            t.insert("end", "EVIDÊNCIA\n", "rot")
            t.insert("end", f.evidencia + "\n", "code")
        if f.explicacao:
            t.insert("end", "POR QUE IMPORTA" + (" · IA" if f.fonte_explicacao == "ia" else "") + "\n", "rot")
            t.insert("end", f.explicacao + "\n", "corpo")
        if f.fix:
            exata = f.fix.tipo is FixTipo.DETERMINISTICO
            t.insert("end", "CORREÇÃO " + ("EXATA" if exata else "A REVISAR") + "\n", "rot")
            t.insert("end", f.fix.descricao + "\n", "corpo")
            if f.fix.patch:
                t.insert("end", f.fix.patch + "\n", "code")
        if f.sugestao_ia:
            t.insert("end", "SUGESTÃO DA IA — CONFIRA ANTES DE APLICAR\n", "rot_ia")
            t.insert("end", f.sugestao_ia + "\n", "code")
        if f.verificacao:
            t.insert("end", "COMO CONFIRMAR\n", "rot")
            t.insert("end", f.verificacao + "\n", "corpo")
        t.configure(state="disabled")

    def _preencher_scanners(self):
        t = self.t_scan
        t.configure(state="normal")
        t.delete("1.0", "end")
        if not self.meta:
            t.insert("end", "Rode uma auditoria pra ver quais scanners participaram.\n", "sub")
        else:
            t.insert("end", "ALVO\n", "rot")
            t.insert("end", (self.meta.get("alvo") or "—") + "\n")
            t.insert("end", "RODARAM\n", "rot")
            for r in self.meta.get("rodaram", []) or ["nenhum"]:
                t.insert("end", f"  ✓ {r}\n", "ok")
            if self.meta.get("pulados"):
                t.insert("end", "PULADOS\n", "rot")
                for n, m in self.meta["pulados"]:
                    t.insert("end", f"  • {n}: ", "pulo")
                    t.insert("end", f"{m}\n", "sub")
            if self.meta.get("avisos"):
                t.insert("end", "AVISOS\n", "rot")
                for a in self.meta["avisos"]:
                    t.insert("end", f"  • {a}\n", "pulo")
            t.insert("end", "DETALHES\n", "rot")
            t.insert("end", f"  achados repetidos fundidos: {self.meta.get('fundidos', 0)}\n", "sub")
            if self.meta.get("nota_ia"):
                t.insert("end", f"  IA: {self.meta['nota_ia']}\n", "sub")
        t.configure(state="disabled")

    # ------------------------------------------------------------ ações
    def _aba(self, chave):
        for k, b in self.abas.items():
            b.ativo(k == chave)
        for v in (self.v_brechas, self.v_lgpd, self.v_scanners):
            v.pack_forget()
        {"brechas": self.v_brechas, "lgpd": self.v_lgpd, "scanners": self.v_scanners}[chave].pack(
            fill="both", expand=True)

    def _filtrar(self, chave):
        self.filtro = chave
        for k, b in self.b_filtros.items():
            b.ativo(k == chave)
        self._desenhar_lista()
        self.lista.yview_moveto(0)

    def _clique_card(self, f, i):
        atual = self.lista.find_withtag("current")
        tags = self.lista.gettags(atual[0]) if atual else ()
        if f"chk{i}" in tags:
            est.alternar(self.estado, self.chave, fingerprint(f))
            est.salvar(self.estado)
            self._atualizar_contagens()
        else:
            self.selecionado = f
            self._mostrar_detalhe(f)
            self.b_aceitar.habilitado(est.conta(f))
        self._desenhar_lista()

    def _alternar_lgpd(self, i):
        est.alternar_lgpd(self.estado, self.chave, i)
        est.salvar(self.estado)
        self._desenhar_lgpd()

    def _atualizar_contagens(self):
        feitos, total = est.progresso(self.estado, self.chave, self.findings)
        self.l_prog.configure(text=f"{feitos} de {total} marcados" if self.meta else "")
        self._desenhar_placar()

    def _escolher_pasta(self):
        p = filedialog.askdirectory(title="Pasta do projeto")
        if p:
            self.e_pasta.delete(0, "end")
            self.e_pasta.insert(0, p)

    def _escolher_pcap(self):
        p = filedialog.askopenfilename(title="Captura do Wireshark",
                                       filetypes=[("Capturas", "*.pcap *.pcapng"), ("Todos", "*.*")])
        if p:
            self.e_pcap.delete(0, "end")
            self.e_pcap.insert(0, p)

    def _auditar(self):
        if self.varrendo:
            return
        pasta = self.e_pasta.get().strip()
        pcap = self.e_pcap.get().strip()
        try:
            portas = [int(p) for p in self.e_portas.get().replace(";", ",").split(",") if p.strip()]
        except ValueError:
            messagebox.showwarning("Argos", "Portas devem ser números separados por vírgula, ex.: 8000, 4200")
            return
        if not (pasta or portas or pcap):
            messagebox.showinfo("Argos", "Diga o que vigiar: uma pasta, portas do app rodando ou uma captura .pcap.")
            return
        if pasta and not os.path.isdir(pasta):
            messagebox.showwarning("Argos", f"Pasta não encontrada:\n{pasta}")
            return
        if pcap and not os.path.isfile(pcap):
            messagebox.showwarning("Argos", f"Captura não encontrada:\n{pcap}")
            return
        self.varrendo = True
        self.b_auditar.habilitado(False, "Vigiando…")
        self.l_status.configure(text="Os cem olhos estão olhando. Isso pode levar alguns minutos.")
        chave = est.chave_alvo(pasta, portas, pcap)
        args = (pasta, portas, self.sw_rede.valor, pcap, self.sw_ia.valor, chave)
        threading.Thread(target=self._trabalhar, args=args, daemon=True).start()

    def _trabalhar(self, pasta, portas, rede, pcap, ia, chave):
        """Roda fora da thread da janela: nada de Tk aqui."""
        try:
            nativo = {"portas": portas, "processo": None, "rede": rede} if portas else None
            trafego = {"pcap": pcap} if pcap else None
            res = auditar(pasta or None, nativo, trafego)
            avisos = mod_aceitos.aplicar(res.findings)
            nota_ia = ""
            if ia:
                cliente = Ollama()
                ok, msg = cliente.status()
                if ok:
                    e = narrar(res.findings, cliente)
                    nota_ia = f"{msg} {e.gerados} novas, {e.do_cache} do cache, {e.falhas} falha(s)."
                else:
                    narrar(res.findings, None)
                    nota_ia = f"indisponível ({msg}); usando as explicações base."
            else:
                narrar(res.findings, None)
            alvo = " + ".join(filter(None, [pasta, ("portas " + ", ".join(map(str, portas))) if portas else "", pcap]))
            meta = {"alvo": alvo, "rodaram": res.rodaram, "pulados": res.pulados,
                    "fundidos": res.fundidos, "avisos": avisos, "nota_ia": nota_ia}
            self.fila.put(("ok", res.findings, meta, chave))
        except Exception as e:  # noqa: BLE001 - qualquer erro vira mensagem na janela
            self.fila.put(("erro", str(e)))

    def _mostrar(self, findings, meta, resolvidos, chave):
        self.findings, self.meta, self.chave = findings, meta, chave
        self.selecionado = None
        p = calcular(findings)
        self.cor_iris = C["ok"] if p.aprovado else C["critico"]
        self._desenhar_olho()
        self._desenhar_banner(resolvidos)
        self._mostrar_detalhe(None)
        self.b_aceitar.habilitado(False)
        self._atualizar_contagens()
        self._desenhar_lista()
        self._desenhar_lgpd()
        self._preencher_scanners()
        pulados = len(meta.get("pulados", []))
        txt = f"{len(findings)} achado(s) · {len(meta.get('rodaram', []))} scanner(s) rodaram"
        if pulados:
            txt += f" · {pulados} pulado(s) (veja a aba Scanners)"
        self.l_status.configure(text=txt)

    def _exportar(self):
        if not self.meta:
            messagebox.showinfo("Argos", "Rode uma auditoria antes de exportar.")
            return
        destino = filedialog.asksaveasfilename(title="Salvar relatório", defaultextension=".html",
                                               initialfile="relatorio_argos.html",
                                               filetypes=[("Página HTML", "*.html")])
        if not destino:
            return
        with open(destino, "w", encoding="utf-8") as fp:
            fp.write(render_html(self.findings, self.meta))
        webbrowser.open("file://" + os.path.abspath(destino))

    def _dialogo_aceitar(self):
        f = self.selecionado
        if f is None or not est.conta(f):
            return
        d = tk.Toplevel(self.root, bg=C["bg"])
        d.title("Aceitar risco")
        d.transient(self.root)
        d.resizable(False, False)
        card = arte.Cartao(d)
        card.pack(fill="both", expand=True, padx=16, pady=16)
        dd = card.dentro
        self._rotulo(dd, "Aceitar como falso positivo", "h2", "txt").pack(fill="x")
        self._rotulo(dd, f.titulo, "pq", wraplength=380, justify="left").pack(fill="x", pady=(2, 10))
        self._rotulo(dd, "POR QUE ISSO NÃO É UM PROBLEMA? (mín. 10 letras)", "pqb").pack(fill="x")
        motivo = self._entrada(dd, largura=46)
        motivo.pack(fill="x", ipady=7, pady=(3, 10))
        self._rotulo(dd, "VALE POR QUANTOS DIAS? (1 a 90)", "pqb").pack(fill="x")
        dias = self._entrada(dd, largura=6)
        dias.insert(0, "30")
        dias.pack(anchor="w", ipady=7, pady=(3, 6))
        erro = self._rotulo(dd, "", "pq", "critico", wraplength=380, justify="left")
        erro.pack(fill="x")

        def confirmar():
            try:
                n = int(dias.get().strip())
            except ValueError:
                erro.configure(text="Dias deve ser um número de 1 a 90.")
                return
            try:
                novo = mod_aceitos.aceitar(fingerprint(f), motivo.get(), n, titulo=f.titulo)
            except mod_aceitos.AceiteInvalido as e:
                erro.configure(text=str(e))
                return
            d.destroy()
            self.l_status.configure(text=f"Risco aceito até {novo['ate']}. Vale a partir do próximo scan.")

        linha = tk.Frame(dd, bg=C["card"])
        linha.pack(fill="x", pady=(10, 0))
        arte.Botao(linha, "Aceitar", confirmar, self.f["txtb"], altura=36, largura=120,
                   fundo_pai=C["card"]).pack(side="right")
        arte.Botao(linha, "Cancelar", d.destroy, self.f["txtb"], variante="fantasma", altura=36,
                   largura=110, fundo_pai=C["card"]).pack(side="right", padx=(0, 8))
        motivo.focus_set()
        d.grab_set()

    # ------------------------------------------------------------ laço
    def _agendar(self, nome, func, atraso=60):
        if nome in self._agendados:
            self.root.after_cancel(self._agendados[nome])
        self._agendados[nome] = self.root.after(atraso, func)

    def _loop(self):
        try:
            while True:
                msg = self.fila.get_nowait()
                self.varrendo = False
                self.b_auditar.habilitado(True, "Auditar")
                if msg[0] == "erro":
                    self.l_status.configure(text=f"Erro: {msg[1]}")
                    self._desenhar_olho()
                else:
                    _, findings, meta, chave = msg
                    resolvidos = est.resolvidos(self.estado, chave, findings)
                    est.registrar_scan(self.estado, chave, findings)
                    est.salvar(self.estado)
                    est.salvar_ultimo(findings)
                    self._mostrar(findings, meta, resolvidos, chave)
        except queue.Empty:
            pass

        agora = time.time()
        if self.varrendo:
            self.fase += 0.16
            self._desenhar_olho(dx=arte.onda(self.fase, 9))
        elif self._piscando is not None:
            seq = (1, 0.55, 0.15, 0.55, 1)
            if self._piscando < len(seq):
                self._desenhar_olho(abertura=seq[self._piscando])
                self._piscando += 1
            else:
                self._piscando = None
                self._piscar_em = agora + 3.5 + (agora * 7 % 3)
        elif agora >= self._piscar_em:
            self._piscando = 0
        self.root.after(40, self._loop)


def main(demo=None):
    try:  # nitidez em telas com escala no Windows
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root, demo=demo)
    root.mainloop()
