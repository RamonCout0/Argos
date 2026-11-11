"""
Argos GUI — arte vetorial (tudo desenhado no Canvas do Tk, sem imagem nenhuma).

Olho do Argos, constelação de olhos, ícones de severidade (forma + cor, pra
não depender só da cor), caixas de marcar, barra de vida segmentada,
anel de progresso, botões e interruptores arredondados.
"""
from __future__ import annotations

import math
import tkinter as tk

CORES = {
    "bg": "#0b0e14",
    "card": "#141922",
    "card2": "#1b212d",
    "card3": "#222a38",
    "borda": "#252c3a",
    "borda2": "#323b4e",
    "txt": "#e8ebf2",
    "sub": "#9aa3b5",
    "fraco": "#5d6678",
    "critico": "#ff4d6d",
    "alto": "#ff8c42",
    "medio": "#ffd166",
    "baixo": "#4cc9f0",
    "info": "#8d99ae",
    "ok": "#2dd4a3",
    "ok_esc": "#0e3a31",
    "perigo_esc": "#3d1522",
    "acento": "#8b7cff",
    "acento_esc": "#251f4d",
    "code": "#cfe3ff",
}

SEV_COR = {s: CORES[s] for s in ("critico", "alto", "medio", "baixo", "info")}
SEV_ROTULO = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MÉDIO", "baixo": "BAIXO", "info": "INFO"}


def ret(c: tk.Canvas, x1, y1, x2, y2, r=12, **kw):
    """Retângulo de cantos arredondados (polígono suavizado)."""
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


def escurecer(cor: str, f: float) -> str:
    cor = cor.lstrip("#")
    r, g, b = (int(cor[i:i + 2], 16) for i in (0, 2, 4))
    return "#%02x%02x%02x" % (int(r * f), int(g * f), int(b * f))


def olho(c: tk.Canvas, cx, cy, s=1.0, dx=0.0, abertura=1.0, iris=None, contorno=None,
         fundo=None, fundo_canvas=None, brilho=True, detalhes=True, inclinacao=11, tags="olho"):
    """
    O olho do Argos: amêndoa com o canto de fora puxado pra cima, delineado
    com "asinha", cílios, dobra da pálpebra e íris meio coberta pela pálpebra.
    dx move a pupila; abertura < 1 desce a pálpebra (piscada).
    """
    contorno = contorno or CORES["txt"]
    bgc = fundo_canvas or CORES["bg"]
    iris = iris or CORES["acento"]
    a = max(abertura, 0.04)
    w, hu, hl = 30 * s, 12.5 * s * a, 8.5 * s * a
    ang = math.radians(-inclinacao)
    cs, sn = math.cos(ang), math.sin(ang)

    def P(x, y):
        return cx + x * cs - y * sn, cy + x * sn + y * cs

    def achatar(pts):
        return [v for p in pts for v in P(*p)]

    canto_in, canto_out = (-w, 0.0), (w, -0.05 * hu)
    cima = [(-0.62 * w, -0.86 * hu), (-0.1 * w, -hu), (0.46 * w, -0.86 * hu)]
    baixo = [(0.52 * w, 0.82 * hl), (-0.08 * w, hl), (-0.64 * w, 0.68 * hl)]
    # pontos repetidos = cantos pontudos na suavização do Tk
    lente = [canto_in] * 3 + cima + [canto_out] * 3 + baixo
    c.create_polygon(achatar(lente), smooth=True, fill=fundo or CORES["card"], outline="", tags=tags)

    ri = 11 * s
    ix, iy = P(dx * s, -2.5 * s)  # a pálpebra de cima cobre um pedacinho da íris
    c.create_oval(ix - ri, iy - ri, ix + ri, iy + ri, fill=escurecer(iris, 0.55), outline="", tags=tags)
    r2 = ri * 0.8
    c.create_oval(ix - r2, iy - r2, ix + r2, iy + r2, fill=iris, outline="", tags=tags)
    p = ri * 0.42
    c.create_oval(ix - p, iy - p, ix + p, iy + p, fill="#07090d", outline="", tags=tags)
    if brilho:
        for bx, by, br in ((0.36, -0.42, 0.22), (-0.32, 0.34, 0.1)):
            hx, hy = ix + bx * ri, iy + by * ri
            c.create_oval(hx - br * ri, hy - br * ri, hx + br * ri, hy + br * ri,
                          fill="#ffffff", outline="", tags=tags)

    # máscaras com a cor do fundo: escondem o que a íris passaria das pálpebras
    m = ri + 3 * s
    sup = [canto_in] * 3 + cima + [canto_out] * 3 + [(w + 3 * s, -hu - m)] * 3 + [(-w - 3 * s, -hu - m)] * 3
    inf = [canto_out] * 3 + baixo + [canto_in] * 3 + [(-w - 3 * s, hl + m)] * 3 + [(w + 3 * s, hl + m)] * 3
    for pts in (sup, inf):
        c.create_polygon(achatar(pts), smooth=True, fill=bgc, outline=bgc, tags=tags)

    grosso = max(1.2, 2.8 * s)
    if detalhes:  # dobra da pálpebra, bem sutil
        dobra = [(-0.7 * w, -0.9 * hu - 4 * s), (-0.1 * w, -hu - 6 * s), (0.55 * w, -0.86 * hu - 5 * s)]
        c.create_line(achatar(dobra), smooth=True, fill=CORES["fraco"], width=max(1.0, 1.1 * s),
                      capstyle="round", tags=tags)
    # delineado de cima com a asinha puxada
    asa = (w + 7 * s, -0.05 * hu - 5.5 * s)
    c.create_line(achatar([canto_in] + cima + [canto_out, asa]), smooth=True, fill=contorno,
                  width=grosso, capstyle="round", joinstyle="round", tags=tags)
    c.create_line(achatar([canto_out] + baixo + [canto_in]), smooth=True, fill=escurecer(contorno, 0.62),
                  width=max(1.0, 1.2 * s), capstyle="round", tags=tags)
    if detalhes:  # dois cílios finos no canto de fora
        for (bx, by), (ex, ey) in (((0.52 * w, -0.82 * hu), (0.62 * w, -0.82 * hu - 6 * s)),
                                   ((0.76 * w, -0.55 * hu), (0.9 * w, -0.55 * hu - 5 * s))):
            c.create_line(*P(bx, by), *P(ex, ey), fill=contorno, width=max(1.0, 1.6 * s),
                          capstyle="round", tags=tags)


def olho_fraco(c, cx, cy, s, tags="fundo"):
    """Olho discreto da constelação do cabeçalho."""
    olho(c, cx, cy, s, iris=CORES["borda2"], contorno=CORES["borda2"], fundo=CORES["bg"],
         brilho=False, detalhes=False, tags=tags)


def icone_sev(c: tk.Canvas, x, y, sev: str, t=8.0, tags=()):
    """Forma + cor: crítico ▲, alto ◆, médio ■, baixo ●, info ○."""
    cor = SEV_COR.get(sev, CORES["info"])
    if sev == "critico":
        return c.create_polygon(x, y - t, x + t * 1.05, y + t * 0.8, x - t * 1.05, y + t * 0.8,
                                fill=cor, outline=cor, joinstyle="round", tags=tags)
    if sev == "alto":
        return c.create_polygon(x, y - t, x + t, y, x, y + t, x - t, y, fill=cor, outline=cor, tags=tags)
    if sev == "medio":
        return ret(c, x - t * 0.8, y - t * 0.8, x + t * 0.8, y + t * 0.8, r=3, fill=cor, outline="", tags=tags)
    if sev == "baixo":
        return c.create_oval(x - t * 0.85, y - t * 0.85, x + t * 0.85, y + t * 0.85, fill=cor, outline="", tags=tags)
    return c.create_oval(x - t * 0.75, y - t * 0.75, x + t * 0.75, y + t * 0.75, outline=cor, width=2, tags=tags)


def check(c: tk.Canvas, x, y, t, cor, largura=2.6, tags=()):
    """Visto vetorial dentro de um quadrado (x, y, t)."""
    return c.create_line(x + t * 0.25, y + t * 0.53, x + t * 0.43, y + t * 0.71, x + t * 0.76, y + t * 0.31,
                         fill=cor, width=largura, capstyle="round", joinstyle="round", tags=tags)


def caixa(c: tk.Canvas, x, y, marcado: bool, t=22, tags=()):
    if marcado:
        ret(c, x, y, x + t, y + t, r=7, fill=CORES["ok"], outline=CORES["ok"], tags=tags)
        check(c, x, y, t, CORES["bg"], largura=max(2.0, t / 8), tags=tags)
    else:
        ret(c, x, y, x + t, y + t, r=7, fill=CORES["card3"], outline=CORES["borda2"], width=1.5, tags=tags)


def cor_hp(score: int) -> str:
    return CORES["ok"] if score >= 80 else (CORES["medio"] if score >= 50 else CORES["critico"])


def barra_hp(c: tk.Canvas, x, y, w, h, score: int, segmentos=20, tags=()):
    """Barra de vida segmentada, estilo boss fight."""
    gap = 3
    larg = (w - gap * (segmentos - 1)) / segmentos
    cheios = round(score / 100 * segmentos)
    cor = cor_hp(score)
    for i in range(segmentos):
        sx = x + i * (larg + gap)
        ret(c, sx, y, sx + larg, y + h, r=3,
            fill=cor if i < cheios else CORES["card3"], outline="", tags=tags)


def anel(c: tk.Canvas, cx, cy, r, frac: float, cor, largura=7, tags=()):
    c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=CORES["card3"], width=largura, tags=tags)
    if frac >= 0.999:
        c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=cor, width=largura, tags=tags)
    elif frac > 0:
        c.create_arc(cx - r, cy - r, cx + r, cy + r, start=90, extent=-360 * frac,
                     style="arc", outline=cor, width=largura, tags=tags)


def pilula(c: tk.Canvas, x, y, texto, cor_txt, cor_fundo, fonte, ancora="nw", pad=(10, 4), tags=()):
    """Etiqueta em formato de pílula. Devolve (x1, y1, x2, y2)."""
    t = c.create_text(0, 0, text=texto, fill=cor_txt, font=fonte, anchor="nw", tags=tags)
    bx1, by1, bx2, by2 = c.bbox(t)
    lw, lh = bx2 - bx1 + pad[0] * 2, by2 - by1 + pad[1] * 2
    if ancora == "ne":
        x -= lw
    elif ancora == "center":
        x, y = x - lw / 2, y - lh / 2
    c.coords(t, x + pad[0], y + pad[1])
    fundo = ret(c, x, y, x + lw, y + lh, r=lh / 2, fill=cor_fundo, outline="", tags=tags)
    c.tag_lower(fundo, t)
    return x, y, x + lw, y + lh


class Botao(tk.Canvas):
    """Botão vetorial: 'primario', 'fantasma' ou 'aba' (alternável)."""

    def __init__(self, master, texto, comando, fonte, variante="primario", altura=36,
                 largura=None, fundo_pai=None, raio=None):
        super().__init__(master, height=altura, bg=fundo_pai or CORES["bg"], highlightthickness=0,
                         bd=0, cursor="hand2")
        if largura:
            self.configure(width=largura)
        self.texto, self.comando, self.fonte, self.variante = texto, comando, fonte, variante
        self.altura, self.raio = altura, raio
        self._hover = self._ativo = False
        self._habilitado = True
        self.bind("<Configure>", lambda e: self._desenhar())
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))
        self.bind("<ButtonRelease-1>", self._clique)

    def _set_hover(self, v):
        self._hover = v
        self._desenhar()

    def _clique(self, e):
        if self._habilitado and 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height():
            self.comando()

    def ativo(self, v: bool):
        self._ativo = v
        self._desenhar()

    def habilitado(self, v: bool, texto=None):
        self._habilitado = v
        if texto:
            self.texto = texto
        self.configure(cursor="hand2" if v else "arrow")
        self._desenhar()

    def _cores(self):
        if self.variante == "primario":
            if not self._habilitado:
                return CORES["card3"], CORES["card3"], CORES["sub"]
            f = "#45e3b6" if self._hover else CORES["ok"]
            return f, f, CORES["bg"]
        if self.variante == "aba":
            if self._ativo:
                return CORES["acento_esc"], CORES["acento"], CORES["txt"]
            return (CORES["card2"] if self._hover else CORES["bg"]), CORES["borda"], CORES["sub"]
        f = CORES["card3"] if self._hover else CORES["card2"]
        return f, CORES["borda2"], CORES["txt"] if self._habilitado else CORES["fraco"]

    def _desenhar(self):
        self.delete("all")
        w, h = self.winfo_width(), self.altura
        if w < 4:
            return
        fundo, borda, txt = self._cores()
        r = self.raio if self.raio is not None else h / 2
        ret(self, 1, 1, w - 1, h - 1, r=r, fill=fundo, outline=borda, width=1)
        self.create_text(w / 2, h / 2, text=self.texto, fill=txt, font=self.fonte)


class Interruptor(tk.Canvas):
    """Chave liga/desliga vetorial com texto ao lado."""

    def __init__(self, master, texto, fonte, fundo_pai, valor=False):
        super().__init__(master, height=28, bg=fundo_pai, highlightthickness=0, bd=0, cursor="hand2")
        self.texto, self.fonte, self.valor = texto, fonte, valor
        self.bind("<Configure>", lambda e: self._desenhar())
        self.bind("<ButtonRelease-1>", lambda e: self.set(not self.valor))

    def set(self, v: bool):
        self.valor = v
        self._desenhar()

    def _desenhar(self):
        self.delete("all")
        y = 14
        ret(self, 2, y - 10, 40, y + 10, r=10,
            fill=CORES["ok"] if self.valor else CORES["card3"],
            outline=CORES["ok"] if self.valor else CORES["borda2"])
        kx = 30 if self.valor else 12
        self.create_oval(kx - 7, y - 7, kx + 7, y + 7, fill=CORES["txt"] if self.valor else CORES["sub"], outline="")
        self.create_text(52, y, text=self.texto, anchor="w", fill=CORES["txt"], font=self.fonte)


class Cartao(tk.Canvas):
    """Container com fundo arredondado. Coloque widgets em .dentro."""

    def __init__(self, master, fundo_pai=None, pad=16, cor=None, expandir=False):
        super().__init__(master, bg=fundo_pai or CORES["bg"], highlightthickness=0, bd=0)
        self.pad, self.cor, self.expandir = pad, cor or CORES["card"], expandir
        self.dentro = tk.Frame(self, bg=self.cor)
        self._janela = self.create_window(pad, pad, window=self.dentro, anchor="nw")
        self.dentro.bind("<Configure>", lambda e: self._ajustar())
        self.bind("<Configure>", lambda e: self._ajustar())

    def _ajustar(self):
        w = self.winfo_width()
        if w > 2 * self.pad:
            self.itemconfigure(self._janela, width=w - 2 * self.pad)
        if self.expandir:  # ocupa a altura que o layout der
            h = self.winfo_height()
            if h > 2 * self.pad:
                self.itemconfigure(self._janela, height=h - 2 * self.pad)
        else:
            h = self.dentro.winfo_reqheight() + 2 * self.pad
            if int(self.cget("height")) != h:
                self.configure(height=h)
        self.delete("fundo")
        ret(self, 1, 1, w - 1, h - 1, r=16, fill=self.cor, outline=CORES["borda"], tags="fundo")
        self.tag_lower("fundo")


def onda(fase: float, amplitude: float) -> float:
    return amplitude * math.sin(fase)
