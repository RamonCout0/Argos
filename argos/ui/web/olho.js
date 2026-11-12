/* Argos — o olho vetorial (SVG puro, sem imagem nenhuma).
 *
 * Olho amendoado, puxado no canto de fora (o grupo todo é inclinado), com
 * delineado de asinha, cílios, dobra da pálpebra, íris com gradiente e
 * fibras, pupila, dois brilhos e sombra da pálpebra.
 *
 * A cor vem de variáveis CSS do container (data-estado):
 *   repouso = azul · vigiando = roxo · alerta = vermelho · ressalva = âmbar · ok = verde
 */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  let seq = 0;

  const SUPERIOR = "C -62 -40, 34 -52, 90 -10";
  const AMENDOA = "M -88 4 " + SUPERIOR + " C 54 32, -38 42, -88 4 Z";

  function no(tag, attrs, pai) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (pai) pai.appendChild(e);
    return e;
  }

  class Olho {
    constructor(alvo, opc) {
      opc = opc || {};
      this.id = "olho" + (++seq);
      this.detalhes = opc.detalhes !== false;
      const svg = no("svg", { viewBox: "-114 -70 228 128", class: "olho-svg", "aria-hidden": "true" });
      const defs = no("defs", {}, svg);

      const gi = no("radialGradient", { id: this.id + "gi", cx: "40%", cy: "36%", r: "72%" }, defs);
      no("stop", { offset: "0", class: "st-a" }, gi);
      no("stop", { offset: ".52", class: "st-b" }, gi);
      no("stop", { offset: "1", class: "st-c" }, gi);

      const gs = no("linearGradient", { id: this.id + "gs", x1: "0", y1: "0", x2: "0", y2: "1" }, defs);
      no("stop", { offset: "0", "stop-color": "#1d2537" }, gs);
      no("stop", { offset: "1", "stop-color": "#0c1019" }, gs);

      const gl = no("linearGradient", { id: this.id + "gl", x1: "0", y1: "0", x2: "0", y2: "1" }, defs);
      no("stop", { offset: "0", "stop-color": "#000", "stop-opacity": ".62" }, gl);
      no("stop", { offset: "1", "stop-color": "#000", "stop-opacity": "0" }, gl);

      const cp = no("clipPath", { id: this.id + "cp" }, defs);
      no("path", { d: AMENDOA }, cp);

      const raiz = no("g", { transform: "rotate(-9)" }, svg);
      this.corpo = no("g", { class: "olho-corpo" }, raiz);

      const dentro = no("g", { "clip-path": "url(#" + this.id + "cp)" }, this.corpo);
      no("path", { d: AMENDOA, fill: "url(#" + this.id + "gs)" }, dentro);

      this.iris = no("g", { class: "olho-iris" }, dentro);
      no("circle", { r: "33", fill: "url(#" + this.id + "gi)" }, this.iris);
      if (this.detalhes) {
        for (let i = 0; i < 28; i++) {
          const a = (i / 28) * Math.PI * 2;
          const r1 = 15 + (i % 3), r2 = 29 - (i % 2) * 2;
          no("line", {
            x1: (Math.cos(a) * r1).toFixed(2), y1: (Math.sin(a) * r1).toFixed(2),
            x2: (Math.cos(a) * r2).toFixed(2), y2: (Math.sin(a) * r2).toFixed(2),
            class: "olho-fibra",
          }, this.iris);
        }
      }
      no("circle", { r: "33", fill: "none", stroke: "rgba(0,0,0,.5)", "stroke-width": "3.5" }, this.iris);
      this.pupila = no("circle", { r: "13", class: "olho-pupila" }, this.iris);
      no("ellipse", { cx: "11", cy: "-13", rx: "7", ry: "6", fill: "#fff", opacity: ".92" }, this.iris);
      no("circle", { cx: "-13", cy: "12", r: "3", fill: "#fff", opacity: ".45" }, this.iris);

      no("rect", { x: "-100", y: "-62", width: "200", height: "44", fill: "url(#" + this.id + "gl)" }, dentro);

      const linhas = no("g", {}, this.corpo);
      if (this.detalhes) {
        no("path", { d: "M -72 -27 C -40 -59, 30 -65, 80 -35", class: "olho-dobra" }, linhas);
      }
      no("path", { d: "M -90 5 " + SUPERIOR + " Q 99 -16 111 -28", class: "olho-delineado" }, linhas);
      no("path", { d: "M 90 -10 C 54 32, -38 42, -88 4", class: "olho-inferior" }, linhas);
      if (this.detalhes) {
        ["M 42 -41 Q 48 -50 50 -58", "M 59 -34 Q 67 -42 71 -50", "M 74 -25 Q 83 -31 90 -39"]
          .forEach(d => no("path", { d, class: "olho-cilio" }, linhas));
      }

      alvo.appendChild(svg);
      this.svg = svg;
    }

    olhar(x, y) {
      this.iris.style.transform = "translate(" + (x * 30).toFixed(1) + "px," + (y * 9).toFixed(1) + "px)";
    }

    piscar() {
      this.corpo.classList.add("piscando");
      setTimeout(() => this.corpo.classList.remove("piscando"), 140);
    }

    dilatar(escala) {
      this.pupila.style.transform = "scale(" + escala + ")";
    }
  }

  const rnd = (a, b) => a + Math.random() * (b - a);


  /* O buraco negro que abre atrás do vigia enquanto ele vasculha.
   * Canvas 2D: brilho de fundo, disco de acreção inclinado (partículas que
   * caem em espiral, mais rápidas e mais quentes perto do centro), horizonte
   * de eventos, anel de fótons e o arco de luz "dobrada" por cima do núcleo.
   * Só desenha enquanto está visível; some suavemente ao sair do estado. */
  class BuracoNegro {
    constructor(palco) {
      this.cv = document.createElement("canvas");
      this.cv.className = "buraco-negro";
      this.cv.setAttribute("aria-hidden", "true");
      palco.insertBefore(this.cv, palco.firstChild);
      this.ctx = this.cv.getContext("2d");
      this.forca = 0;      // 0..1, vai suavizando até o alvo
      this.alvo = 0;
      this.giro = 0;
      this.calmo = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
      this.parts = [];
      for (let i = 0; i < 420; i++) this.parts.push(this._nova(true));
      this._medir();
      window.addEventListener("resize", () => this._medir());
    }

    _medir() {
      const r = this.cv.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      this.w = Math.max(1, r.width); this.h = Math.max(1, r.height);
      this.cv.width = Math.round(this.w * dpr); this.cv.height = Math.round(this.h * dpr);
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    _nova(espalhar) {
      // raio em unidades do núcleo (1 = horizonte de eventos)
      return { a: rnd(0, Math.PI * 2), r: espalhar ? rnd(1.25, 4.6) : rnd(3.6, 4.8),
               v: rnd(0.75, 1.25), t: rnd(0.6, 1.6), queda: rnd(0.0022, 0.0055) };
    }

    ligar(sim) { this.alvo = sim ? 1 : 0; }

    tique(dt) {
      this.forca += (this.alvo - this.forca) * Math.min(1, dt * (this.alvo ? 1.6 : 2.6));
      if (this.forca < 0.004 && this.alvo === 0) {
        if (this._sujo) { this.ctx.clearRect(0, 0, this.w, this.h); this._sujo = false; }
        this.forca = 0;
        return;
      }
      if (!this.w || this.w < 2) this._medir();
      this._sujo = true;
      const k = this.calmo ? 0.15 : 1;
      this.giro += dt * 0.35 * k;
      this._desenhar(dt * k);
    }

    _desenhar(dt) {
      const c = this.ctx, f = this.forca;
      const cx = this.w / 2, cy = this.h / 2;
      // o núcleo "abre" de dentro pra fora (easeOutBack leve)
      const e = 1 - Math.pow(1 - f, 3);
      const R = Math.min(this.w * 0.145, this.h * 0.33) * (0.35 + 0.65 * e);
      const INCL = 0.24;                          // achatamento do disco (visto quase de lado)
      c.clearRect(0, 0, this.w, this.h);
      c.globalAlpha = f;

      // brilho difuso de fundo
      let g = c.createRadialGradient(cx, cy, R * 0.8, cx, cy, R * 4.6);
      g.addColorStop(0, "rgba(160,115,255,.42)");
      g.addColorStop(0.35, "rgba(95,60,210,.18)");
      g.addColorStop(1, "rgba(20,10,60,0)");
      c.fillStyle = g;
      c.fillRect(0, 0, this.w, this.h);

      c.save();
      c.translate(cx, cy); c.rotate(-0.157); c.translate(-cx, -cy);   // mesma inclinação do olho

      // atualiza partículas: caem em espiral, mais rápidas perto do centro
      for (const p of this.parts) {
        p.pa = p.a; p.pr = p.r;
        p.a += dt * p.v * 2.4 / Math.pow(p.r, 1.5);
        p.r -= dt * 60 * p.queda * (1 + 1.6 / p.r);
        if (p.r < 1.08) Object.assign(p, this._nova(false), { pa: undefined });
      }

      const rastro = (frente) => {
        c.globalCompositeOperation = "lighter";
        c.lineCap = "round";
        for (const p of this.parts) {
          if (p.pa === undefined) continue;
          const naFrente = Math.sin(p.a) > 0;
          if (naFrente !== frente) continue;
          const quente = Math.max(0, Math.min(1, (4.6 - p.r) / 3.4));   // 0 fora, 1 perto do núcleo
          const x0 = cx + Math.cos(p.pa) * p.pr * R, y0 = cy + Math.sin(p.pa) * p.pr * R * INCL;
          // estica o rastro pra trás pra parecer movimento
          const a1 = p.a + 0.06 * p.v / Math.pow(p.r, 0.5);
          const x1 = cx + Math.cos(a1) * p.r * R, y1 = cy + Math.sin(a1) * p.r * R * INCL;
          const lum = 55 + quente * 38;
          const hue = 265 - quente * 25;         // violeta -> lilás quase branco no centro
          c.strokeStyle = `hsla(${hue}, 100%, ${lum}%, ${Math.min(1, (0.35 + quente * 0.8) * p.t)})`;
          c.lineWidth = 1 + quente * 2.4 * p.t;
          c.beginPath(); c.moveTo(x0, y0); c.lineTo(x1, y1); c.stroke();
        }
        c.globalCompositeOperation = "source-over";
      };

      // disco: faixa contínua (atrás), partículas de trás
      const disco = (frente) => {
        c.save();
        c.translate(cx, cy); c.scale(1, INCL);
        c.globalCompositeOperation = "lighter";
        const gd = c.createRadialGradient(0, 0, R * 1.05, 0, 0, R * 3.9);
        gd.addColorStop(0, "rgba(245,235,255,.9)");
        gd.addColorStop(0.12, "rgba(200,160,255,.7)");
        gd.addColorStop(0.3, "rgba(150,100,255,.38)");
        gd.addColorStop(0.6, "rgba(100,60,220,.14)");
        gd.addColorStop(1, "rgba(60,30,160,0)");
        c.fillStyle = gd;
        c.beginPath();
        if (frente) { c.ellipse(0, 0, R * 3.9, R * 3.9, 0, 0, Math.PI); }
        else { c.ellipse(0, 0, R * 3.9, R * 3.9, 0, Math.PI, Math.PI * 2); }
        c.ellipse(0, 0, R * 1.02, R * 1.02, 0, 0, Math.PI * 2, true);
        c.fill("evenodd");
        c.restore();
        c.globalCompositeOperation = "source-over";
      };

      disco(false);
      rastro(false);

      // luz dobrada pela gravidade: a parte de trás do disco aparece como um
      // arco por cima do núcleo, e uma imagem fina por baixo
      c.save();
      c.globalCompositeOperation = "lighter";
      c.shadowColor = "rgba(170,120,255,.95)";
      for (let i = 0; i < 4; i++) {
        c.beginPath();
        c.ellipse(cx, cy, R * (1.16 + i * 0.09), R * (1.12 + i * 0.1), 0, Math.PI * 1.02, Math.PI * 1.98);
        c.strokeStyle = `rgba(${230 - i * 20},${205 - i * 25},255,${0.75 - i * 0.17})`;
        c.lineWidth = R * (0.13 - i * 0.025);
        c.shadowBlur = R * 0.45;
        c.stroke();
      }
      c.beginPath();
      c.ellipse(cx, cy, R * 1.12, R * 1.1, 0, Math.PI * 0.08, Math.PI * 0.92);
      c.strokeStyle = "rgba(215,190,255,.5)";
      c.lineWidth = R * 0.05; c.shadowBlur = R * 0.3;
      c.stroke();
      c.restore();

      // horizonte de eventos
      g = c.createRadialGradient(cx, cy, R * 0.6, cx, cy, R * 1.12);
      g.addColorStop(0, "#000");
      g.addColorStop(0.82, "#000");
      g.addColorStop(1, "rgba(0,0,0,0)");
      c.fillStyle = g;
      c.beginPath(); c.arc(cx, cy, R * 1.12, 0, Math.PI * 2); c.fill();

      // anel de fótons (fino e brilhante, pulsa de leve)
      c.save();
      c.globalCompositeOperation = "lighter";
      c.beginPath(); c.arc(cx, cy, R * 1.03, 0, Math.PI * 2);
      c.strokeStyle = `rgba(225,205,255,${0.55 + 0.2 * Math.sin(this.giro * 6)})`;
      c.lineWidth = Math.max(1, R * 0.045);
      c.shadowColor = "rgba(185,140,255,1)"; c.shadowBlur = R * 0.35;
      c.stroke();
      c.restore();

      // parte da frente do disco passa NA FRENTE do núcleo
      disco(true);
      rastro(true);
      c.restore();
      c.globalAlpha = 1;
    }
  }

  /* O vigia: o olho grande + o enxame de olhos que aparece quando ele está vigiando. */
  class Vigia {
    constructor(palco, opc) {
      opc = opc || {};
      this.palco = palco;
      this.estado = "repouso";
      this.buraco = opc.buraco === false ? null : new BuracoNegro(palco);
      const grande = document.createElement("div");
      grande.className = "olho olho-grande";
      palco.appendChild(grande);
      this.olho = new Olho(grande);
      this.olhos = [this.olho];
      this.enxame = [];
      const n = opc.enxame || 0;
      for (let i = 0; i < n; i++) {
        const el = document.createElement("div");
        el.className = "olho olho-enxame";
        const a = (i / n) * Math.PI * 2 + rnd(-0.12, 0.12);
        const rx = rnd(41, 46), ry = rnd(38, 44);
        el.style.left = (50 + Math.cos(a) * rx).toFixed(2) + "%";
        el.style.top = (50 + Math.sin(a) * ry).toFixed(2) + "%";
        el.style.setProperty("--s", rnd(0.55, 1).toFixed(2));
        el.style.transitionDelay = (i * 45) + "ms";
        palco.appendChild(el);
        const o = new Olho(el, { detalhes: false });
        o._prox = 0;
        Object.assign(o, { _el: el, _a: a, _rx: rx, _ry: ry });
        this.enxame.push(o);
      }
      this.extras = [];
      this._piscarEm = performance.now() + rnd(2500, 5000);
      this._olharEm = 0;
      this._antes = performance.now();
      requestAnimationFrame(t => this._tique(t));
    }

    acompanhar(olho) { this.extras.push(olho); }

    definir(estado) {
      this.estado = estado;
      this.palco.dataset.estado = estado;
      if (this.buraco) this.buraco.ligar(estado === "vigiando");
      this.extras.forEach(o => o.svg.parentNode.dataset.estado = estado);
      const dil = { alerta: 0.68, ok: 1.12, vigiando: 0.85 }[estado] || 1;
      [this.olho].concat(this.extras).forEach(o => o.dilatar(dil));
      if (estado === "alerta") this.olho.olhar(0, 0.15);
      this._olharEm = 0;
    }

    _tique(t) {
      const vig = this.estado === "vigiando";
      const dt = Math.min(0.05, Math.max(0, (t - this._antes) / 1000));
      this._antes = t;
      if (this.buraco) {
        this.buraco.tique(dt);
        // a gravidade arrasta o enxame em órbita lenta enquanto o buraco está aberto
        const forca = this.buraco.forca;
        if (forca > 0.01 && !this.buraco.calmo) {
          this.enxame.forEach((o, i) => {
            o._a += dt * forca * (0.16 + (i % 3) * 0.03);
            const aperto = 1 - forca * 0.08;
            o._el.style.left = (50 + Math.cos(o._a) * o._rx * aperto).toFixed(2) + "%";
            o._el.style.top = (50 + Math.sin(o._a) * o._ry * aperto).toFixed(2) + "%";
          });
        }
      }
      if (t >= this._olharEm && this.estado !== "alerta") {
        const amp = vig ? 0.95 : 0.4;
        const x = rnd(-amp, amp), y = rnd(-0.6, 0.6) * (vig ? 1 : 0.5);
        this.olho.olhar(x, y);
        this.extras.forEach(o => o.olhar(x, y));
        this._olharEm = t + (vig ? rnd(260, 600) : rnd(1400, 3200));
      }
      if (vig) {
        this.enxame.forEach(o => {
          if (t >= o._prox) {
            o.olhar(rnd(-1, 1), rnd(-0.9, 0.9));
            o._prox = t + rnd(380, 1300);
            if (Math.random() < 0.08) o.piscar();
          }
        });
      }
      if (t >= this._piscarEm) {
        this.olho.piscar();
        this.extras.forEach(o => o.piscar());
        this._piscarEm = t + (vig ? rnd(1800, 3200) : rnd(3200, 6500));
      }
      requestAnimationFrame(tt => this._tique(tt));
    }
  }

  window.ArgosOlho = { Olho, Vigia };
})();
