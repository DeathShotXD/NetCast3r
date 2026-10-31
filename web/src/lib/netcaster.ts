/**
 * Netcaster: NetCast3r's own cursor.
 *
 * The banner's hooded figure throws a web over whatever it hunts. This brings
 * that gesture into the live shell without taking over the pointer: a small
 * acid reticle trails the pointer, and as it comes near any interactive
 * element it spins a net out to that element's corners, tightens, and knots
 * itself to the edge. Pull away and the strands stretch and melt. A press
 * throws a short burst of web.
 *
 * It is a progressive enhancement. It starts only for a fine pointer with
 * motion allowed, it never runs under reduced motion, it hands the native
 * cursor back over text fields, and every caller can stop it.
 */

const ACID = [200, 248, 26] as const;
const HOT = [245, 248, 125] as const;
const VIOLET = [159, 35, 221] as const;
const TAU = Math.PI * 2;

const TARGET_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([type=hidden])',
  'select',
  'textarea',
  '[role="button"]',
  '[role="tab"]',
  '[role="link"]',
  '[data-nc-target]'
].join(',');

type Rgb = readonly [number, number, number];

export type NetcasterOptions = {
  /** Distance, in px, at which the net starts reaching for an element. */
  sense?: number;
  /** Distance, in px, at which the net grabs the element. */
  reach?: number;
};

type Target = { el: HTMLElement; rect: DOMRect };

type Point = { x: number; y: number };
type Burst = { x: number; y: number; start: number };

function rgba(color: Rgb, alpha: number): string {
  return `rgba(${color[0]}, ${color[1]}, ${color[2]}, ${alpha})`;
}

function labelOf(el: HTMLElement): string {
  const raw =
    el.getAttribute('data-nc-label') ||
    el.getAttribute('aria-label') ||
    el.getAttribute('title') ||
    (el.textContent || '');
  return raw.replace(/\s+/g, ' ').trim().slice(0, 22).toUpperCase();
}

/** Corner and edge-midpoint anchors, so the net reads as a net. */
function netAnchors(rect: DOMRect): Point[] {
  const { left, top, right, bottom, width, height } = rect;
  const midX = (left + right) / 2;
  const midY = (top + bottom) / 2;
  const points: Point[] = [
    { x: left, y: top },
    { x: right, y: top },
    { x: right, y: bottom },
    { x: left, y: bottom }
  ];
  if (width > 96 && height > 34) {
    points.push(
      { x: midX, y: top },
      { x: right, y: midY },
      { x: midX, y: bottom },
      { x: left, y: midY }
    );
  }
  return points;
}

/** Distance from a point to a rect, zero when the point is inside it. */
function distanceToRect(x: number, y: number, rect: DOMRect): number {
  const dx = Math.max(rect.left - x, 0, x - rect.right);
  const dy = Math.max(rect.top - y, 0, y - rect.bottom);
  return Math.hypot(dx, dy);
}

export class Netcaster {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D | null;
  private sense: number;
  private reach: number;

  private raf = 0;
  private running = false;
  private destroyed = false;

  private x = -100;
  private y = -100;
  private lastMove = 0;
  private seen = false;
  private trail: { x: number; y: number; t: number }[] = [];
  private bursts: Burst[] = [];

  private targets: Target[] = [];
  private caught: HTMLElement | null = null;
  private scanTimer = 0;
  private scanQueued = false;

  private observer: MutationObserver | null = null;
  private media: MediaQueryList | null = null;

  private onPointerMove = (event: PointerEvent) => this.pointerMove(event);
  private onPointerDown = (event: PointerEvent) => this.pointerDown(event);
  private onPointerLeave = () => this.hide();
  private onScroll = () => this.queueScan();
  private onResize = () => {
    this.resize();
    this.queueScan();
  };

  constructor(canvas: HTMLCanvasElement, options: NetcasterOptions = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.sense = options.sense ?? 240;
    this.reach = options.reach ?? 88;
  }

  get active(): boolean {
    return this.running;
  }

  start(): void {
    if (this.running || this.destroyed) return;
    if (typeof window === 'undefined') return;
    this.media = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (this.media.matches) return;
    this.media.addEventListener('change', this.onMotionChange);
    this.running = true;
    this.resize();
    this.bind();
    this.scan();
    this.scanTimer = window.setInterval(() => this.scan(), 400);
    this.raf = window.requestAnimationFrame(this.frame);
  }

  stop(): void {
    if (!this.running) return;
    this.running = false;
    window.cancelAnimationFrame(this.raf);
    window.clearInterval(this.scanTimer);
    this.unbind();
    this.release();
    this.trail = [];
    this.bursts = [];
    this.seen = false;
    document.documentElement.classList.remove('nc-live');
    this.clear();
  }

  destroy(): void {
    this.stop();
    this.observer?.disconnect();
    this.observer = null;
    this.media?.removeEventListener('change', this.onMotionChange);
    this.destroyed = true;
  }

  // -- plumbing ----------------------------------------------------------
  private onMotionChange = () => {
    if (this.media?.matches) this.stop();
  };

  private bind(): void {
    window.addEventListener('pointermove', this.onPointerMove, { passive: true });
    window.addEventListener('pointerdown', this.onPointerDown, { passive: true });
    window.addEventListener('pointerleave', this.onPointerLeave, { passive: true });
    window.addEventListener('blur', this.onPointerLeave);
    window.addEventListener('scroll', this.onScroll, { passive: true, capture: true });
    window.addEventListener('resize', this.onResize, { passive: true });
    this.observer = new MutationObserver(() => this.queueScan());
    this.observer.observe(document.body, { childList: true, subtree: true });
  }

  private unbind(): void {
    window.removeEventListener('pointermove', this.onPointerMove);
    window.removeEventListener('pointerdown', this.onPointerDown);
    window.removeEventListener('pointerleave', this.onPointerLeave);
    window.removeEventListener('blur', this.onPointerLeave);
    window.removeEventListener('scroll', this.onScroll, { capture: true });
    window.removeEventListener('resize', this.onResize);
    this.observer?.disconnect();
    this.observer = null;
  }

  private pointerMove(event: PointerEvent): void {
    if (event.pointerType === 'touch') return;
    this.x = event.clientX;
    this.y = event.clientY;
    this.lastMove = performance.now();
    if (!this.seen) {
      this.seen = true;
      document.documentElement.classList.add('nc-live');
    }
    const last = this.trail[this.trail.length - 1];
    if (!last || Math.hypot(this.x - last.x, this.y - last.y) > 3) {
      this.trail.push({ x: this.x, y: this.y, t: this.lastMove });
      if (this.trail.length > 16) this.trail.shift();
    }
  }

  private pointerDown(event: PointerEvent): void {
    if (event.pointerType === 'touch') return;
    this.bursts.push({ x: event.clientX, y: event.clientY, start: performance.now() });
    if (this.bursts.length > 4) this.bursts.shift();
  }

  private hide(): void {
    this.seen = false;
    this.lastMove = 0;
    this.trail = [];
    this.release();
    document.documentElement.classList.remove('nc-live');
    this.clear();
  }

  private queueScan(): void {
    if (this.scanQueued) return;
    this.scanQueued = true;
    window.setTimeout(() => {
      this.scanQueued = false;
      this.scan();
    }, 120);
  }

  private scan(): void {
    if (!this.running) return;
    const found: Target[] = [];
    const nodes = document.querySelectorAll<HTMLElement>(TARGET_SELECTOR);
    nodes.forEach((el) => {
      if (el.closest('.nc-skip')) return;
      if (el.hasAttribute('disabled')) return;
      const rect = el.getBoundingClientRect();
      if (rect.width < 6 || rect.height < 6) return;
      if (rect.bottom < -80 || rect.top > window.innerHeight + 80) return;
      if (rect.right < -80 || rect.left > window.innerWidth + 80) return;
      found.push({ el, rect });
    });
    this.targets = found;
  }

  private resize(): void {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.canvas.width = Math.floor(window.innerWidth * dpr);
    this.canvas.height = Math.floor(window.innerHeight * dpr);
    this.canvas.style.width = `${window.innerWidth}px`;
    this.canvas.style.height = `${window.innerHeight}px`;
    this.ctx?.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  private clear(): void {
    this.ctx?.clearRect(0, 0, window.innerWidth, window.innerHeight);
  }

  private release(): void {
    if (this.caught) {
      this.caught.classList.remove('nc-caught');
      this.caught = null;
    }
  }

  private nearest(): { target: Target; distance: number } | null {
    let best: Target | null = null;
    let bestDistance = Infinity;
    for (const target of this.targets) {
      const distance = distanceToRect(this.x, this.y, target.rect);
      if (distance < bestDistance) {
        bestDistance = distance;
        best = target;
      }
    }
    if (!best) return null;
    return { target: best, distance: bestDistance };
  }

  // -- frame -------------------------------------------------------------
  private frame = (now: number) => {
    if (!this.running) return;
    this.raf = window.requestAnimationFrame(this.frame);
    try {
      this.draw(now);
    } catch {
      // A drawing fault must never strand the user without a cursor.
      this.stop();
    }
  };

  private draw(now: number): void {
    const ctx = this.ctx;
    if (!ctx || document.hidden) return;
    this.clear();
    ctx.globalCompositeOperation = 'lighter';

    const idle = now - this.lastMove > 2200 || !this.seen;
    if (!this.seen) return;

    const near = this.nearest();
    const withinSense = near && near.distance <= this.sense ? near : null;
    const caughtTarget = near && near.distance <= this.reach ? near.target.el : null;
    if (caughtTarget !== this.caught) {
      this.caught?.classList.remove('nc-caught');
      this.caught = caughtTarget;
      this.caught?.classList.add('nc-caught');
    }

    this.drawTrail(ctx, now, idle);
    if (withinSense) {
      const grabbed = withinSense.distance <= this.reach;
      this.drawNet(ctx, now, withinSense.target.rect, withinSense.distance, grabbed);
    }
    this.drawBursts(ctx, now);
    this.drawCore(ctx, now, idle, !!caughtTarget);
  }

  private drawTrail(ctx: CanvasRenderingContext2D, now: number, idle: boolean): void {
    if (idle || this.trail.length < 2) return;
    for (let i = 1; i < this.trail.length; i += 1) {
      const a = this.trail[i - 1];
      const b = this.trail[i];
      const age = (now - b.t) / 600;
      const alpha = Math.max(0, 0.3 * (1 - age) * (i / this.trail.length));
      if (alpha <= 0.01) continue;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = rgba(ACID, alpha);
      ctx.lineWidth = 0.8;
      ctx.stroke();
    }
  }

  private drawNet(
    ctx: CanvasRenderingContext2D,
    now: number,
    rect: DOMRect,
    distance: number,
    grabbed: boolean
  ): void {
    const anchors = netAnchors(rect);
    const closeness = 1 - Math.min(1, distance / this.sense);
    const pull = grabbed ? 1 : 0.3 + closeness * 0.5;
    const strandAlpha = 0.14 + pull * 0.62;
    const core: Point = { x: this.x, y: this.y };

    // Perimeter threads: the outline of the net itself.
    ctx.beginPath();
    anchors.forEach((point, index) => {
      const next = anchors[(index + 1) % anchors.length];
      ctx.moveTo(point.x, point.y);
      ctx.lineTo(next.x, next.y);
    });
    ctx.strokeStyle = rgba(ACID, strandAlpha * 0.6);
    ctx.lineWidth = grabbed ? 1 : 0.7;
    ctx.stroke();

    // Strands from the reticle to every anchor, with an electric glow.
    ctx.shadowColor = rgba(ACID, grabbed ? 0.55 : 0.22);
    ctx.shadowBlur = grabbed ? 9 : 3;
    anchors.forEach((point, index) => {
      const wobble = Math.sin(now * 0.0022 + index * 1.7) * 3.2;
      const midX = (core.x + point.x) / 2;
      const midY = (core.y + point.y) / 2;
      const dx = point.x - core.x;
      const dy = point.y - core.y;
      const length = Math.hypot(dx, dy) || 1;
      const ctrlX = midX + (-dy / length) * (6 + wobble);
      const ctrlY = midY + (dx / length) * (6 + wobble);
      ctx.beginPath();
      ctx.moveTo(core.x, core.y);
      ctx.quadraticCurveTo(ctrlX, ctrlY, point.x, point.y);
      ctx.strokeStyle = rgba(index % 2 ? HOT : ACID, strandAlpha);
      ctx.lineWidth = grabbed ? 1.2 : 0.85;
      ctx.stroke();

      // Knot: a small cross tick anchored on the element edge.
      const tick = grabbed ? 3.4 : 2.2;
      ctx.beginPath();
      ctx.moveTo(point.x - tick, point.y);
      ctx.lineTo(point.x + tick, point.y);
      ctx.moveTo(point.x, point.y - tick);
      ctx.lineTo(point.x, point.y + tick);
      ctx.strokeStyle = rgba(HOT, 0.24 + pull * 0.66);
      ctx.lineWidth = 1.1;
      ctx.stroke();

      if (grabbed) {
        const phase = (now * 0.0016 + index / anchors.length) % 1;
        const px = (1 - phase) * (1 - phase) * core.x + 2 * (1 - phase) * phase * ctrlX + phase * phase * point.x;
        const py = (1 - phase) * (1 - phase) * core.y + 2 * (1 - phase) * phase * ctrlY + phase * phase * point.y;
        ctx.beginPath();
        ctx.arc(px, py, 1.6, 0, TAU);
        ctx.fillStyle = rgba(HOT, 0.95);
        ctx.fill();
      }
    });
    ctx.shadowBlur = 0;

    // An X across the net when it is tight, so it reads as a cast, not a fan.
    if (grabbed && anchors.length >= 4) {
      ctx.beginPath();
      ctx.moveTo(anchors[0].x, anchors[0].y);
      ctx.lineTo(anchors[2].x, anchors[2].y);
      ctx.moveTo(anchors[1].x, anchors[1].y);
      ctx.lineTo(anchors[3].x, anchors[3].y);
      ctx.strokeStyle = rgba(ACID, strandAlpha * 0.45);
      ctx.lineWidth = 0.7;
      ctx.stroke();
    }
  }

  private drawBursts(ctx: CanvasRenderingContext2D, now: number): void {
    this.bursts = this.bursts.filter((burst) => now - burst.start < 460);
    for (const burst of this.bursts) {
      const age = (now - burst.start) / 460;
      const radius = 8 + age * 46;
      const alpha = (1 - age) * 0.5;
      ctx.beginPath();
      ctx.arc(burst.x, burst.y, radius, 0, TAU);
      ctx.strokeStyle = rgba(ACID, alpha * 0.6);
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.beginPath();
      for (let i = 0; i < 8; i += 1) {
        const angle = (i / 8) * TAU + burst.start;
        ctx.moveTo(burst.x + Math.cos(angle) * radius * 0.3, burst.y + Math.sin(angle) * radius * 0.3);
        ctx.lineTo(burst.x + Math.cos(angle) * radius, burst.y + Math.sin(angle) * radius);
      }
      ctx.strokeStyle = rgba(HOT, alpha * 0.5);
      ctx.lineWidth = 0.8;
      ctx.stroke();
    }
  }

  private drawCore(ctx: CanvasRenderingContext2D, now: number, idle: boolean, grabbed: boolean): void {
    const breathe = idle ? 0.55 + Math.sin(now * 0.002) * 0.15 : 1;
    ctx.save();
    ctx.translate(this.x, this.y);
    ctx.rotate(now * 0.0009);
    const size = grabbed ? 6.4 : 8.4;
    ctx.beginPath();
    ctx.moveTo(0, -size);
    ctx.lineTo(size, 0);
    ctx.lineTo(0, size);
    ctx.lineTo(-size, 0);
    ctx.closePath();
    ctx.strokeStyle = rgba(HOT, (grabbed ? 0.95 : 0.7) * breathe);
    ctx.lineWidth = 1.15;
    ctx.stroke();
    ctx.restore();

    ctx.beginPath();
    ctx.arc(this.x, this.y, grabbed ? 5.4 : 7.6, 0, TAU);
    ctx.strokeStyle = rgba(ACID, 0.34 * breathe);
    ctx.lineWidth = 0.8;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(this.x, this.y, 2.1, 0, TAU);
    ctx.fillStyle = rgba(VIOLET, 0.95);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(this.x, this.y, 1.1, 0, TAU);
    ctx.fillStyle = rgba(HOT, 0.95);
    ctx.fill();

    if (grabbed && this.caught) {
      const label = labelOf(this.caught);
      if (label) {
        const text = `NET ${label}`;
        ctx.font = '600 10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
        ctx.textBaseline = 'middle';
        const width = ctx.measureText(text).width;
        const lx = Math.min(this.x + 14, window.innerWidth - width - 18);
        const ly = this.y + 22;
        ctx.globalCompositeOperation = 'source-over';
        ctx.fillStyle = rgba(ACID, 0.95);
        ctx.fillText(text, lx, ly);
        ctx.beginPath();
        ctx.moveTo(lx, ly + 7.5);
        ctx.lineTo(lx + width, ly + 7.5);
        ctx.strokeStyle = rgba(ACID, 0.5);
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }
    }
  }
}
