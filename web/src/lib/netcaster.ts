/**
 * Netcaster: NetCast3r's own cursor.
 *
 * The banner's hooded figure throws a web over whatever it hunts. This brings
 * that gesture into the live shell without taking over the pointer: an acid
 * reticle trails the pointer on a short elastic leash, and as it comes near any
 * interactive element it spins a net out to that element's corners, tightens,
 * knots itself to the edge, and runs a hot bead along every strand. Pull away
 * and the net melts. A press throws a burst, and keyboard focus casts a web of
 * its own.
 *
 * Only elements that are really there get hunted. The net is occlusion aware:
 * a control behind an open command palette, a modal backdrop, a closed drawer,
 * a `visibility: hidden` or zero-opacity ghost, or anything with
 * `pointer-events: none` is never a target, because the engine asks the browser
 * what is actually topmost under the probe before it casts. It is also zone
 * aware: it only reaches for controls that live in the same region the pointer
 * is in, so the sidebar never webs up while you work in the content pane.
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
  'summary',
  '[role="button"]',
  '[role="tab"]',
  '[role="link"]',
  '[role="menuitem"]',
  '[data-nc-target]'
].join(',');

/**
 * Regions the net is allowed to hunt within. A control is only a target when
 * it shares a region with the pointer, so the sidebar never lights up while the
 * pointer is in the content pane. `[data-nc-zone]` lets a view carve its own.
 */
const ZONE_SELECTOR = [
  '[data-nc-zone]',
  'main',
  'aside',
  'nav',
  'header',
  'footer',
  'section',
  'form',
  'dialog',
  '[role="dialog"]',
  '[role="region"]',
  '[role="tablist"]'
].join(',');

const IDLE_MS = 2200;
const TRAIL_MS = 620;
const BURST_MS = 480;
const MELT_MS = 280;
const GRAB_RIPPLE_MS = 300;
const FOCUS_MS = 900;
const MAX_TARGETS = 500;
const MAX_ATTEMPTS = 5;
/** Never scan the document more often than this, however busy the DOM is. */
const MIN_SCAN_MS = 400;
/** Time constant, in ms, of the elastic leash that pulls the reticle. */
const LEASH_MS = 45;
/** How far, as a fraction, the reticle leans toward a grabbed element. */
const MAGNET_LEAN = 0.12;

type Rgb = readonly [number, number, number];

export type NetcasterOptions = {
  /** Distance, in px, at which the net starts reaching for an element. */
  sense?: number;
  /** Distance, in px, at which the net grabs the element. */
  reach?: number;
};

type Target = { el: HTMLElement; rect: DOMRect; zone: Element | null };

type Point = { x: number; y: number };
type Burst = { x: number; y: number; start: number };
type Melt = { rect: DOMRect; grabbed: boolean; x: number; y: number; start: number };
type Ripple = { rect: DOMRect; start: number };
type NetSnapshot = { rect: DOMRect; grabbed: boolean; x: number; y: number };

type VisibilityOptions = {
  checkOpacity?: boolean;
  checkVisibilityCSS?: boolean;
  contentVisibilityAuto?: boolean;
};

function rgba(color: Rgb, alpha: number): string {
  return `rgba(${color[0]}, ${color[1]}, ${color[2]}, ${alpha})`;
}

function clamp(value: number, low: number, high: number): number {
  return value < low ? low : value > high ? high : value;
}

function cleanLabel(value: string): string {
  const text = value.replace(/\s+/g, ' ').trim();
  // Drop a trailing badge count so "Missions 15" reads as "MISSIONS".
  const trimmed = text.replace(/\s*\d+\s*$/, '').trim();
  return (trimmed || text).slice(0, 22).toUpperCase();
}

function labelOf(el: HTMLElement): string {
  const explicit = el.getAttribute('data-nc-label') || el.getAttribute('aria-label');
  if (explicit) return cleanLabel(explicit);
  // innerText puts each rendered block on its own line, so a row with a glyph,
  // a name and a hint yields just the name.
  const rendered = (el.innerText || el.textContent || '').split('\n');
  for (const line of rendered) {
    if (/[a-z]/i.test(line)) return cleanLabel(line);
  }
  return cleanLabel(el.getAttribute('title') || '');
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

function roundRectPath(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  radius: number
): void {
  const r = Math.min(radius, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

export class Netcaster {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D | null;
  private sense: number;
  private reach: number;

  private raf = 0;
  private running = false;
  private destroyed = false;

  /** Raw pointer position: what the browser hit-tests against. */
  private x = -100;
  private y = -100;
  /** Leashed position: what the reticle and its strands are drawn from. */
  private rx = -100;
  private ry = -100;
  /** Drawn origin: the leashed position, leaned toward a grabbed element. */
  private ox = -100;
  private oy = -100;
  private lastNow = 0;
  private lastMove = 0;
  private seen = false;
  private keyboard = false;
  private dpr = 1;
  private nativeFallback = false;
  private popovers = true;

  private trail: { x: number; y: number; t: number }[] = [];
  private bursts: Burst[] = [];
  private melts: Melt[] = [];
  private ripples: Ripple[] = [];
  private lastNet: NetSnapshot | null = null;

  private targets: Target[] = [];
  private caught: HTMLElement | null = null;
  private caughtLabel = '';
  private focused: HTMLElement | null = null;
  private focusLabel = '';
  private focusAt = 0;
  private tag: HTMLDivElement | null = null;
  private focusTag: HTMLDivElement | null = null;
  private scanTimer = 0;
  private scanQueued = false;
  private dirty = true;
  private lastScanAt = 0;

  private observer: MutationObserver | null = null;
  private media: MediaQueryList | null = null;

  private onPointerMove = (event: PointerEvent) => this.pointerMove(event);
  private onPointerDown = (event: PointerEvent) => this.pointerDown(event);
  private onPointerLeave = () => this.hide();
  private onScroll = () => this.queueScan();
  private onKeyDown = () => {
    this.keyboard = true;
  };
  private onFocusIn = (event: Event) => this.focusIn(event);
  private onFocusOut = () => {
    this.focused = null;
    this.focusLabel = '';
  };
  private onResize = () => {
    this.resize();
    this.queueScan();
  };

  constructor(canvas: HTMLCanvasElement, options: NetcasterOptions = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.sense = options.sense ?? 190;
    this.reach = options.reach ?? 78;
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
    this.ensureTags();
    this.scan();
    this.scanTimer = window.setInterval(() => this.scan(), 800);
    this.raf = window.requestAnimationFrame(this.frame);
  }

  stop(): void {
    if (!this.running) return;
    this.running = false;
    window.cancelAnimationFrame(this.raf);
    window.clearInterval(this.scanTimer);
    this.scanTimer = 0;
    this.unbind();
    this.release();
    this.trail = [];
    this.bursts = [];
    this.melts = [];
    this.ripples = [];
    this.lastNet = null;
    this.seen = false;
    this.rx = -100;
    this.ry = -100;
    this.nativeFallback = false;
    document.documentElement.classList.remove('nc-live');
    document.documentElement.classList.remove('nc-native');
    this.hideTags();
    this.clear();
  }

  destroy(): void {
    this.stop();
    this.observer?.disconnect();
    this.observer = null;
    this.media?.removeEventListener('change', this.onMotionChange);
    this.destroyed = true;
    this.tag?.remove();
    this.tag = null;
    this.focusTag?.remove();
    this.focusTag = null;
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
    window.addEventListener('keydown', this.onKeyDown, { passive: true, capture: true });
    document.addEventListener('focusin', this.onFocusIn, true);
    document.addEventListener('focusout', this.onFocusOut, true);
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
    window.removeEventListener('keydown', this.onKeyDown, { capture: true });
    document.removeEventListener('focusin', this.onFocusIn, true);
    document.removeEventListener('focusout', this.onFocusOut, true);
    this.observer?.disconnect();
    this.observer = null;
  }

  private pointerMove(event: PointerEvent): void {
    if (event.pointerType === 'touch') return;
    this.x = event.clientX;
    this.y = event.clientY;
    this.lastMove = performance.now();
    if (!this.seen) {
      // Snap the leash so the reticle does not slide in from the corner.
      this.seen = true;
      this.rx = this.x;
      this.ry = this.y;
      this.lastNow = 0;
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
    // A press is a pointer gesture: it retires the keyboard focus web.
    this.keyboard = false;
    this.bursts.push({ x: event.clientX, y: event.clientY, start: performance.now() });
    if (this.bursts.length > 4) this.bursts.shift();
  }

  private focusIn(event: Event): void {
    const node = event.target;
    if (!(node instanceof HTMLElement)) return;
    const match = node.matches(TARGET_SELECTOR)
      ? node
      : (node.closest(TARGET_SELECTOR) as HTMLElement | null);
    this.focused = match ?? null;
    this.focusLabel = match ? labelOf(match) : '';
    this.focusAt = performance.now();
  }

  private hide(): void {
    this.seen = false;
    this.keyboard = false;
    this.lastMove = 0;
    this.trail = [];
    this.melts = [];
    this.ripples = [];
    this.lastNet = null;
    this.release();
    this.nativeFallback = false;
    document.documentElement.classList.remove('nc-live');
    document.documentElement.classList.remove('nc-native');
    this.hideTags();
    this.clear();
  }

  private queueScan(): void {
    this.dirty = true;
    if (this.scanQueued) return;
    this.scanQueued = true;
    window.setTimeout(() => {
      this.scanQueued = false;
      this.scan();
    }, 320);
  }

  // -- targeting ---------------------------------------------------------
  /**
   * Is this element even allowed to be hunted? Hidden, disabled, inert, or
   * fully transparent elements are not real parts of the interface.
   */
  private admissible(el: HTMLElement): boolean {
    if (!el.isConnected) return false;
    if (el.hasAttribute('disabled')) return false;
    if (el.getAttribute('aria-disabled') === 'true') return false;
    if (el.closest('.nc-skip, [inert], [aria-hidden="true"]')) return false;

    const check = (el as unknown as { checkVisibility?: (o?: VisibilityOptions) => boolean })
      .checkVisibility;
    if (typeof check === 'function') {
      try {
        // One engine call covers display, visibility, opacity and
        // content-visibility, which keeps the scan cheap on busy screens.
        return check.call(el, {
          checkOpacity: true,
          checkVisibilityCSS: true,
          contentVisibilityAuto: true
        });
      } catch {
        /* older signature: fall through to the computed style */
      }
    }

    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (style.pointerEvents === 'none') return false;
    if (Number.parseFloat(style.opacity) < 0.08) return false;
    return true;
  }

  private scan(): void {
    if (!this.running || document.hidden) return;
    const now = performance.now();
    // Coalesce bursts: a streaming screen can mutate far faster than we need.
    if (now - this.lastScanAt < MIN_SCAN_MS) {
      this.queueScan();
      return;
    }
    if (!this.dirty && this.targets.length > 0) return;
    this.dirty = false;
    this.lastScanAt = now;
    const found: Target[] = [];
    const nodes = document.querySelectorAll<HTMLElement>(TARGET_SELECTOR);
    for (let i = 0; i < nodes.length && found.length < MAX_TARGETS; i += 1) {
      const el = nodes[i];
      if (!this.admissible(el)) continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 6 || rect.height < 6) continue;
      // Must overlap the viewport, not merely hover the margin of it.
      if (rect.right <= 0 || rect.bottom <= 0) continue;
      if (rect.left >= window.innerWidth || rect.top >= window.innerHeight) continue;
      found.push({ el, rect, zone: this.zoneOf(el) });
    }
    this.targets = found;
  }

  private probePoints(rect: DOMRect): Point[] {
    const inset = Math.min(3, rect.width / 4, rect.height / 4);
    const left = rect.left + inset;
    const right = rect.right - inset;
    const top = rect.top + inset;
    const bottom = rect.bottom - inset;
    return [
      { x: clamp(this.x, left, right), y: clamp(this.y, top, bottom) },
      { x: (left + right) / 2, y: (top + bottom) / 2 },
      { x: left, y: top },
      { x: right, y: bottom },
      { x: right, y: top },
      { x: left, y: bottom }
    ];
  }

  /**
   * Is the element genuinely topmost somewhere on its own footprint? This is
   * the fix for the net latching onto things that sit behind an overlay: we
   * ask the browser what is under each probe and reject anything the topmost
   * hit does not own.
   */
  private reachable(target: Target): boolean {
    const el = target.el;
    if (!el.isConnected) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 4 || rect.height < 4) return false;
    target.rect = rect;
    for (const point of this.probePoints(rect)) {
      if (point.x < 0 || point.y < 0) continue;
      if (point.x >= window.innerWidth || point.y >= window.innerHeight) continue;
      const top = document.elementFromPoint(point.x, point.y);
      if (top && (top === el || el.contains(top))) return true;
    }
    return false;
  }

  /** Nearest region that owns an element, or null when it lives loose. */
  private zoneOf(el: Element | null): Element | null {
    return el ? el.closest(ZONE_SELECTOR) : null;
  }

  /** Region the pointer is currently in, so hunting stays local. */
  private zoneUnderPointer(): Element | null {
    if (this.x < 0 || this.y < 0) return null;
    if (this.x >= window.innerWidth || this.y >= window.innerHeight) return null;
    return this.zoneOf(document.elementFromPoint(this.x, this.y));
  }

  private inZone(zone: Element | null, target: Target): boolean {
    if (!zone) return true;
    const home = target.zone;
    if (!home) return true;
    return home === zone || zone.contains(home) || home.contains(zone);
  }

  /** Nearest element within sense range that is not covered or out of zone. */
  private pick(): { target: Target; distance: number } | null {
    const zone = this.zoneUnderPointer();
    const tried = new Set<HTMLElement>();
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      let best: Target | null = null;
      let bestDistance = this.sense + 1;
      for (const target of this.targets) {
        if (tried.has(target.el)) continue;
        if (!this.inZone(zone, target)) continue;
        const distance = distanceToRect(this.x, this.y, target.rect);
        if (distance <= bestDistance) {
          bestDistance = distance;
          best = target;
        }
      }
      if (!best) return null;
      if (this.reachable(best)) return { target: best, distance: bestDistance };
      tried.add(best.el);
    }
    return null;
  }

  private release(): void {
    if (this.caught) {
      this.caught.classList.remove('nc-caught');
      this.caught = null;
    }
  }

  // -- canvas ------------------------------------------------------------
  private resize(): void {
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.canvas.width = Math.floor(window.innerWidth * this.dpr);
    this.canvas.height = Math.floor(window.innerHeight * this.dpr);
    this.canvas.style.width = `${window.innerWidth}px`;
    this.canvas.style.height = `${window.innerHeight}px`;
    this.ctx?.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
  }

  private clear(): void {
    this.ctx?.clearRect(0, 0, window.innerWidth, window.innerHeight);
  }

  /**
   * A dialog, popover, or fullscreen element lives in the top layer, which
   * paints above every z-index. The overlay cannot draw over it, so the shell
   * must not hide the native pointer there either.
   */
  private topLayerActive(): boolean {
    if (document.fullscreenElement) return true;
    if (document.querySelector('dialog[open]')) return true;
    if (this.popovers) {
      try {
        if (document.querySelector(':popover-open')) return true;
      } catch {
        this.popovers = false;
      }
    }
    return false;
  }

  private syncFallback(): void {
    const native = this.topLayerActive();
    if (native === this.nativeFallback) return;
    this.nativeFallback = native;
    document.documentElement.classList.toggle('nc-native', native);
    if (native) this.hideTags();
  }

  /**
   * Labels live in the DOM, not on the canvas: the canvas blends additively,
   * so it can add light but never lay down the dark plate a label needs to stay
   * readable over other text.
   */
  private ensureTags(): void {
    if (this.tag) return;
    const make = (variant: string): HTMLDivElement => {
      const el = document.createElement('div');
      el.className = `nc-tag ${variant}`;
      el.setAttribute('aria-hidden', 'true');
      document.body.appendChild(el);
      return el;
    };
    this.tag = make('nc-tag-net');
    this.focusTag = make('nc-tag-focus');
  }

  private setTag(tag: HTMLDivElement, text: string, x: number, y: number): void {
    if (tag.dataset.text !== text) {
      tag.textContent = text;
      tag.dataset.text = text;
      tag.dataset.w = '';
    }
    if (!tag.dataset.w) {
      tag.dataset.w = String(tag.offsetWidth);
      tag.dataset.h = String(tag.offsetHeight);
    }
    const w = Number(tag.dataset.w) || 90;
    const h = Number(tag.dataset.h) || 16;
    const tx = clamp(x, 4, Math.max(4, window.innerWidth - w - 6));
    const ty = clamp(y, 4, Math.max(4, window.innerHeight - h - 6));
    tag.style.transform = `translate3d(${Math.round(tx)}px, ${Math.round(ty)}px, 0)`;
    tag.classList.add('is-on');
  }

  private hideTags(): void {
    this.tag?.classList.remove('is-on');
    this.focusTag?.classList.remove('is-on');
  }

  private updateTags(): void {
    this.ensureTags();
    const net = this.tag;
    const focus = this.focusTag;
    if (!net || !focus) return;
    if (this.nativeFallback) {
      this.hideTags();
      return;
    }
    if (this.caught && this.caughtLabel) {
      this.setTag(net, `NET ${this.caughtLabel}`, this.ox + 14, this.oy + 22);
    } else {
      net.classList.remove('is-on');
    }

    const el = this.focused;
    if (
      this.keyboard &&
      el &&
      el.isConnected &&
      el !== this.caught &&
      !this.isTextLike(el) &&
      this.focusLabel
    ) {
      const rect = el.getBoundingClientRect();
      if (rect.width >= 6 && rect.height >= 6) {
        const right = rect.right + 9;
        const x = right + 120 > window.innerWidth ? rect.left + 6 : right;
        this.setTag(focus, `FOCUS ${this.focusLabel}`, x, rect.top + rect.height / 2 - 8);
      } else {
        focus.classList.remove('is-on');
      }
    } else {
      focus.classList.remove('is-on');
    }
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
    if (Math.min(window.devicePixelRatio || 1, 2) !== this.dpr) this.resize();
    this.syncFallback();
    this.clear();
    ctx.globalCompositeOperation = 'lighter';

    const dt = this.lastNow ? Math.min(now - this.lastNow, 60) : 16;
    this.lastNow = now;

    // Elastic leash: the reticle chases the pointer instead of being welded to
    // it, which is what makes the web feel thrown rather than drawn.
    const k = 1 - Math.exp(-dt / LEASH_MS);
    const goalX = this.seen ? this.x : this.rx;
    const goalY = this.seen ? this.y : this.ry;
    this.rx += (goalX - this.rx) * k;
    this.ry += (goalY - this.ry) * k;

    if (!this.seen) return;
    const idle = now - this.lastMove > IDLE_MS;

    const near = this.pick();
    const caughtTarget = near && near.distance <= this.reach ? near.target.el : null;

    // Magnet lean: inside the reach, the reticle pulls a little toward the
    // element it is about to take, so the grab feels physical.
    this.ox = this.rx;
    this.oy = this.ry;
    if (near && caughtTarget) {
      const rect = near.target.rect;
      const ax = clamp(this.x, rect.left, rect.right);
      const ay = clamp(this.y, rect.top, rect.bottom);
      this.ox += (ax - this.ox) * MAGNET_LEAN;
      this.oy += (ay - this.oy) * MAGNET_LEAN;
    }

    if (caughtTarget !== this.caught) {
      this.caught?.classList.remove('nc-caught');
      this.caught = caughtTarget;
      this.caughtLabel = caughtTarget ? labelOf(caughtTarget) : '';
      if (this.caught && near) {
        this.caught.classList.add('nc-caught');
        this.ripples.push({ rect: near.target.rect, start: now });
        if (this.ripples.length > 6) this.ripples.shift();
      }
    }

    this.drawTrail(ctx, now, idle);
    if (near) {
      const grabbed = near.distance <= this.reach;
      this.drawNet(ctx, now, near.target.rect, near.distance, grabbed, 1);
      this.lastNet = { rect: near.target.rect, grabbed, x: this.ox, y: this.oy };
    } else if (this.lastNet) {
      this.melts.push({ ...this.lastNet, start: now });
      if (this.melts.length > 6) this.melts.shift();
      this.lastNet = null;
    }
    this.drawMelts(ctx, now);
    this.drawRipples(ctx, now);
    this.drawFocus(ctx, now);
    this.drawBursts(ctx, now);
    this.drawCore(ctx, now, idle, !!caughtTarget);
    this.updateTags();
  }

  private drawTrail(ctx: CanvasRenderingContext2D, now: number, idle: boolean): void {
    if (idle || this.trail.length < 2) return;
    for (let i = 1; i < this.trail.length; i += 1) {
      const a = this.trail[i - 1];
      const b = this.trail[i];
      const age = (now - b.t) / TRAIL_MS;
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
    grabbed: boolean,
    scale: number
  ): void {
    const anchors = netAnchors(rect);
    const closeness = 1 - Math.min(1, distance / this.sense);
    // Distant webs stay faint; the pull only becomes loud inside the reach.
    const pull = grabbed ? 1 : 0.1 + Math.pow(closeness, 2.2) * 0.72;
    const strandAlpha = (0.14 + pull * 0.62) * scale;
    const core: Point = { x: this.ox, y: this.oy };
    const live = scale > 0.99;

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
    ctx.shadowColor = rgba(ACID, (grabbed ? 0.55 : 0.22) * scale);
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
      ctx.strokeStyle = rgba(HOT, (0.24 + pull * 0.66) * scale);
      ctx.lineWidth = 1.1;
      ctx.stroke();

      if (grabbed && live) {
        const phase = (now * 0.0016 + index / anchors.length) % 1;
        const px =
          (1 - phase) * (1 - phase) * core.x +
          2 * (1 - phase) * phase * ctrlX +
          phase * phase * point.x;
        const py =
          (1 - phase) * (1 - phase) * core.y +
          2 * (1 - phase) * phase * ctrlY +
          phase * phase * point.y;
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

  /** Nets that outlived their element fade instead of blinking out. */
  private drawMelts(ctx: CanvasRenderingContext2D, now: number): void {
    this.melts = this.melts.filter((melt) => now - melt.start < MELT_MS);
    for (const melt of this.melts) {
      const age = (now - melt.start) / MELT_MS;
      const rect = melt.rect;
      const sx = melt.x;
      const sy = melt.y;
      const anchors = netAnchors(rect);
      ctx.beginPath();
      anchors.forEach((point, index) => {
        const next = anchors[(index + 1) % anchors.length];
        ctx.moveTo(point.x, point.y);
        ctx.lineTo(next.x, next.y);
      });
      ctx.strokeStyle = rgba(ACID, (1 - age) * 0.28);
      ctx.lineWidth = 0.7;
      ctx.stroke();
      ctx.beginPath();
      for (const point of anchors) {
        ctx.moveTo(sx, sy);
        ctx.lineTo(point.x, point.y);
      }
      ctx.strokeStyle = rgba(ACID, (1 - age) * 0.2);
      ctx.lineWidth = 0.7;
      ctx.stroke();
      // The strands retract toward the reticle as they die.
      const shrink = 1 - age * 0.35;
      ctx.beginPath();
      ctx.arc(sx, sy, 3 + shrink * 2, 0, TAU);
      ctx.strokeStyle = rgba(HOT, (1 - age) * 0.35);
      ctx.lineWidth = 0.8;
      ctx.stroke();
    }
  }

  /** A short ripple when a new element is grabbed: the lunge, made visible. */
  private drawRipples(ctx: CanvasRenderingContext2D, now: number): void {
    this.ripples = this.ripples.filter((ripple) => now - ripple.start < GRAB_RIPPLE_MS);
    for (const ripple of this.ripples) {
      const age = (now - ripple.start) / GRAB_RIPPLE_MS;
      const grow = 2 + age * 10;
      const rect = ripple.rect;
      roundRectPath(
        ctx,
        rect.left - grow,
        rect.top - grow,
        rect.width + grow * 2,
        rect.height + grow * 2,
        9
      );
      ctx.strokeStyle = rgba(ACID, (1 - age) * 0.5);
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  }

  private isTextLike(el: HTMLElement): boolean {
    const tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
  }

  /**
   * Keyboard focus gets its own cast, so tabbing through the shell feels like
   * the net is finding each control for you. It never fights the pointer: a
   * press retires it, and text fields are left alone.
   */
  private drawFocus(ctx: CanvasRenderingContext2D, now: number): void {
    const el = this.focused;
    if (!this.keyboard || !el || !el.isConnected || el === this.caught) return;
    if (this.isTextLike(el)) return;
    const rect = el.getBoundingClientRect();
    if (rect.width < 6 || rect.height < 6) return;

    const age = (now - this.focusAt) / FOCUS_MS;
    const settling = age < 1 ? age : 1;
    const strength = 0.6 + (1 - settling) * 0.4;
    const anchors = netAnchors(rect);
    const cx = (rect.left + rect.right) / 2;
    const cy = (rect.top + rect.bottom) / 2;
    const grow = (1 - settling) * 9;

    ctx.beginPath();
    anchors.forEach((point, index) => {
      const next = anchors[(index + 1) % anchors.length];
      ctx.moveTo(point.x, point.y);
      ctx.lineTo(next.x, next.y);
    });
    ctx.strokeStyle = rgba(ACID, (0.16 + (1 - settling) * 0.18) * strength);
    ctx.lineWidth = 0.8;
    ctx.stroke();

    anchors.forEach((point, index) => {
      const outX = point.x + Math.sign(point.x - cx) * grow;
      const outY = point.y + Math.sign(point.y - cy) * grow;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(outX, outY);
      ctx.strokeStyle = rgba(index % 2 ? HOT : ACID, 0.1 * strength);
      ctx.lineWidth = 0.7;
      ctx.stroke();
      const tick = 2.6;
      ctx.beginPath();
      ctx.moveTo(point.x - tick, point.y);
      ctx.lineTo(point.x + tick, point.y);
      ctx.moveTo(point.x, point.y - tick);
      ctx.lineTo(point.x, point.y + tick);
      ctx.strokeStyle = rgba(HOT, 0.26 * strength);
      ctx.lineWidth = 1;
      ctx.stroke();
    });
  }

  private drawBursts(ctx: CanvasRenderingContext2D, now: number): void {
    this.bursts = this.bursts.filter((burst) => now - burst.start < BURST_MS);
    for (const burst of this.bursts) {
      const age = (now - burst.start) / BURST_MS;
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
        ctx.moveTo(
          burst.x + Math.cos(angle) * radius * 0.3,
          burst.y + Math.sin(angle) * radius * 0.3
        );
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
    ctx.translate(this.ox, this.oy);
    ctx.rotate(now * (grabbed ? 0.0016 : 0.0009));
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
    ctx.arc(this.ox, this.oy, grabbed ? 5.4 : 7.6, 0, TAU);
    ctx.strokeStyle = rgba(ACID, 0.34 * breathe);
    ctx.lineWidth = 0.8;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(this.ox, this.oy, 2.1, 0, TAU);
    ctx.fillStyle = rgba(VIOLET, 0.95);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(this.ox, this.oy, 1.1, 0, TAU);
    ctx.fillStyle = rgba(HOT, 0.95);
    ctx.fill();
  }
}
