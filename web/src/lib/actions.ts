/** Count a number up from zero (or animate between values) when the node mounts. */
export function countup(node: HTMLElement, value: number) {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let raf = 0;
  let from = 0;
  let current = 0;

  const paint = (v: number) => {
    node.textContent = String(Math.round(v));
  };

  const run = (to: number) => {
    cancelAnimationFrame(raf);
    if (to !== current && !reduced) {
      node.classList.remove('bump');
      void node.offsetWidth;
      node.classList.add('bump');
    }
    if (reduced || from === to) {
      current = to;
      from = to;
      paint(to);
      return;
    }
    const start = performance.now();
    const dur = 750;
    const step = (t: number) => {
      const p = Math.min(1, (t - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      paint(from + (to - from) * eased);
      if (p < 1) {
        raf = requestAnimationFrame(step);
      } else {
        current = to;
        from = to;
      }
    };
    raf = requestAnimationFrame(step);
  };

  run(value);

  return {
    update(next: number) {
      from = current;
      run(next);
    },
    destroy() {
      cancelAnimationFrame(raf);
    }
  };
}

/** A soft light that follows the pointer across a panel's face. */
export function spotlight(node: HTMLElement) {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (getComputedStyle(node).position === 'static') node.style.position = 'relative';
  const spot = document.createElement('i');
  spot.className = 'spot';
  spot.setAttribute('aria-hidden', 'true');
  node.appendChild(spot);

  let raf = 0;
  let queued = false;

  const paint = (event: PointerEvent) => {
    queued = false;
    const rect = node.getBoundingClientRect();
    spot.style.setProperty('--sx', `${event.clientX - rect.left}px`);
    spot.style.setProperty('--sy', `${event.clientY - rect.top}px`);
  };

  const onMove = (event: PointerEvent) => {
    spot.classList.add('on');
    if (!queued) {
      queued = true;
      raf = requestAnimationFrame(() => paint(event));
    }
  };

  const onLeave = () => {
    spot.classList.remove('on');
  };

  node.addEventListener('pointermove', onMove, { passive: true });
  node.addEventListener('pointerleave', onLeave);
  return {
    destroy() {
      cancelAnimationFrame(raf);
      node.removeEventListener('pointermove', onMove);
      node.removeEventListener('pointerleave', onLeave);
      spot.remove();
    }
  };
}

/** Park every animation inside the node while it is scrolled out of view. */
export function pauseOffscreen(node: HTMLElement) {
  if (!('IntersectionObserver' in window)) return;
  const io = new IntersectionObserver(
    (entries) => {
      node.classList.toggle('parked', !entries[0]?.isIntersecting);
    },
    { rootMargin: '80px' }
  );
  io.observe(node);
  return {
    destroy() {
      io.disconnect();
    }
  };
}
