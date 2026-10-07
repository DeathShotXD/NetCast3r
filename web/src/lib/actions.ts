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
