<script lang="ts">
  const lattice =
    "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cpath d='M0 0L140 140M140 0L0 140M70 0v140M0 70h140' fill='none' stroke='%239F23DD' stroke-width='1' opacity='0.6'/%3E%3Ccircle cx='70' cy='70' r='2' fill='%23C8F81A' opacity='0.5'/%3E%3C/svg%3E\")";

  const noise =
    "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='0.4'/%3E%3C/svg%3E\")";

  // A handful of sparks rising off the water -- transform/opacity only.
  const embers = Array.from({ length: 16 }, (_, i) => ({
    left: (i * 6.4 + ((i * 37) % 9)).toFixed(1),
    size: i % 4 === 0 ? 4 : 3,
    violet: i % 3 === 0,
    dur: 14 + ((i * 13) % 17),
    delay: (i * 2.3) % 21
  }));
</script>

<!-- Ambient stage: glows, grid, a drifting net lattice, a slow scan sweep, grain. -->
<div class="pointer-events-none fixed inset-0 -z-10 overflow-hidden" aria-hidden="true">
  <div
    class="absolute inset-0"
    style="background:
      radial-gradient(44rem 32rem at 6% -10%, rgba(200, 248, 26, 0.07), transparent 70%),
      radial-gradient(50rem 38rem at 104% 106%, rgba(159, 35, 221, 0.12), transparent 68%),
      radial-gradient(36rem 28rem at 94% -8%, rgba(159, 35, 221, 0.06), transparent 70%);"
  ></div>

  <div
    class="absolute inset-0 opacity-60"
    style="background-image:
      linear-gradient(rgba(40, 21, 80, 0.4) 1px, transparent 1px),
      linear-gradient(90deg, rgba(40, 21, 80, 0.4) 1px, transparent 1px);
      background-size: 46px 46px;
      mask-image: radial-gradient(130% 110% at 50% 0%, black 34%, transparent 92%);"
  ></div>

  <div
    class="absolute -inset-x-1/4 inset-y-[-12%] opacity-[0.05]"
    style="background-image:{lattice}; background-size:140px 140px; animation:drift-x 120s linear infinite;"
  ></div>

  <div
    class="absolute -inset-y-1/4 inset-x-[-14%] opacity-[0.04]"
    style="background-image:{lattice}; background-size:210px 210px; animation:drift-x 180s linear infinite reverse;"
  ></div>

  <div
    class="absolute inset-x-0 top-0 h-[46vh]"
    style="background:linear-gradient(180deg, transparent 0%, rgba(200,248,26,0.035) 38%, rgba(200,248,26,0.11) 56%, rgba(200,248,26,0.035) 76%, transparent 100%);
      animation:scan-down 15s linear infinite;"
  ></div>

  <div class="absolute inset-0 opacity-40" style="background-image:{noise}; mix-blend-mode:soft-light;"></div>

  <!-- rising sparks -->
  <div class="absolute inset-0 overflow-hidden">
    {#each embers as e (e.left + ':' + e.delay)}
      <span
        class="ember {e.violet ? 'e-violet' : ''}"
        style="left:{e.left}%; width:{e.size}px; height:{e.size}px;
               background:{e.violet ? 'var(--nc-violet)' : 'var(--nc-acid)'};
               box-shadow:0 0 {e.size * 2}px {e.violet ? 'rgba(159,35,221,0.55)' : 'rgba(200,248,26,0.5)'};
               animation-duration:{e.dur}s; animation-delay:-{e.delay}s;"
      ></span>
    {/each}
  </div>

  <!-- the CRT the whole product lives inside -->
  <div class="scanlines absolute inset-0" aria-hidden="true"></div>

  <div class="absolute inset-y-6 right-4 hidden flex-col justify-between 2xl:flex">
    <span
      class="mono text-[10px] tracking-[0.4em] text-slate"
      style="writing-mode:vertical-rl">NETCAST3R // BUG BOUNTY AUTOMATION</span
    >
    <span class="mono text-[10px] tracking-[0.4em] text-slate" style="writing-mode:vertical-rl"
      >AUTHORIZED TESTING ONLY</span
    >
  </div>
</div>
