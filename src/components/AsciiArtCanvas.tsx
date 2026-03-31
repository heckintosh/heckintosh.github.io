/**
 * Particle-driven ASCII art animation using @chenglou/pretext.
 *
 * How pretext is used here (matching the variable-typographic-ascii demo):
 *   prepareWithSegments('M', font) → prepared.widths[0]
 *   measures the exact monospace cell advance width via the browser font engine,
 *   so the canvas is sized to the pixel regardless of system DPI or font-size scaling.
 *
 *   The same width measurement is used to build the character brightness palette:
 *   each character in the charset is rendered to a small offscreen canvas, its
 *   alpha-channel sum gives ink coverage (brightness), and prepareWithSegments
 *   could measure proportional widths if we ever switch to a variable-width font.
 *
 * Physics: 80 particles attracted to two orbiting points accumulate into a
 * brightness field (oversampled 2×). Each text cell samples its 2×2 field block
 * and maps the average brightness to the closest character in the sorted palette.
 * A single fillText per row keeps the render budget low.
 */

import { useEffect, useRef } from "react";
import { prepareWithSegments } from "@chenglou/pretext";

type MousePos = { x: number; y: number };

// ── Grid & font ───────────────────────────────────────────────────────────────
const COLS = 55;
const ROWS = 28;
const FONT_SIZE = 6; // rendered at 6 px; CSS transform scales for each viewport
const LINE_HEIGHT = FONT_SIZE;
const FONT_FAMILY = '"JetBrains Mono", monospace';
const FONT = `${FONT_SIZE}px ${FONT_FAMILY}`;

// ── Particle physics ──────────────────────────────────────────────────────────
const PARTICLE_N = 90;
const SPRITE_R = 9; // canvas-px influence radius per particle
const LARGE_ATT_R = 18; // primary attractor
const SMALL_ATT_R = 7; // secondary attractor
const FORCE_1 = 0.22;
const FORCE_2 = 0.05;
const FIELD_DECAY = 0.82;
const FIELD_OS = 2; // brightness field oversample factor

// ASCII brightness ramp — sparse → dense (measured empirically for JetBrains Mono)
const CHARSET = " .,:;!|+=*#@%";

type Particle = { x: number; y: number; vx: number; vy: number };
type Stamp = {
  rx: number;
  ry: number;
  sw: number;
  sh: number;
  values: Float32Array;
};

/** Pre-compute a radial influence stamp for a given radius. */
function makeStamp(rPx: number, fsx: number, fsy: number): Stamp {
  const rx = Math.ceil(rPx * fsx);
  const ry = Math.ceil(rPx * fsy);
  const sw = rx * 2 + 1;
  const sh = ry * 2 + 1;
  const values = new Float32Array(sw * sh);
  for (let y = -ry; y <= ry; y++) {
    for (let x = -rx; x <= rx; x++) {
      const nd = Math.sqrt((x / (rx || 1)) ** 2 + (y / (ry || 1)) ** 2);
      let v = 0;
      if (nd <= 0.35) v = 0.45 + (0.15 - 0.45) * (nd / 0.35);
      else if (nd < 1) v = 0.15 * (1 - (nd - 0.35) / 0.65);
      values[(y + ry) * sw + x + rx] = v;
    }
  }
  return { rx, ry, sw, sh, values };
}

export default function AsciiArtCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mouseRef = useRef<MousePos | null>(null);

  useEffect(() => {
    let running = true;
    let rafId = 0;
    let removeListeners: (() => void) | null = null;

    async function start() {
      // Wait for JetBrains Mono to be available before measuring
      await document.fonts.ready;
      if (!running) return;

      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      // ── 1. Measure monospace cell width via pretext ───────────────────────
      // prepareWithSegments calls the browser's font engine for precise metrics.
      // For a monospace font every glyph shares the same advance, so 'M' suffices.
      const probe = prepareWithSegments("M", FONT);
      const charW = probe.widths[0] ?? FONT_SIZE * 0.601;

      const canvasW = COLS * charW;
      const canvasH = ROWS * LINE_HEIGHT;
      canvas.width = Math.ceil(canvasW);
      canvas.height = Math.ceil(canvasH);

      const fieldCols = COLS * FIELD_OS;
      const fieldRows = ROWS * FIELD_OS;
      const fsx = fieldCols / canvasW;
      const fsy = fieldRows / canvasH;

      // ── 2. Build brightness palette ───────────────────────────────────────
      // Render each charset character to a 28×28 canvas and sum alpha pixels.
      const bCv = document.createElement("canvas");
      bCv.width = bCv.height = 28;
      const bCtx = bCv.getContext("2d", { willReadFrequently: true })!;
      bCtx.font = `28px ${FONT_FAMILY}`;
      bCtx.fillStyle = "#fff";
      bCtx.textBaseline = "middle";

      const palette = Array.from(CHARSET).map((ch) => {
        bCtx.clearRect(0, 0, 28, 28);
        bCtx.fillText(ch, 1, 14);
        const d = bCtx.getImageData(0, 0, 28, 28).data;
        let sum = 0;
        for (let i = 3; i < d.length; i += 4) sum += d[i]!;
        return { ch, b: sum / (255 * 28 * 28) };
      });

      const maxB = Math.max(...palette.map((e) => e.b));
      if (maxB > 0) palette.forEach((e) => (e.b /= maxB));
      palette.sort((a, z) => a.b - z.b);

      // 256-entry lookup: brightness byte → nearest palette character
      const lookup: string[] = new Array(256);
      for (let i = 0; i < 256; i++) {
        const t = i / 255;
        let best = palette[0]!;
        let bestD = Math.abs(best.b - t);
        for (const e of palette) {
          const d = Math.abs(e.b - t);
          if (d < bestD) {
            bestD = d;
            best = e;
          }
        }
        lookup[i] = best.ch;
      }

      // ── 3. Particles & field stamps ───────────────────────────────────────
      const pStamp = makeStamp(SPRITE_R, fsx, fsy);
      const laStamp = makeStamp(LARGE_ATT_R, fsx, fsy);
      const saStamp = makeStamp(SMALL_ATT_R, fsx, fsy);

      const particles: Particle[] = Array.from({ length: PARTICLE_N }, () => ({
        x: Math.random() * canvasW,
        y: Math.random() * canvasH,
        vx: 0,
        vy: 0,
      }));

      const field = new Float32Array(fieldCols * fieldRows);

      // ── Mouse / touch tracking (document-level, canvas stays pointer-events:none) ──
      function getCanvasPos(clientX: number, clientY: number): MousePos {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        return {
          x: (clientX - rect.left) * scaleX,
          y: (clientY - rect.top) * scaleY,
        };
      }
      function onMouseMove(e: MouseEvent) { mouseRef.current = getCanvasPos(e.clientX, e.clientY); }
      function onMouseLeave() { mouseRef.current = null; }
      function onTouchMove(e: TouchEvent) {
        const t = e.touches[0];
        if (t) mouseRef.current = getCanvasPos(t.clientX, t.clientY);
      }
      function onTouchEnd() { mouseRef.current = null; }
      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseleave", onMouseLeave);
      document.addEventListener("touchmove", onTouchMove, { passive: true });
      document.addEventListener("touchend", onTouchEnd);
      removeListeners = () => {
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseleave", onMouseLeave);
        document.removeEventListener("touchmove", onTouchMove);
        document.removeEventListener("touchend", onTouchEnd);
      };

      function splat(cx: number, cy: number, stamp: Stamp) {
        const gcx = Math.round(cx * fsx);
        const gcy = Math.round(cy * fsy);
        for (let dy = -stamp.ry; dy <= stamp.ry; dy++) {
          const gy = gcy + dy;
          if (gy < 0 || gy >= fieldRows) continue;
          const rOff = gy * fieldCols;
          const sOff = (dy + stamp.ry) * stamp.sw;
          for (let dx = -stamp.rx; dx <= stamp.rx; dx++) {
            const gx = gcx + dx;
            if (gx < 0 || gx >= fieldCols) continue;
            const v = stamp.values[sOff + dx + stamp.rx]!;
            if (!v) continue;
            const fi = rOff + gx;
            field[fi] = Math.min(1, field[fi]! + v);
          }
        }
      }

      // ── 4. Animation loop ─────────────────────────────────────────────────
      function render(now: number) {
        if (!running) return;

        // Two attractors orbit on offset Lissajous paths
        const a1x = Math.cos(now * 0.0007) * canvasW * 0.25 + canvasW / 2;
        const a1y = Math.sin(now * 0.0011) * canvasH * 0.3 + canvasH / 2;
        const a2x =
          Math.cos(now * 0.0013 + Math.PI) * canvasW * 0.2 + canvasW / 2;
        const a2y =
          Math.sin(now * 0.0009 + Math.PI) * canvasH * 0.25 + canvasH / 2;

        // Mouse attractor (mapped through CSS scale via getBoundingClientRect)
        const mouse = mouseRef.current;
        const mx = mouse !== null ? Math.max(0, Math.min(canvasW, mouse.x)) : null;
        const my = mouse !== null ? Math.max(0, Math.min(canvasH, mouse.y)) : null;

        // Update particle physics
        for (const p of particles) {
          const d1x = a1x - p.x,
            d1y = a1y - p.y;
          const d2x = a2x - p.x,
            d2y = a2y - p.y;
          const sq1 = d1x * d1x + d1y * d1y;
          const sq2 = d2x * d2x + d2y * d2y;
          const c1 = sq1 < sq2;
          const ax = c1 ? d1x : d2x;
          const ay = c1 ? d1y : d2y;
          const dist = Math.sqrt(c1 ? sq1 : sq2) + 1;
          const force = c1 ? FORCE_1 : FORCE_2;
          p.vx += (ax / dist) * force + (Math.random() - 0.5) * 0.25;
          p.vy += (ay / dist) * force + (Math.random() - 0.5) * 0.25;
          // Pull toward mouse cursor (stronger than auto-orbit attractors)
          if (mx !== null && my !== null) {
            const dmx = mx - p.x, dmy = my - p.y;
            const md = Math.sqrt(dmx * dmx + dmy * dmy) + 1;
            p.vx += (dmx / md) * 0.45;
            p.vy += (dmy / md) * 0.45;
          }
          p.vx *= 0.97;
          p.vy *= 0.97;
          p.x += p.vx;
          p.y += p.vy;
          // Wrap at edges
          if (p.x < -SPRITE_R) p.x += canvasW + SPRITE_R * 2;
          if (p.x > canvasW + SPRITE_R) p.x -= canvasW + SPRITE_R * 2;
          if (p.y < -SPRITE_R) p.y += canvasH + SPRITE_R * 2;
          if (p.y > canvasH + SPRITE_R) p.y -= canvasH + SPRITE_R * 2;
        }

        // Decay field and accumulate particle contributions
        for (let i = 0; i < field.length; i++) field[i]! *= FIELD_DECAY;
        for (const p of particles) splat(p.x, p.y, pStamp);
        splat(a1x, a1y, laStamp);
        splat(a2x, a2y, saStamp);
        // Extra bright stamp at cursor so characters cluster visibly there
        if (mx !== null && my !== null) splat(mx, my, laStamp);

        // Draw: one fillText per row (monospace → all chars same advance width)
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.font = FONT;
        ctx.fillStyle = "#facc15"; // yellow-400
        ctx.globalAlpha = 0.65;
        ctx.textBaseline = "top";

        for (let row = 0; row < ROWS; row++) {
          let rowStr = "";
          const baseRow = row * FIELD_OS * fieldCols;
          for (let col = 0; col < COLS; col++) {
            const baseCol = col * FIELD_OS;
            let b = 0;
            for (let sy = 0; sy < FIELD_OS; sy++)
              for (let sx = 0; sx < FIELD_OS; sx++)
                b += field[baseRow + sy * fieldCols + baseCol + sx]!;
            b /= FIELD_OS * FIELD_OS;
            rowStr += lookup[Math.min(255, (b * 255) | 0)]!;
          }
          ctx.fillText(rowStr, 0, row * LINE_HEIGHT);
        }

        rafId = requestAnimationFrame(render);
      }

      rafId = requestAnimationFrame(render);
    }

    start().catch(console.error);
    return () => {
      running = false;
      cancelAnimationFrame(rafId);
      mouseRef.current = null;
      removeListeners?.();
    };
  }, []);

  return <canvas ref={canvasRef} className="ascii-art" />;
}
