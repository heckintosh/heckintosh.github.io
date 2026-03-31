import { useEffect, useRef, useState } from "react";

interface Particle {
  ch: string;
  hx: number; hy: number; // home
  x:  number; y:  number; // current
  vx: number; vy: number;
}

const FONT_SIZE = 7;
const LINE_H    = FONT_SIZE * 1.2;
const FONT      = `${FONT_SIZE}px 'JetBrains Mono', monospace`;
const SPRING    = 0.10;
const DAMP      = 0.72;
const REPEL_R   = 55;
const REPEL_F   = 5.5;

// Color lerp: slate-gray at rest → yellow when displaced
function charColor(disp: number): string {
  const t = Math.min(disp / 28, 1);
  const r = Math.round(148 + t * 102);  // 148→250
  const g = Math.round(163 + t *  41);  // 163→204
  const b = Math.round(184 - t * 163);  // 184→ 21
  return `rgb(${r},${g},${b})`;
}

export default function AsciiArtCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [text, setText] = useState("");

  useEffect(() => {
    const n = Math.floor(Math.random() * 9) + 1;
    fetch(`/ascii-art-${n}.txt`).then(r => r.text()).then(setText).catch(() => {});
  }, []);

  useEffect(() => {
    if (!text) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Measure char width on an offscreen canvas so we don't reset state mid-setup
    const mc  = document.createElement("canvas").getContext("2d")!;
    mc.font   = FONT;
    const charW = mc.measureText("M").width;

    // Build particle list
    const lines  = text.split("\n");
    const particles: Particle[] = [];
    let canvasW = 0, canvasH = 0;

    lines.forEach((line, row) => {
      const hy = row * LINE_H + FONT_SIZE;
      [...line].forEach((ch, col) => {
        if (ch === " ") return;
        const hx = col * charW;
        particles.push({ ch, hx, hy, x: hx, y: hy, vx: 0, vy: 0 });
        if (hx + charW > canvasW) canvasW = hx + charW;
      });
      if (hy > canvasH) canvasH = hy;
    });
    canvasH += FONT_SIZE;

    const dpr = window.devicePixelRatio || 1;
    canvas.width  = Math.ceil(canvasW * dpr);
    canvas.height = Math.ceil(canvasH * dpr);
    canvas.style.width  = `${canvasW}px`;
    canvas.style.height = `${canvasH}px`;
    ctx.scale(dpr, dpr);

    let mx = -9999, my = -9999;
    let running = true;
    let rafId   = 0;

    function frame() {
      if (!running) return;
      ctx.clearRect(0, 0, canvasW, canvasH);
      ctx.font = FONT;

      for (const p of particles) {
        const dx   = p.x - mx;
        const dy   = p.y - my;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < REPEL_R && dist > 0.5) {
          const strength = ((REPEL_R - dist) / REPEL_R) ** 2 * REPEL_F;
          p.vx += (dx / dist) * strength;
          p.vy += (dy / dist) * strength;
        }

        p.vx += (p.hx - p.x) * SPRING;
        p.vy += (p.hy - p.y) * SPRING;
        p.vx *= DAMP;
        p.vy *= DAMP;
        p.x  += p.vx;
        p.y  += p.vy;

        const disp = Math.sqrt((p.x - p.hx) ** 2 + (p.y - p.hy) ** 2);
        ctx.fillStyle = charColor(disp);
        ctx.fillText(p.ch, p.x, p.y);
      }

      rafId = requestAnimationFrame(frame);
    }

    function onMove(e: PointerEvent) {
      const rect = canvas.getBoundingClientRect();
      mx = e.clientX - rect.left;
      my = e.clientY - rect.top;
    }
    function onLeave() { mx = -9999; my = -9999; }

    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerleave", onLeave);
    rafId = requestAnimationFrame(frame);

    return () => {
      running = false;
      cancelAnimationFrame(rafId);
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerleave", onLeave);
    };
  }, [text]);

  return (
    <div className="ascii-art">
      <canvas ref={canvasRef} className="ascii-canvas" />
    </div>
  );
}
