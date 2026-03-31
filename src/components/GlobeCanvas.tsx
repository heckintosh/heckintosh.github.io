import { useEffect, useRef } from "react";

const LOCATIONS = [
  { name: "Vietnam",   lon: 108, lat: 14  },
  { name: "Australia", lon: 134, lat: -27 },
  { name: "Taiwan",    lon: 121, lat: 24  },
];

function project(
  lon: number, lat: number,
  cLon: number, cLat: number,
  r: number, cx: number, cy: number,
) {
  const λ  = (lon  * Math.PI) / 180;
  const φ  = (lat  * Math.PI) / 180;
  const λ0 = (cLon * Math.PI) / 180;
  const φ0 = (cLat * Math.PI) / 180;
  const cosc =
    Math.sin(φ0) * Math.sin(φ) +
    Math.cos(φ0) * Math.cos(φ) * Math.cos(λ - λ0);
  return {
    x: cx + r * Math.cos(φ) * Math.sin(λ - λ0),
    y: cy - r * (Math.cos(φ0) * Math.sin(φ) - Math.sin(φ0) * Math.cos(φ) * Math.cos(λ - λ0)),
    visible: cosc > 0,
  };
}

export default function GlobeCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Size canvas to its CSS container
    const dpr  = window.devicePixelRatio || 1;
    const size = Math.min(
      canvas.parentElement?.clientWidth  ?? 160,
      canvas.parentElement?.clientHeight ?? 160,
    );
    canvas.width  = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width  = `${size}px`;
    canvas.style.height = `${size}px`;
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const r  = size * 0.42;

    // View state
    let cLon = 115; // start Asia-Pacific centered
    let cLat = -5;

    // Drag state
    let dragging = false;
    let dragStartX = 0, dragStartY = 0;
    let dragLon = cLon, dragLat = cLat;

    let running = true;
    let rafId   = 0;

    function draw(now: number) {
      if (!running) return;
      if (!dragging) cLon = 115 + now * 0.004; // slow east-to-west rotation

      ctx.clearRect(0, 0, size, size);

      // Globe fill
      const bg = ctx.createRadialGradient(cx - r * 0.25, cy - r * 0.25, 0, cx, cy, r);
      bg.addColorStop(0, "#16162a");
      bg.addColorStop(1, "#0a0a14");
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.fillStyle = bg;
      ctx.fill();

      // Globe rim
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(250,204,21,0.15)";
      ctx.lineWidth = 0.8;
      ctx.stroke();

      // Grid lines
      ctx.strokeStyle = "rgba(255,255,255,0.045)";
      ctx.lineWidth   = 0.5;

      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let gap = true;
        for (let lon = -180; lon <= 181; lon += 3) {
          const p = project(lon, lat, cLon, cLat, r, cx, cy);
          if (p.visible) { gap ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y); gap = false; }
          else gap = true;
        }
        ctx.stroke();
      }
      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let gap = true;
        for (let lat = -90; lat <= 90; lat += 3) {
          const p = project(lon, lat, cLon, cLat, r, cx, cy);
          if (p.visible) { gap ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y); gap = false; }
          else gap = true;
        }
        ctx.stroke();
      }

      // Location markers
      for (const loc of LOCATIONS) {
        const p = project(loc.lon, loc.lat, cLon, cLat, r, cx, cy);
        if (!p.visible) continue;

        // Glow halo
        const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 16);
        glow.addColorStop(0, "rgba(250,204,21,0.35)");
        glow.addColorStop(1, "rgba(250,204,21,0)");
        ctx.beginPath();
        ctx.arc(p.x, p.y, 16, 0, Math.PI * 2);
        ctx.fillStyle = glow;
        ctx.fill();

        // Dot
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = "#facc15";
        ctx.fill();

        // Label
        ctx.font      = "8px 'JetBrains Mono', monospace";
        ctx.fillStyle = "rgba(250,204,21,0.9)";
        ctx.fillText(loc.name, p.x + 5, p.y - 3);
      }

      rafId = requestAnimationFrame(draw);
    }

    // Drag to rotate
    function onDown(e: PointerEvent) {
      dragging = true;
      canvas!.setPointerCapture(e.pointerId);
      dragStartX = e.clientX;
      dragStartY = e.clientY;
      dragLon    = cLon;
      dragLat    = cLat;
    }
    function onPointerMove(e: PointerEvent) {
      if (!dragging) return;
      cLon = dragLon - (e.clientX - dragStartX) * 0.4;
      cLat = Math.max(-60, Math.min(60, dragLat + (e.clientY - dragStartY) * 0.3));
    }
    function onUp() { dragging = false; }

    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onPointerMove);
    canvas.addEventListener("pointerup",   onUp);
    canvas.addEventListener("pointerout",  onUp);

    rafId = requestAnimationFrame(draw);

    return () => {
      running = false;
      cancelAnimationFrame(rafId);
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onPointerMove);
      canvas.removeEventListener("pointerup",   onUp);
      canvas.removeEventListener("pointerout",  onUp);
    };
  }, []);

  return <canvas ref={canvasRef} className="globe-canvas" />;
}
