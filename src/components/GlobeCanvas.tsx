import { useEffect, useRef } from "react";
import * as d3 from "d3";
// @ts-ignore
import worldData from "../lib/world.json";

const VISITED = ["Vietnam", "Australia"];

export default function GlobeCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const dpr    = window.devicePixelRatio || 1;
    const parent = canvas.parentElement!;
    const rect   = parent.getBoundingClientRect();
    const pw     = rect.width  || parent.clientWidth  || 160;
    const ph     = rect.height || parent.clientHeight || pw;
    const size   = Math.max(Math.min(pw, ph) || 160, 60);

    canvas.width        = size * dpr;
    canvas.height       = size * dpr;
    canvas.style.width  = `${size}px`;
    canvas.style.height = `${size}px`;

    const ctx = canvas.getContext("2d")!;
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;

    const projection = d3
      .geoOrthographic()
      .scale(size * 0.46)
      .translate([cx, cy])
      .rotate([0, -20])
      .clipAngle(90);

    const path      = d3.geoPath().projection(projection).context(ctx);
    const graticule = d3.geoGraticule()();

    let running  = true;
    let rafId    = 0;
    let lastTime = 0;

    function draw(now: number) {
      if (!running) return;
      const delta = lastTime ? now - lastTime : 16;
      lastTime = now;

      const r = projection.rotate() as [number, number];
      projection.rotate([r[0] + delta * 0.018, r[1]]);

      ctx.clearRect(0, 0, size, size);

      // Ocean
      ctx.beginPath();
      ctx.arc(cx, cy, size * 0.46, 0, Math.PI * 2);
      ctx.fillStyle = "#1a3a5c";
      ctx.fill();

      // Graticule
      ctx.beginPath();
      path(graticule as any);
      ctx.strokeStyle = "rgba(255,255,255,0.07)";
      ctx.lineWidth   = 0.4;
      ctx.stroke();

      // Countries
      for (const feature of (worldData as any).features) {
        const visited = VISITED.includes(feature.properties?.name);
        ctx.beginPath();
        path(feature);
        ctx.fillStyle   = visited ? "rgba(250,204,21,0.9)" : "rgba(45,106,79,0.85)";
        ctx.strokeStyle = visited ? "rgba(250,204,21,1)"   : "rgba(255,255,255,0.12)";
        ctx.lineWidth   = visited ? 0.8 : 0.3;
        ctx.fill();
        ctx.stroke();
      }

      rafId = requestAnimationFrame(draw);
    }

    rafId = requestAnimationFrame(draw);

    return () => {
      running = false;
      cancelAnimationFrame(rafId);
    };
  }, []);

  return <canvas ref={canvasRef} className="globe-canvas" />;
}
