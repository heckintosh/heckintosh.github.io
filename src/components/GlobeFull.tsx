import { useEffect, useRef } from "react";
import * as d3 from "d3";
// @ts-ignore
import worldData from "../lib/world.json";

const VISITED = ["Vietnam", "Australia"];

export default function GlobeFull() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const dpr    = window.devicePixelRatio || 1;
    const W      = canvas.parentElement!.clientWidth  || window.innerWidth  || 800;
    const H      = Math.min(window.innerHeight * 0.72, 560);
    const radius = Math.min(W, H) * 0.42;

    canvas.width        = W   * dpr;
    canvas.height       = H   * dpr;
    canvas.style.width  = `${W}px`;
    canvas.style.height = `${H}px`;

    const ctx = canvas.getContext("2d")!;
    ctx.scale(dpr, dpr);

    const projection = d3
      .geoOrthographic()
      .scale(radius)
      .translate([W / 2, H / 2])
      .rotate([0, -20])
      .clipAngle(90);

    const path = d3.geoPath().projection(projection).context(ctx);
    const graticule = d3.geoGraticule()();

    let rotate   = 0;
    let dragging = false;
    let lastX    = 0;
    let lastY    = 0;
    let running  = true;
    let rafId    = 0;

    function draw() {
      ctx.clearRect(0, 0, W, H);

      // Ocean sphere
      ctx.beginPath();
      ctx.arc(W / 2, H / 2, radius, 0, Math.PI * 2);
      ctx.fillStyle = "#1a3a5c";
      ctx.fill();

      // Graticule
      ctx.beginPath();
      path(graticule as any);
      ctx.strokeStyle = "rgba(255,255,255,0.07)";
      ctx.lineWidth = 0.5;
      ctx.stroke();

      // Countries
      for (const feature of (worldData as any).features) {
        const isVisited = VISITED.includes(feature.properties?.name);
        ctx.beginPath();
        path(feature);
        ctx.fillStyle   = isVisited ? "rgba(250,204,21,0.85)" : "rgba(45,106,79,0.9)";
        ctx.strokeStyle = isVisited ? "rgba(250,204,21,0.9)"  : "rgba(255,255,255,0.15)";
        ctx.lineWidth   = isVisited ? 1 : 0.3;
        ctx.fill();
        ctx.stroke();
      }

      // Atmosphere rim
      const atmos = ctx.createRadialGradient(W/2, H/2, radius * 0.96, W/2, H/2, radius * 1.06);
      atmos.addColorStop(0, "rgba(100,160,255,0)");
      atmos.addColorStop(1, "rgba(100,160,255,0.22)");
      ctx.beginPath();
      ctx.arc(W / 2, H / 2, radius * 1.06, 0, Math.PI * 2);
      ctx.fillStyle = atmos;
      ctx.fill();
    }

    function frame() {
      if (!running) return;
      if (!dragging) {
        rotate += 0.15;
        const r = projection.rotate() as [number, number];
        projection.rotate([r[0] + 0.15, r[1]]);
      }
      draw();
      rafId = requestAnimationFrame(frame);
    }

    function onDown(e: PointerEvent) {
      dragging = true;
      lastX    = e.clientX;
      lastY    = e.clientY;
      canvas.setPointerCapture(e.pointerId);
      canvas.style.cursor = "grabbing";
    }

    function onMove(e: PointerEvent) {
      if (!dragging) return;
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      lastX    = e.clientX;
      lastY    = e.clientY;
      const r  = projection.rotate() as [number, number];
      projection.rotate([
        r[0] + dx * 0.4,
        Math.max(-70, Math.min(70, r[1] - dy * 0.4)),
      ]);
    }

    function onUp() {
      dragging            = false;
      canvas.style.cursor = "grab";
    }

    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup",   onUp);
    canvas.addEventListener("pointercancel", onUp);

    rafId = requestAnimationFrame(frame);

    return () => {
      running = false;
      cancelAnimationFrame(rafId);
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerup",   onUp);
      canvas.removeEventListener("pointercancel", onUp);
    };
  }, []);

  return (
    <div style={{ width: "100%", display: "flex", justifyContent: "center" }}>
      <canvas ref={canvasRef} />
    </div>
  );
}
