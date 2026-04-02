import { useEffect, useRef } from "react";
import * as d3 from "d3";
// @ts-ignore
import worldData from "../lib/world.json";

const VISITED = ["Vietnam", "Australia", "Taiwan"];

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
      const ocean = ctx.createRadialGradient(
        W / 2 - radius * 0.35,
        H / 2 - radius * 0.35,
        radius * 0.15,
        W / 2,
        H / 2,
        radius * 1.05,
      );
      ocean.addColorStop(0, "#4d7db5");
      ocean.addColorStop(0.45, "#1f4f84");
      ocean.addColorStop(1, "#12273f");
      ctx.fillStyle = ocean;
      ctx.fill();

      // Graticule
      ctx.beginPath();
      path(graticule as any);
      ctx.strokeStyle = "rgba(255,255,255,0.09)";
      ctx.lineWidth = 0.5;
      ctx.stroke();

      // Countries
      for (const feature of (worldData as any).features) {
        const isVisited = VISITED.includes(feature.properties?.name);
        ctx.beginPath();
        path(feature);
        ctx.fillStyle   = isVisited ? "rgba(248,209,82,0.94)" : "rgba(38,86,120,0.8)";
        ctx.strokeStyle = isVisited ? "rgba(248,209,82,0.96)" : "rgba(255,255,255,0.2)";
        ctx.lineWidth   = isVisited ? 1.2 : 0.35;
        ctx.fill();
        ctx.stroke();
      }

      // Atmosphere rim
      const atmos = ctx.createRadialGradient(W/2, H/2, radius * 0.96, W/2, H/2, radius * 1.06);
      atmos.addColorStop(0, "rgba(100,160,255,0)");
      atmos.addColorStop(1, "rgba(120,178,255,0.26)");
      ctx.beginPath();
      ctx.arc(W / 2, H / 2, radius * 1.06, 0, Math.PI * 2);
      ctx.fillStyle = atmos;
      ctx.fill();

      // subtle specular highlight
      const spec = ctx.createRadialGradient(
        W / 2 - radius * 0.28,
        H / 2 - radius * 0.3,
        radius * 0.02,
        W / 2 - radius * 0.2,
        H / 2 - radius * 0.22,
        radius * 0.48,
      );
      spec.addColorStop(0, "rgba(255,255,255,0.24)");
      spec.addColorStop(1, "rgba(255,255,255,0)");
      ctx.beginPath();
      ctx.arc(W / 2, H / 2, radius, 0, Math.PI * 2);
      ctx.fillStyle = spec;
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

  return <canvas ref={canvasRef} />;
}
