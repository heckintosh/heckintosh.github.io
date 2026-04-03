import { useEffect, useRef } from "react";
import * as d3 from "d3";
// @ts-ignore
import worldData from "../lib/world.json";

const VISITED = ["Vietnam", "Australia", "Taiwan"];

type Palette = {
  oceanStops: [number, string][];
  graticule: string;
  visitedFill: string;
  visitedStroke: string;
  countryFill: string;
  countryStroke: string;
  atmosEdge: string;
  specular: string;
};

const LIGHT_PALETTE: Palette = {
  oceanStops: [
    [0, "#5d8fca"],
    [0.5, "#24558d"],
    [1, "#132a44"],
  ],
  graticule: "rgba(255,255,255,0.10)",
  visitedFill: "rgba(249,213,93,0.96)",
  visitedStroke: "rgba(249,213,93,1)",
  countryFill: "rgba(43,96,136,0.84)",
  countryStroke: "rgba(255,255,255,0.22)",
  atmosEdge: "rgba(136,188,255,0.30)",
  specular: "rgba(255,255,255,0.26)",
};

const DARK_PALETTE: Palette = {
  oceanStops: [
    [0, "#3e6ea5"],
    [0.55, "#17395f"],
    [1, "#0b1726"],
  ],
  graticule: "rgba(255,255,255,0.12)",
  visitedFill: "rgba(255,216,102,0.96)",
  visitedStroke: "rgba(255,216,102,1)",
  countryFill: "rgba(64,114,158,0.78)",
  countryStroke: "rgba(255,255,255,0.20)",
  atmosEdge: "rgba(111,173,255,0.34)",
  specular: "rgba(255,255,255,0.20)",
};

export default function GlobeFull() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const dpr = Math.min(window.devicePixelRatio || 1, 1.3);
    const W = canvas.parentElement?.clientWidth || window.innerWidth || 800;
    const H = Math.min(window.innerHeight * 0.72, 560);
    const radius = Math.min(W, H) * 0.42;

    canvas.width = Math.ceil(W * dpr);
    canvas.height = Math.ceil(H * dpr);
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.scale(dpr, dpr);

    const projection = d3
      .geoOrthographic()
      .scale(radius)
      .translate([W / 2, H / 2])
      .rotate([0, -20])
      .clipAngle(90);

    const path = d3.geoPath().projection(projection).context(ctx);
    const graticule = d3.geoGraticule()();
    const features = (worldData as any).features as any[];

    const root = document.documentElement;
    let isDark = root.classList.contains("dark");
    let palette = isDark ? DARK_PALETTE : LIGHT_PALETTE;

    let ocean = ctx.createRadialGradient(0, 0, 0, 0, 0, 0);
    let atmos = ctx.createRadialGradient(0, 0, 0, 0, 0, 0);
    let spec = ctx.createRadialGradient(0, 0, 0, 0, 0, 0);

    const rebuildGradients = () => {
      palette = isDark ? DARK_PALETTE : LIGHT_PALETTE;

      ocean = ctx.createRadialGradient(
        W / 2 - radius * 0.35,
        H / 2 - radius * 0.35,
        radius * 0.15,
        W / 2,
        H / 2,
        radius * 1.05,
      );
      for (const [stop, color] of palette.oceanStops) ocean.addColorStop(stop, color);

      atmos = ctx.createRadialGradient(W / 2, H / 2, radius * 0.96, W / 2, H / 2, radius * 1.06);
      atmos.addColorStop(0, "rgba(100,160,255,0)");
      atmos.addColorStop(1, palette.atmosEdge);

      spec = ctx.createRadialGradient(
        W / 2 - radius * 0.28,
        H / 2 - radius * 0.3,
        radius * 0.02,
        W / 2 - radius * 0.2,
        H / 2 - radius * 0.22,
        radius * 0.48,
      );
      spec.addColorStop(0, palette.specular);
      spec.addColorStop(1, "rgba(255,255,255,0)");
    };

    rebuildGradients();

    const observer = new MutationObserver(() => {
      const nextDark = root.classList.contains("dark");
      if (nextDark !== isDark) {
        isDark = nextDark;
        rebuildGradients();
      }
    });
    observer.observe(root, { attributes: true, attributeFilter: ["class"] });

    let dragging = false;
    let lastX = 0;
    let lastY = 0;
    let running = true;
    let rafId = 0;
    let lastFrameTs = 0;
    const FRAME_MS = 1000 / 28;

    function draw() {
      ctx.clearRect(0, 0, W, H);

      ctx.beginPath();
      ctx.arc(W / 2, H / 2, radius, 0, Math.PI * 2);
      ctx.fillStyle = ocean;
      ctx.fill();

      ctx.beginPath();
      path(graticule as any);
      ctx.strokeStyle = palette.graticule;
      ctx.lineWidth = 0.38;
      ctx.stroke();

      for (const feature of features) {
        const visited = VISITED.includes(feature.properties?.name);
        ctx.beginPath();
        path(feature);
        ctx.fillStyle = visited ? palette.visitedFill : palette.countryFill;
        ctx.strokeStyle = visited ? palette.visitedStroke : palette.countryStroke;
        ctx.lineWidth = visited ? 0.95 : 0.25;
        ctx.fill();
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.arc(W / 2, H / 2, radius * 1.06, 0, Math.PI * 2);
      ctx.fillStyle = atmos;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(W / 2, H / 2, radius, 0, Math.PI * 2);
      ctx.fillStyle = spec;
      ctx.fill();
    }

    function frame(ts: number) {
      if (!running) return;
      if (ts - lastFrameTs < FRAME_MS) {
        rafId = requestAnimationFrame(frame);
        return;
      }
      lastFrameTs = ts;

      if (!dragging) {
        const r = projection.rotate() as [number, number];
        projection.rotate([r[0] + 0.11, r[1]]);
      }

      draw();
      rafId = requestAnimationFrame(frame);
    }

    function onDown(e: PointerEvent) {
      dragging = true;
      lastX = e.clientX;
      lastY = e.clientY;
      canvas.setPointerCapture(e.pointerId);
      canvas.style.cursor = "grabbing";
    }

    function onMove(e: PointerEvent) {
      if (!dragging) return;
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      lastX = e.clientX;
      lastY = e.clientY;
      const r = projection.rotate() as [number, number];
      projection.rotate([
        r[0] + dx * 0.33,
        Math.max(-70, Math.min(70, r[1] - dy * 0.33)),
      ]);
    }

    function onUp() {
      dragging = false;
      canvas.style.cursor = "grab";
    }

    function onVisibility() {
      if (document.hidden) {
        running = false;
        cancelAnimationFrame(rafId);
      } else {
        if (!running) {
          running = true;
          rafId = requestAnimationFrame(frame);
        }
      }
    }

    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointercancel", onUp);
    document.addEventListener("visibilitychange", onVisibility);

    rafId = requestAnimationFrame(frame);

    return () => {
      running = false;
      cancelAnimationFrame(rafId);
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerup", onUp);
      canvas.removeEventListener("pointercancel", onUp);
    };
  }, []);

  return <canvas ref={canvasRef} />;
}
