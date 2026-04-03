import { useEffect, useRef } from "react";
import * as d3 from "d3";
// @ts-ignore
import worldData from "../lib/world.json";

type Props = {
  compact?: boolean;
};

type Palette = {
  oceanInner: string;
  oceanOuter: string;
  graticule: string;
  countryFill: string;
  countryStroke: string;
  visitedFill: string;
  visitedStroke: string;
  atmos: string;
  spec: string;
  night: string;
  route: string;
  pin: string;
};

const LIGHT: Palette = {
  oceanInner: "#6fa4de",
  oceanOuter: "#13304f",
  graticule: "rgba(255,255,255,0.13)",
  countryFill: "rgba(47,102,145,0.88)",
  countryStroke: "rgba(255,255,255,0.2)",
  visitedFill: "rgba(247,212,92,0.98)",
  visitedStroke: "rgba(247,212,92,1)",
  atmos: "rgba(132,187,255,0.34)",
  spec: "rgba(255,255,255,0.30)",
  night: "rgba(9,20,34,0.42)",
  route: "rgba(247,212,92,0.78)",
  pin: "rgba(250,217,105,1)",
};

const DARK: Palette = {
  oceanInner: "#4f7fb3",
  oceanOuter: "#0a1828",
  graticule: "rgba(255,255,255,0.16)",
  countryFill: "rgba(68,121,166,0.84)",
  countryStroke: "rgba(255,255,255,0.2)",
  visitedFill: "rgba(249,216,104,0.98)",
  visitedStroke: "rgba(249,216,104,1)",
  atmos: "rgba(115,177,255,0.42)",
  spec: "rgba(255,255,255,0.24)",
  night: "rgba(3,9,18,0.5)",
  route: "rgba(249,216,104,0.82)",
  pin: "rgba(250,217,105,1)",
};

const VISITED = new Set(["Vietnam", "Australia", "Taiwan"]);
const POINTS: Record<string, [number, number]> = {
  taiwan: [121.0, 23.7],
  vietnam: [108.2772, 14.0583],
  australia: [133.7751, -25.2744],
};

export default function RealisticGlobe({ compact = false }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    const root = document.documentElement;
    const projection = d3.geoOrthographic();
    const path = d3.geoPath(projection, ctx);
    const graticule = d3.geoGraticule10();
    const features = (worldData as any).features as any[];

    const fps = compact ? 20 : 26;
    const frameMs = 1000 / fps;
    const speed = compact ? 0.085 : 0.11;

    let width = 220;
    let height = 220;
    let radius = 82;
    let cx = 110;
    let cy = 110;
    let dpr = 1;
    let running = true;
    let visible = true;
    let dragging = false;
    let dark = root.classList.contains("dark");
    let palette: Palette = dark ? DARK : LIGHT;
    let rafId = 0;
    let lastTs = 0;
    let lastX = 0;
    let lastY = 0;

    const resize = () => {
      const host = canvas.parentElement;
      const maxW = compact ? 132 : Math.min(host?.clientWidth || 560, 640);
      width = Math.max(120, Math.floor(maxW));
      height = width;
      dpr = Math.min(window.devicePixelRatio || 1, 1.35);

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);

      cx = width / 2;
      cy = height / 2;
      radius = Math.floor(width * (compact ? 0.36 : 0.385));

      projection
        .scale(radius)
        .translate([cx, cy])
        .clipAngle(90)
        .precision(0.35);
    };

    const drawArc = (a: [number, number], b: [number, number], lift: number) => {
      const pa = projection(a);
      const pb = projection(b);
      if (!pa || !pb) return;
      const mx = (pa[0] + pb[0]) / 2;
      const my = (pa[1] + pb[1]) / 2 - lift;
      ctx.beginPath();
      ctx.moveTo(pa[0], pa[1]);
      ctx.quadraticCurveTo(mx, my, pb[0], pb[1]);
      ctx.strokeStyle = palette.route;
      ctx.lineWidth = compact ? 0.7 : 1.0;
      ctx.setLineDash([2, 2]);
      ctx.stroke();
      ctx.setLineDash([]);
    };

    const drawPin = (point: [number, number], r: number) => {
      const p = projection(point);
      if (!p) return;
      ctx.beginPath();
      ctx.arc(p[0], p[1], r, 0, Math.PI * 2);
      ctx.fillStyle = palette.pin;
      ctx.shadowBlur = compact ? 4 : 6;
      ctx.shadowColor = palette.pin;
      ctx.fill();
      ctx.shadowBlur = 0;
    };

    const paint = () => {
      ctx.clearRect(0, 0, width, height);

      const ocean = ctx.createRadialGradient(
        cx - radius * 0.3,
        cy - radius * 0.34,
        radius * 0.08,
        cx,
        cy,
        radius * 1.04,
      );
      ocean.addColorStop(0, palette.oceanInner);
      ocean.addColorStop(1, palette.oceanOuter);

      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fillStyle = ocean;
      ctx.fill();

      for (const feature of features) {
        const visited = VISITED.has(feature.properties?.name);
        ctx.beginPath();
        path(feature);
        ctx.fillStyle = visited ? palette.visitedFill : palette.countryFill;
        ctx.strokeStyle = visited ? palette.visitedStroke : palette.countryStroke;
        ctx.lineWidth = visited ? (compact ? 0.55 : 0.75) : 0.34;
        ctx.fill();
        ctx.stroke();
      }

      if (!compact) {
        ctx.beginPath();
        path(graticule as any);
        ctx.strokeStyle = palette.graticule;
        ctx.lineWidth = 0.52;
        ctx.stroke();
      }

      drawArc(POINTS.taiwan, POINTS.vietnam, compact ? 8 : 12);
      drawArc(POINTS.vietnam, POINTS.australia, compact ? 12 : 16);

      drawPin(POINTS.taiwan, compact ? 1.7 : 2.3);
      drawPin(POINTS.vietnam, compact ? 1.9 : 2.5);
      drawPin(POINTS.australia, compact ? 2.1 : 2.7);

      const r = projection.rotate();
      const t = ((r?.[0] || 0) % 360) / 360;
      const shadeShift = radius * 0.58 * Math.sin(t * Math.PI * 2);
      const night = ctx.createLinearGradient(cx - radius - shadeShift, cy, cx + radius - shadeShift, cy);
      night.addColorStop(0.12, "rgba(0,0,0,0)");
      night.addColorStop(0.72, palette.night);
      night.addColorStop(1, "rgba(0,0,0,0.66)");

      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fillStyle = night;
      ctx.fill();

      const spec = ctx.createRadialGradient(
        cx - radius * 0.22,
        cy - radius * 0.25,
        radius * 0.02,
        cx - radius * 0.18,
        cy - radius * 0.18,
        radius * 0.6,
      );
      spec.addColorStop(0, palette.spec);
      spec.addColorStop(1, "rgba(255,255,255,0)");

      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fillStyle = spec;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(cx, cy, radius + 1.8, 0, Math.PI * 2);
      ctx.strokeStyle = palette.atmos;
      ctx.lineWidth = compact ? 2.0 : 2.6;
      ctx.stroke();
    };

    const frame = (ts: number) => {
      if (!running) return;
      if (ts - lastTs < frameMs) {
        rafId = requestAnimationFrame(frame);
        return;
      }
      const delta = Math.min(ts - lastTs || frameMs, 64);
      lastTs = ts;

      if (!dragging) {
        const r = projection.rotate() as [number, number, number];
        projection.rotate([r[0] + delta * speed * 0.016, r[1], r[2]]);
      }

      paint();
      rafId = requestAnimationFrame(frame);
    };

    const onDown = (e: PointerEvent) => {
      dragging = true;
      lastX = e.clientX;
      lastY = e.clientY;
      canvas.setPointerCapture(e.pointerId);
      canvas.style.cursor = "grabbing";
    };

    const onMove = (e: PointerEvent) => {
      if (!dragging) return;
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      lastX = e.clientX;
      lastY = e.clientY;
      const r = projection.rotate() as [number, number, number];
      projection.rotate([
        r[0] + dx * 0.24,
        Math.max(-72, Math.min(72, r[1] - dy * 0.24)),
        r[2],
      ]);
      paint();
    };

    const onUp = () => {
      dragging = false;
      canvas.style.cursor = "grab";
    };

    const onVisibility = () => {
      visible = !document.hidden;
      if (!visible) {
        running = false;
        cancelAnimationFrame(rafId);
      } else if (!running) {
        running = true;
        rafId = requestAnimationFrame(frame);
      }
    };

    const rootObserver = new MutationObserver(() => {
      const nextDark = root.classList.contains("dark");
      if (nextDark !== dark) {
        dark = nextDark;
        palette = dark ? DARK : LIGHT;
        paint();
      }
    });
    rootObserver.observe(root, { attributes: true, attributeFilter: ["class"] });

    const io = new IntersectionObserver(
      (entries) => {
        const shown = entries.some((entry) => entry.isIntersecting);
        if (shown && visible && !running) {
          running = true;
          rafId = requestAnimationFrame(frame);
        } else if (!shown && running) {
          running = false;
          cancelAnimationFrame(rafId);
        }
      },
      { threshold: 0.01 },
    );

    const ro = new ResizeObserver(() => {
      resize();
      paint();
    });

    resize();
    projection.rotate([-112, -18, 0]);
    paint();

    io.observe(canvas);
    ro.observe(canvas.parentElement || canvas);

    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointercancel", onUp);
    document.addEventListener("visibilitychange", onVisibility);

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return () => {
        rootObserver.disconnect();
        io.disconnect();
        ro.disconnect();
        document.removeEventListener("visibilitychange", onVisibility);
        canvas.removeEventListener("pointerdown", onDown);
        canvas.removeEventListener("pointermove", onMove);
        canvas.removeEventListener("pointerup", onUp);
        canvas.removeEventListener("pointercancel", onUp);
      };
    }

    rafId = requestAnimationFrame(frame);

    return () => {
      running = false;
      cancelAnimationFrame(rafId);
      rootObserver.disconnect();
      io.disconnect();
      ro.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerup", onUp);
      canvas.removeEventListener("pointercancel", onUp);
    };
  }, [compact]);

  return <canvas ref={canvasRef} className="realistic-globe-canvas" aria-label="Visited countries globe" />;
}
