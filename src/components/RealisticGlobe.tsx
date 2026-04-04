import { useEffect, useRef } from "react";
import * as d3 from "d3";
// @ts-ignore
import worldData from "../lib/world.json";

type Props = {
  compact?: boolean;
};

type Palette = {
  halo: string;
  orbit: string;
  shadow: string;
  oceanCore: string;
  oceanMid: string;
  oceanEdge: string;
  continent: string;
  coastline: string;
  visited: string;
  visitedEdge: string;
  graticule: string;
  cloud: string;
  routeGlow: string;
  route: string;
  pin: string;
  pinGlow: string;
  specular: string;
  night: string;
  terminator: string;
  atmosphere: string;
};

type GlobePoint = {
  key: string;
  coords: [number, number];
};

type RouteDef = {
  from: string;
  to: string;
  lift: number;
};

type Cloud = {
  lon: number;
  lat: number;
  radius: number;
  alpha: number;
  drift: number;
};

const LIGHT: Palette = {
  halo: "rgba(116, 179, 255, 0.18)",
  orbit: "rgba(84, 128, 182, 0.18)",
  shadow: "rgba(14, 34, 62, 0.16)",
  oceanCore: "#84d6ff",
  oceanMid: "#1f83ca",
  oceanEdge: "#0e335e",
  continent: "rgba(77, 177, 148, 0.92)",
  coastline: "rgba(238, 252, 255, 0.72)",
  visited: "rgba(251, 214, 102, 0.98)",
  visitedEdge: "rgba(255, 243, 201, 0.98)",
  graticule: "rgba(230, 244, 255, 0.15)",
  cloud: "rgba(255, 255, 255, 0.12)",
  routeGlow: "rgba(255, 204, 98, 0.3)",
  route: "rgba(255, 233, 160, 0.98)",
  pin: "rgba(255, 245, 219, 1)",
  pinGlow: "rgba(255, 203, 92, 0.96)",
  specular: "rgba(255, 255, 255, 0.34)",
  night: "rgba(5, 18, 37, 0.28)",
  terminator: "rgba(0, 7, 20, 0.58)",
  atmosphere: "rgba(168, 216, 255, 0.62)",
};

const DARK: Palette = {
  halo: "rgba(58, 146, 255, 0.2)",
  orbit: "rgba(111, 166, 232, 0.2)",
  shadow: "rgba(0, 0, 0, 0.38)",
  oceanCore: "#4dc8fb",
  oceanMid: "#155694",
  oceanEdge: "#061223",
  continent: "rgba(72, 182, 154, 0.9)",
  coastline: "rgba(214, 245, 255, 0.54)",
  visited: "rgba(255, 214, 106, 0.98)",
  visitedEdge: "rgba(255, 242, 197, 1)",
  graticule: "rgba(198, 229, 255, 0.12)",
  cloud: "rgba(239, 248, 255, 0.1)",
  routeGlow: "rgba(255, 208, 102, 0.36)",
  route: "rgba(255, 229, 153, 0.98)",
  pin: "rgba(255, 247, 220, 1)",
  pinGlow: "rgba(255, 204, 94, 0.98)",
  specular: "rgba(255, 255, 255, 0.3)",
  night: "rgba(3, 11, 24, 0.44)",
  terminator: "rgba(0, 0, 0, 0.76)",
  atmosphere: "rgba(108, 189, 255, 0.78)",
};

const VISITED = new Set(["Vietnam", "Australia", "Taiwan"]);

const POINTS: GlobePoint[] = [
  { key: "taiwan", coords: [121.0, 23.7] },
  { key: "vietnam", coords: [108.2772, 14.0583] },
  { key: "australia", coords: [133.7751, -25.2744] },
];

const ROUTES: RouteDef[] = [
  { from: "taiwan", to: "vietnam", lift: 0.16 },
  { from: "vietnam", to: "australia", lift: 0.22 },
];

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const makeRandom = (seed: number) => {
  let value = seed >>> 0;
  return () => {
    value = (value * 1664525 + 1013904223) >>> 0;
    return value / 4294967296;
  };
};

const createClouds = (compact: boolean) => {
  const random = makeRandom(compact ? 31 : 67);
  const count = compact ? 4 : 7;
  return Array.from({ length: count }, () => ({
    lon: -180 + random() * 360,
    lat: -48 + random() * 96,
    radius: (compact ? 10 : 12) + random() * (compact ? 8 : 10),
    alpha: 0.04 + random() * 0.06,
    drift: 0.2 + random() * 0.8,
  })) satisfies Cloud[];
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
    const graticule = d3.geoGraticule().step([15, 15])();
    const features = (worldData as { features: any[] }).features;
    const pointsByKey = new Map(POINTS.map((point) => [point.key, point]));
    const clouds = createClouds(compact);
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const fps = compact ? 24 : 30;
    const frameMs = 1000 / fps;
    const autoSpin = prefersReducedMotion ? 0 : compact ? 0.0032 : 0.0046;

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
    let velocityX = 0;
    let velocityY = 0;
    let routePhase = 0;
    let cloudPhase = 0;

    const resize = () => {
      const host = canvas.parentElement;
      const maxWidth = compact ? 148 : Math.min(host?.clientWidth || 960, 1120);
      width = Math.max(compact ? 132 : 320, Math.floor(maxWidth));
      height = compact ? width : Math.floor(width * 0.84);
      dpr = Math.min(window.devicePixelRatio || 1, compact ? 1.5 : 1.75);

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);

      cx = width / 2;
      cy = compact ? height / 2 : height * 0.52;
      radius = Math.floor(Math.min(width, height) * (compact ? 0.36 : 0.44));

      projection
        .scale(radius)
        .translate([cx, cy])
        .clipAngle(90)
        .precision(0.35);
    };

    const globePath = () => {
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    };

    const drawHalo = () => {
      const halo = ctx.createRadialGradient(cx, cy, radius * 0.74, cx, cy, radius * 1.6);
      halo.addColorStop(0, "rgba(0,0,0,0)");
      halo.addColorStop(0.55, palette.halo);
      halo.addColorStop(1, "rgba(0,0,0,0)");
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.7, 0, Math.PI * 2);
      ctx.fillStyle = halo;
      ctx.fill();
    };

    const drawShadow = () => {
      ctx.beginPath();
      ctx.ellipse(
        cx,
        cy + radius * (compact ? 1.04 : 1.14),
        radius * 0.92,
        radius * (compact ? 0.18 : 0.16),
        0,
        0,
        Math.PI * 2,
      );
      ctx.fillStyle = palette.shadow;
      ctx.filter = `blur(${compact ? 10 : 18}px)`;
      ctx.fill();
      ctx.filter = "none";
    };

    const drawOrbits = (time: number) => {
      if (compact) return;

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-0.36);

      ctx.beginPath();
      ctx.ellipse(0, 0, radius * 1.26, radius * 0.42, 0, 0, Math.PI * 2);
      ctx.strokeStyle = palette.orbit;
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.beginPath();
      ctx.ellipse(0, 0, radius * 1.08, radius * 0.24, 0, Math.PI * 0.1, Math.PI * 0.92);
      ctx.globalAlpha = 0.75;
      ctx.stroke();

      const orbX = Math.cos(time * 0.0007) * radius * 1.26;
      const orbY = Math.sin(time * 0.0007) * radius * 0.42;
      ctx.beginPath();
      ctx.arc(orbX, orbY, 2.1, 0, Math.PI * 2);
      ctx.fillStyle = palette.pinGlow;
      ctx.shadowBlur = 14;
      ctx.shadowColor = palette.pinGlow;
      ctx.fill();
      ctx.restore();
      ctx.shadowBlur = 0;
      ctx.globalAlpha = 1;
    };

    const drawGlobeBody = () => {
      const ocean = ctx.createRadialGradient(
        cx - radius * 0.28,
        cy - radius * 0.4,
        radius * 0.06,
        cx,
        cy,
        radius * 1.04,
      );
      ocean.addColorStop(0, palette.oceanCore);
      ocean.addColorStop(0.46, palette.oceanMid);
      ocean.addColorStop(1, palette.oceanEdge);

      globePath();
      ctx.fillStyle = ocean;
      ctx.fill();
    };

    const drawLand = () => {
      for (const feature of features) {
        const visited = VISITED.has(feature.properties?.name);
        ctx.beginPath();
        path(feature);
        ctx.fillStyle = visited ? palette.visited : palette.continent;
        ctx.strokeStyle = visited ? palette.visitedEdge : palette.coastline;
        ctx.lineWidth = visited ? (compact ? 0.8 : 1.05) : compact ? 0.4 : 0.56;
        ctx.fill();
        ctx.stroke();
      }
    };

    const drawClouds = () => {
      for (const cloud of clouds) {
        const geometry = d3
          .geoCircle()
          .center([cloud.lon + cloudPhase * cloud.drift * 8, cloud.lat])
          .radius(cloud.radius)();
        ctx.beginPath();
        path(geometry as any);
        ctx.fillStyle = palette.cloud;
        ctx.globalAlpha = cloud.alpha;
        ctx.fill();
      }
      ctx.globalAlpha = 1;
    };

    const drawGraticule = () => {
      ctx.beginPath();
      path(graticule as any);
      ctx.strokeStyle = palette.graticule;
      ctx.lineWidth = compact ? 0.32 : 0.5;
      ctx.stroke();
    };

    const drawRoute = (from: GlobePoint, to: GlobePoint, lift: number) => {
      const start = projection(from.coords);
      const end = projection(to.coords);
      if (!start || !end) return;

      const midX = (start[0] + end[0]) / 2;
      const midY = (start[1] + end[1]) / 2 - radius * lift;

      ctx.beginPath();
      ctx.moveTo(start[0], start[1]);
      ctx.quadraticCurveTo(midX, midY, end[0], end[1]);
      ctx.strokeStyle = palette.routeGlow;
      ctx.lineWidth = compact ? 2 : 3.2;
      ctx.globalAlpha = compact ? 0.42 : 0.58;
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(start[0], start[1]);
      ctx.quadraticCurveTo(midX, midY, end[0], end[1]);
      ctx.setLineDash([compact ? 5 : 8, compact ? 7 : 10]);
      ctx.lineDashOffset = -routePhase;
      ctx.strokeStyle = palette.route;
      ctx.lineWidth = compact ? 1.05 : 1.45;
      ctx.globalAlpha = 1;
      ctx.stroke();
      ctx.setLineDash([]);
    };

    const drawRoutes = () => {
      for (const route of ROUTES) {
        const from = pointsByKey.get(route.from);
        const to = pointsByKey.get(route.to);
        if (!from || !to) continue;
        drawRoute(from, to, route.lift);
      }
    };

    const drawPin = (point: GlobePoint, index: number) => {
      const projected = projection(point.coords);
      if (!projected) return;

      const pulse = 0.65 + Math.sin(routePhase * 0.16 + index * 1.5) * 0.35;
      const pinRadius = compact ? 2.2 : 3.2;
      const ringRadius = pinRadius + (compact ? 4 : 6) * pulse;

      ctx.beginPath();
      ctx.arc(projected[0], projected[1], ringRadius, 0, Math.PI * 2);
      ctx.strokeStyle = palette.pinGlow;
      ctx.globalAlpha = compact ? 0.14 : 0.2;
      ctx.lineWidth = compact ? 1 : 1.25;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(projected[0], projected[1], pinRadius, 0, Math.PI * 2);
      ctx.fillStyle = palette.pin;
      ctx.globalAlpha = 1;
      ctx.shadowBlur = compact ? 8 : 16;
      ctx.shadowColor = palette.pinGlow;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(projected[0], projected[1], pinRadius * 0.46, 0, Math.PI * 2);
      ctx.fillStyle = palette.pinGlow;
      ctx.fill();
      ctx.shadowBlur = 0;
    };

    const drawPins = () => {
      POINTS.forEach(drawPin);
    };

    const drawNight = () => {
      const rotation = projection.rotate() as [number, number, number];
      const shift = Math.sin((rotation[0] / 180) * Math.PI) * radius * 0.55;
      const night = ctx.createLinearGradient(cx - radius - shift, cy, cx + radius - shift, cy);
      night.addColorStop(0, "rgba(0,0,0,0)");
      night.addColorStop(0.52, palette.night);
      night.addColorStop(0.78, palette.terminator);
      night.addColorStop(1, "rgba(0,0,0,0.06)");
      globePath();
      ctx.fillStyle = night;
      ctx.fill();
    };

    const drawHighlights = () => {
      const specular = ctx.createRadialGradient(
        cx - radius * 0.28,
        cy - radius * 0.42,
        radius * 0.05,
        cx - radius * 0.18,
        cy - radius * 0.18,
        radius * 0.82,
      );
      specular.addColorStop(0, palette.specular);
      specular.addColorStop(0.42, "rgba(255,255,255,0.08)");
      specular.addColorStop(1, "rgba(255,255,255,0)");
      globePath();
      ctx.fillStyle = specular;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(cx, cy, radius + (compact ? 2.2 : 2.8), 0, Math.PI * 2);
      ctx.strokeStyle = palette.atmosphere;
      ctx.lineWidth = compact ? 2.4 : 3.2;
      ctx.globalAlpha = compact ? 0.52 : 0.72;
      ctx.stroke();
      ctx.globalAlpha = 1;
    };

    const paint = (time: number) => {
      ctx.clearRect(0, 0, width, height);
      drawHalo();
      drawShadow();
      drawOrbits(time);
      drawGlobeBody();
      drawLand();
      drawClouds();
      drawGraticule();
      drawRoutes();
      drawPins();
      drawNight();
      drawHighlights();
    };

    const frame = (ts: number) => {
      if (!running) return;
      if (ts - lastTs < frameMs) {
        rafId = requestAnimationFrame(frame);
        return;
      }

      const delta = Math.min(ts - lastTs || frameMs, 64);
      lastTs = ts;
      const rotation = projection.rotate() as [number, number, number];

      if (!dragging) {
        projection.rotate([
          rotation[0] + delta * (autoSpin + velocityX * 0.014),
          clamp(rotation[1] + velocityY * 0.014 * delta, -35, 35),
          rotation[2],
        ]);
        velocityX *= 0.94;
        velocityY *= 0.9;
      }

      routePhase += delta * (compact ? 0.022 : 0.03);
      cloudPhase += delta * 0.0008;
      paint(ts);
      rafId = requestAnimationFrame(frame);
    };

    const onDown = (event: PointerEvent) => {
      dragging = true;
      lastX = event.clientX;
      lastY = event.clientY;
      velocityX = 0;
      velocityY = 0;
      canvas.setPointerCapture(event.pointerId);
      canvas.style.cursor = "grabbing";
    };

    const onMove = (event: PointerEvent) => {
      if (!dragging) return;
      const dx = event.clientX - lastX;
      const dy = event.clientY - lastY;
      lastX = event.clientX;
      lastY = event.clientY;
      velocityX = dx;
      velocityY = -dy * 0.18;

      const rotation = projection.rotate() as [number, number, number];
      projection.rotate([
        rotation[0] + dx * 0.28,
        clamp(rotation[1] - dy * 0.22, -35, 35),
        rotation[2],
      ]);
      paint(performance.now());
    };

    const onUp = (event?: PointerEvent) => {
      if (event && canvas.hasPointerCapture(event.pointerId)) {
        canvas.releasePointerCapture(event.pointerId);
      }
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
        paint(performance.now());
      }
    });
    rootObserver.observe(root, { attributes: true, attributeFilter: ["class"] });

    const intersectionObserver = new IntersectionObserver(
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
      { threshold: 0.02 },
    );

    const resizeObserver = new ResizeObserver(() => {
      resize();
      paint(performance.now());
    });

    resize();
    projection.rotate([-116, -14, 0]);
    paint(0);

    intersectionObserver.observe(canvas);
    resizeObserver.observe(canvas.parentElement || canvas);

    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointerleave", onUp);
    canvas.addEventListener("pointercancel", onUp);
    document.addEventListener("visibilitychange", onVisibility);

    if (!prefersReducedMotion) {
      rafId = requestAnimationFrame(frame);
    }

    return () => {
      running = false;
      cancelAnimationFrame(rafId);
      rootObserver.disconnect();
      intersectionObserver.disconnect();
      resizeObserver.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerup", onUp);
      canvas.removeEventListener("pointerleave", onUp);
      canvas.removeEventListener("pointercancel", onUp);
    };
  }, [compact]);

  return <canvas ref={canvasRef} className="realistic-globe-canvas" aria-label="Visited countries globe" />;
}
