import { useEffect, useRef } from "react";
import * as d3 from "d3";
// @ts-ignore
import worldData from "../lib/world.json";

type Props = {
  compact?: boolean;
};

type Palette = {
  backdropTop: string;
  backdropBottom: string;
  star: string;
  starGlow: string;
  halo: string;
  aura: string;
  orbit: string;
  shadow: string;
  oceanCore: string;
  oceanMid: string;
  oceanEdge: string;
  trench: string;
  continent: string;
  continentShade: string;
  coastline: string;
  visited: string;
  visitedEdge: string;
  graticule: string;
  routeGlow: string;
  route: string;
  pin: string;
  pinGlow: string;
  cloud: string;
  specular: string;
  night: string;
  terminator: string;
  atmosphere: string;
  rim: string;
};

type GlobePoint = {
  key: string;
  label: string;
  coords: [number, number];
};

type RouteDef = {
  from: string;
  to: string;
  lift: number;
};

type Star = {
  x: number;
  y: number;
  radius: number;
  alpha: number;
  twinkle: number;
};

type Cloud = {
  lon: number;
  lat: number;
  radius: number;
  alpha: number;
  drift: number;
};

const LIGHT: Palette = {
  backdropTop: "rgba(239, 246, 255, 0.72)",
  backdropBottom: "rgba(210, 226, 248, 0.16)",
  star: "rgba(41, 75, 118, 0.35)",
  starGlow: "rgba(255, 224, 123, 0.18)",
  halo: "rgba(111, 178, 255, 0.24)",
  aura: "rgba(248, 211, 93, 0.16)",
  orbit: "rgba(73, 119, 171, 0.18)",
  shadow: "rgba(17, 39, 73, 0.22)",
  oceanCore: "#76cbf4",
  oceanMid: "#1d7bc0",
  oceanEdge: "#0d2e56",
  trench: "rgba(7, 29, 59, 0.28)",
  continent: "rgba(73, 170, 140, 0.92)",
  continentShade: "rgba(36, 107, 96, 0.58)",
  coastline: "rgba(239, 255, 251, 0.68)",
  visited: "rgba(250, 214, 102, 0.98)",
  visitedEdge: "rgba(255, 241, 190, 0.96)",
  graticule: "rgba(226, 246, 255, 0.17)",
  routeGlow: "rgba(255, 209, 101, 0.28)",
  route: "rgba(255, 229, 155, 0.98)",
  pin: "rgba(255, 238, 194, 0.98)",
  pinGlow: "rgba(255, 212, 103, 0.94)",
  cloud: "rgba(255, 255, 255, 0.14)",
  specular: "rgba(255, 255, 255, 0.36)",
  night: "rgba(7, 20, 42, 0.34)",
  terminator: "rgba(0, 7, 20, 0.66)",
  atmosphere: "rgba(167, 216, 255, 0.7)",
  rim: "rgba(255, 249, 212, 0.64)",
};

const DARK: Palette = {
  backdropTop: "rgba(8, 14, 25, 0.9)",
  backdropBottom: "rgba(15, 31, 52, 0.22)",
  star: "rgba(216, 232, 255, 0.82)",
  starGlow: "rgba(131, 194, 255, 0.24)",
  halo: "rgba(64, 152, 255, 0.3)",
  aura: "rgba(255, 203, 86, 0.16)",
  orbit: "rgba(123, 175, 236, 0.2)",
  shadow: "rgba(0, 0, 0, 0.46)",
  oceanCore: "#4bc2f2",
  oceanMid: "#125293",
  oceanEdge: "#071325",
  trench: "rgba(2, 10, 20, 0.4)",
  continent: "rgba(74, 184, 154, 0.9)",
  continentShade: "rgba(24, 94, 90, 0.66)",
  coastline: "rgba(211, 247, 255, 0.58)",
  visited: "rgba(255, 214, 106, 0.98)",
  visitedEdge: "rgba(255, 243, 196, 1)",
  graticule: "rgba(190, 228, 255, 0.14)",
  routeGlow: "rgba(255, 209, 105, 0.38)",
  route: "rgba(255, 229, 150, 0.98)",
  pin: "rgba(255, 244, 208, 1)",
  pinGlow: "rgba(255, 204, 94, 0.98)",
  cloud: "rgba(234, 247, 255, 0.12)",
  specular: "rgba(255, 255, 255, 0.32)",
  night: "rgba(3, 11, 24, 0.46)",
  terminator: "rgba(0, 0, 0, 0.8)",
  atmosphere: "rgba(108, 189, 255, 0.82)",
  rim: "rgba(255, 237, 168, 0.66)",
};

const VISITED = new Set(["Vietnam", "Australia", "Taiwan"]);

const POINTS: GlobePoint[] = [
  { key: "taiwan", label: "Taiwan", coords: [121.0, 23.7] },
  { key: "vietnam", label: "Vietnam", coords: [108.2772, 14.0583] },
  { key: "australia", label: "Australia", coords: [133.7751, -25.2744] },
];

const ROUTES: RouteDef[] = [
  { from: "taiwan", to: "vietnam", lift: 0.17 },
  { from: "vietnam", to: "australia", lift: 0.22 },
];

const makeRandom = (seed: number) => {
  let value = seed >>> 0;
  return () => {
    value = (value * 1664525 + 1013904223) >>> 0;
    return value / 4294967296;
  };
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const createStars = (width: number, height: number, compact: boolean) => {
  const random = makeRandom(Math.round(width * 17 + height * 29 + (compact ? 7 : 19)));
  const count = compact ? 26 : 68;
  return Array.from({ length: count }, () => ({
    x: random() * width,
    y: random() * height,
    radius: (compact ? 0.55 : 0.65) + random() * (compact ? 0.9 : 1.35),
    alpha: 0.18 + random() * 0.72,
    twinkle: 0.4 + random() * 1.2,
  })) satisfies Star[];
};

const createClouds = (compact: boolean) => {
  const random = makeRandom(compact ? 41 : 71);
  const count = compact ? 5 : 9;
  return Array.from({ length: count }, () => ({
    lon: -180 + random() * 360,
    lat: -48 + random() * 96,
    radius: (compact ? 10 : 12) + random() * (compact ? 8 : 12),
    alpha: 0.04 + random() * 0.08,
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
    const autoSpin = prefersReducedMotion ? 0 : compact ? 0.0034 : 0.0048;

    let width = 220;
    let height = 220;
    let radius = 82;
    let cx = 110;
    let cy = 110;
    let dpr = 1;
    let stars: Star[] = [];
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
      const maxWidth = compact ? 146 : Math.min(host?.clientWidth || 640, 720);
      width = Math.max(compact ? 132 : 260, Math.floor(maxWidth));
      height = width;
      dpr = Math.min(window.devicePixelRatio || 1, compact ? 1.5 : 1.75);

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);

      cx = width / 2;
      cy = height / 2;
      radius = Math.floor(width * (compact ? 0.36 : 0.39));
      stars = createStars(width, height, compact);

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

    const drawBackdrop = (time: number) => {
      const background = ctx.createLinearGradient(0, 0, 0, height);
      background.addColorStop(0, palette.backdropTop);
      background.addColorStop(1, palette.backdropBottom);
      ctx.fillStyle = background;
      ctx.fillRect(0, 0, width, height);

      const halo = ctx.createRadialGradient(cx, cy, radius * 0.82, cx, cy, radius * 1.78);
      halo.addColorStop(0, "rgba(0,0,0,0)");
      halo.addColorStop(0.58, palette.halo);
      halo.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.92, 0, Math.PI * 2);
      ctx.fill();

      const aura = ctx.createRadialGradient(
        cx - radius * 0.35,
        cy - radius * 0.6,
        radius * 0.08,
        cx - radius * 0.12,
        cy - radius * 0.22,
        radius * 1.15,
      );
      aura.addColorStop(0, palette.aura);
      aura.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = aura;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.55, 0, Math.PI * 2);
      ctx.fill();

      for (const star of stars) {
        const pulse = 0.65 + Math.sin(time * 0.0014 * star.twinkle + star.x * 0.02) * 0.35;
        if (!compact && star.radius > 1.2) {
          ctx.beginPath();
          ctx.arc(star.x, star.y, star.radius * (2.4 + pulse), 0, Math.PI * 2);
          ctx.fillStyle = palette.starGlow;
          ctx.globalAlpha = star.alpha * 0.16;
          ctx.fill();
        }
        ctx.beginPath();
        ctx.arc(star.x, star.y, star.radius * pulse, 0, Math.PI * 2);
        ctx.fillStyle = palette.star;
        ctx.globalAlpha = star.alpha * (compact ? 0.7 : 1);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
    };

    const drawShadow = () => {
      ctx.beginPath();
      ctx.ellipse(
        cx,
        cy + radius * (compact ? 0.97 : 1.02),
        radius * 0.93,
        radius * (compact ? 0.24 : 0.22),
        0,
        0,
        Math.PI * 2,
      );
      ctx.fillStyle = palette.shadow;
      ctx.filter = `blur(${compact ? 12 : 20}px)`;
      ctx.fill();
      ctx.filter = "none";
    };

    const drawOrbitalLines = (time: number) => {
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-0.38);
      ctx.beginPath();
      ctx.ellipse(0, 0, radius * 1.23, radius * 0.44, 0, 0, Math.PI * 2);
      ctx.strokeStyle = palette.orbit;
      ctx.lineWidth = compact ? 0.8 : 1.1;
      ctx.stroke();

      ctx.beginPath();
      ctx.ellipse(0, 0, radius * 1.07, radius * 0.28, 0, Math.PI * 0.14, Math.PI * 0.9);
      ctx.strokeStyle = palette.orbit;
      ctx.globalAlpha = compact ? 0.6 : 0.85;
      ctx.lineWidth = compact ? 0.6 : 0.95;
      ctx.stroke();

      const orbX = Math.cos(time * 0.00075) * radius * 1.23;
      const orbY = Math.sin(time * 0.00075) * radius * 0.44;
      ctx.beginPath();
      ctx.arc(orbX, orbY, compact ? 1.5 : 2.2, 0, Math.PI * 2);
      ctx.fillStyle = palette.pinGlow;
      ctx.shadowBlur = compact ? 8 : 14;
      ctx.shadowColor = palette.pinGlow;
      ctx.fill();
      ctx.restore();
      ctx.shadowBlur = 0;
      ctx.globalAlpha = 1;
    };

    const drawGlobeBody = () => {
      const ocean = ctx.createRadialGradient(
        cx - radius * 0.28,
        cy - radius * 0.42,
        radius * 0.08,
        cx,
        cy,
        radius * 1.06,
      );
      ocean.addColorStop(0, palette.oceanCore);
      ocean.addColorStop(0.48, palette.oceanMid);
      ocean.addColorStop(1, palette.oceanEdge);

      globePath();
      ctx.fillStyle = ocean;
      ctx.fill();
    };

    const drawOceanTexture = (time: number) => {
      ctx.save();
      globePath();
      ctx.clip();

      const trench = ctx.createLinearGradient(cx - radius, cy + radius * 0.7, cx + radius, cy - radius * 0.7);
      trench.addColorStop(0, "rgba(0,0,0,0)");
      trench.addColorStop(0.45, palette.trench);
      trench.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = trench;
      ctx.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);

      ctx.lineCap = "round";
      for (let i = 0; i < (compact ? 4 : 7); i += 1) {
        const waveOffset = (time * 0.00022 + i * 1.33) % (Math.PI * 2);
        const y = cy - radius * 0.65 + (radius * 1.3 * i) / (compact ? 4 : 7);
        ctx.beginPath();
        for (let step = 0; step <= 36; step += 1) {
          const t = step / 36;
          const x = cx - radius + t * radius * 2;
          const sway = Math.sin(t * Math.PI * 2 + waveOffset) * radius * 0.024;
          const dip = Math.cos(t * Math.PI * 4 - waveOffset * 0.6) * radius * 0.012;
          if (step === 0) {
            ctx.moveTo(x, y + sway + dip);
          } else {
            ctx.lineTo(x, y + sway + dip);
          }
        }
        ctx.strokeStyle = `rgba(255,255,255,${compact ? 0.045 : 0.065})`;
        ctx.lineWidth = compact ? 0.75 : 1.15;
        ctx.stroke();
      }

      ctx.restore();
    };

    const drawLand = () => {
      for (const feature of features) {
        const visited = VISITED.has(feature.properties?.name);
        ctx.beginPath();
        path(feature);
        ctx.fillStyle = visited ? palette.visited : palette.continent;
        ctx.strokeStyle = visited ? palette.visitedEdge : palette.coastline;
        ctx.lineWidth = visited ? (compact ? 0.85 : 1.05) : compact ? 0.42 : 0.58;
        ctx.fill();
        ctx.stroke();
      }

      const landShade = ctx.createLinearGradient(cx - radius, cy + radius, cx + radius, cy - radius);
      landShade.addColorStop(0, "rgba(0,0,0,0)");
      landShade.addColorStop(0.5, palette.continentShade);
      landShade.addColorStop(1, "rgba(255,255,255,0.02)");
      globePath();
      ctx.fillStyle = landShade;
      ctx.globalAlpha = compact ? 0.2 : 0.26;
      ctx.fill();
      ctx.globalAlpha = 1;
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
      ctx.lineWidth = compact ? 0.34 : 0.55;
      ctx.stroke();
    };

    const drawRoute = (from: GlobePoint, to: GlobePoint, lift: number) => {
      const start = projection(from.coords);
      const end = projection(to.coords);
      if (!start || !end) return;

      const arcLift = radius * lift;
      const midX = (start[0] + end[0]) / 2;
      const midY = (start[1] + end[1]) / 2 - arcLift;

      ctx.beginPath();
      ctx.moveTo(start[0], start[1]);
      ctx.quadraticCurveTo(midX, midY, end[0], end[1]);
      ctx.strokeStyle = palette.routeGlow;
      ctx.lineWidth = compact ? 2.2 : 3.4;
      ctx.globalAlpha = compact ? 0.45 : 0.6;
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(start[0], start[1]);
      ctx.quadraticCurveTo(midX, midY, end[0], end[1]);
      ctx.setLineDash([compact ? 5 : 8, compact ? 7 : 10]);
      ctx.lineDashOffset = -routePhase;
      ctx.strokeStyle = palette.route;
      ctx.lineWidth = compact ? 1.15 : 1.55;
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

      const pulse = 0.65 + Math.sin(routePhase * 0.16 + index * 1.4) * 0.35;
      const pinRadius = compact ? 2.3 : 3.3;
      const ringRadius = pinRadius + (compact ? 4 : 7) * pulse;

      ctx.beginPath();
      ctx.arc(projected[0], projected[1], ringRadius, 0, Math.PI * 2);
      ctx.strokeStyle = palette.pinGlow;
      ctx.globalAlpha = compact ? 0.16 : 0.24;
      ctx.lineWidth = compact ? 1 : 1.3;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(projected[0], projected[1], pinRadius, 0, Math.PI * 2);
      ctx.fillStyle = palette.pin;
      ctx.shadowBlur = compact ? 8 : 16;
      ctx.shadowColor = palette.pinGlow;
      ctx.globalAlpha = 1;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(projected[0], projected[1], pinRadius * 0.45, 0, Math.PI * 2);
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
      night.addColorStop(1, "rgba(0,0,0,0.08)");
      globePath();
      ctx.fillStyle = night;
      ctx.fill();
    };

    const drawHighlights = () => {
      const specular = ctx.createRadialGradient(
        cx - radius * 0.28,
        cy - radius * 0.42,
        radius * 0.06,
        cx - radius * 0.18,
        cy - radius * 0.18,
        radius * 0.84,
      );
      specular.addColorStop(0, palette.specular);
      specular.addColorStop(0.42, "rgba(255,255,255,0.08)");
      specular.addColorStop(1, "rgba(255,255,255,0)");
      globePath();
      ctx.fillStyle = specular;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(cx, cy, radius + (compact ? 2.1 : 2.8), 0, Math.PI * 2);
      ctx.strokeStyle = palette.atmosphere;
      ctx.lineWidth = compact ? 2.6 : 3.4;
      ctx.globalAlpha = compact ? 0.54 : 0.72;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx - radius * 0.06, cy - radius * 0.08, radius * 0.98, -Math.PI * 0.62, Math.PI * 0.08);
      ctx.strokeStyle = palette.rim;
      ctx.lineWidth = compact ? 0.9 : 1.3;
      ctx.globalAlpha = compact ? 0.32 : 0.44;
      ctx.stroke();
      ctx.globalAlpha = 1;
    };

    const paint = (time: number) => {
      ctx.clearRect(0, 0, width, height);
      drawBackdrop(time);
      drawShadow();
      if (!compact) {
        drawOrbitalLines(time);
      }
      drawGlobeBody();
      drawOceanTexture(time);
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

      routePhase += delta * (compact ? 0.024 : 0.032);
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
