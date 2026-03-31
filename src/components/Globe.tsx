import { onMount } from "solid-js";
import * as d3 from "d3";
import worldData from "@lib/world.json";

const VISITED = ["Vietnam", "Australia"];

const GlobeComponent = () => {
  let mapContainer: HTMLDivElement | undefined;

  onMount(() => {
    if (!mapContainer) return;

    const width      = mapContainer.clientWidth || window.innerWidth;
    const height     = Math.min(window.innerHeight * 0.75, 520);
    const radius     = Math.min(width, height) * 0.42;

    const projection = d3
      .geoOrthographic()
      .scale(radius)
      .translate([width / 2, height / 2])
      .rotate([0, -20])
      .clipAngle(90);

    const path = d3.geoPath().projection(projection);

    const svg = d3
      .select(mapContainer)
      .append("svg")
      .attr("width", width)
      .attr("height", height)
      .style("cursor", "grab");

    // Ocean
    svg
      .append("circle")
      .attr("cx", width / 2)
      .attr("cy", height / 2)
      .attr("r", radius)
      .attr("fill", "#1a3a5c");

    // Graticule grid
    const graticule = d3.geoGraticule()();
    const gratPath = svg
      .append("path")
      .datum(graticule)
      .attr("d", (d: any) => path(d as any))
      .attr("fill", "none")
      .attr("stroke", "rgba(255,255,255,0.08)")
      .attr("stroke-width", 0.4);

    // All countries
    const countries = svg
      .append("g")
      .selectAll("path")
      .data(worldData.features)
      .enter()
      .append("path")
      .attr("d", (d: any) => path(d as any))
      .attr("fill", (d: any) =>
        VISITED.includes(d.properties.name) ? "#facc15" : "#2d6a4f"
      )
      .attr("stroke", "rgba(255,255,255,0.18)")
      .attr("stroke-width", 0.4);

    // Atmosphere glow ring
    const defs = svg.append("defs");
    const glow = defs.append("radialGradient")
      .attr("id", "atmos")
      .attr("cx", "50%").attr("cy", "50%").attr("r", "50%");
    glow.append("stop").attr("offset", "85%").attr("stop-color", "transparent");
    glow.append("stop").attr("offset", "100%").attr("stop-color", "rgba(100,160,255,0.18)");
    svg
      .append("circle")
      .attr("cx", width / 2)
      .attr("cy", height / 2)
      .attr("r", radius + 6)
      .attr("fill", "url(#atmos)")
      .attr("pointer-events", "none");

    // Drag
    let dragging = false;
    svg.call(
      d3.drag<SVGSVGElement, unknown>()
        .on("start", () => { dragging = true; svg.style("cursor", "grabbing"); })
        .on("drag", (event: any) => {
          const r = projection.rotate();
          const k = 0.4;
          projection.rotate([r[0] + event.dx * k, Math.max(-60, Math.min(60, r[1] - event.dy * k))]);
          countries.attr("d", (d: any) => path(d as any));
          gratPath.attr("d", (d: any) => path(d as any));
        })
        .on("end", () => { dragging = false; svg.style("cursor", "grab"); })
    );

    // Auto-spin
    d3.timer(() => {
      if (dragging) return;
      const r = projection.rotate();
      projection.rotate([r[0] - 0.2, r[1]]);
      countries.attr("d", (d: any) => path(d as any));
      gratPath.attr("d", (d: any) => path(d as any));
    });
  });

  return <div class="w-full" ref={mapContainer} />;
};

export default GlobeComponent;
