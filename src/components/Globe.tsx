import { onMount } from "solid-js";
import * as d3 from "d3";
import worldData from "@lib/world.json";

const VISITED = ["Vietnam", "Australia", "Taiwan"];

const GlobeComponent = () => {
  let mapContainer: HTMLDivElement | undefined;

  onMount(() => {
    if (!mapContainer) return;

    const width      = mapContainer.clientWidth || window.innerWidth;
    const height     = Math.min(window.innerHeight - 120, 600);
    const sensitivity = 60;

    const projection = d3
      .geoOrthographic()
      .scale(Math.min(width, height) * 0.42)
      .center([0, 0])
      .rotate([0, -15])
      .translate([width / 2, height / 2]);

    const pathGenerator = d3.geoPath().projection(projection);

    const svg = d3
      .select(mapContainer)
      .append("svg")
      .attr("width", width)
      .attr("height", height);

    // Globe base — dark sphere
    svg
      .append("circle")
      .attr("cx", width / 2)
      .attr("cy", height / 2)
      .attr("r", projection.scale())
      .attr("fill", "#0f172a")
      .attr("stroke", "rgba(250,204,21,0.2)")
      .attr("stroke-width", 1);

    // Grid lines (graticule)
    const graticule = d3.geoGraticule().step([30, 30]);
    svg
      .append("path")
      .datum(graticule())
      .attr("d", (d: any) => pathGenerator(d as any))
      .attr("fill", "none")
      .attr("stroke", "rgba(255,255,255,0.06)")
      .attr("stroke-width", 0.5)
      .attr("class", "graticule");

    // Countries
    const map = svg.append("g");
    map
      .append("g")
      .attr("class", "countries")
      .selectAll("path")
      .data(worldData.features)
      .enter()
      .append("path")
      .attr("d", (d: any) => pathGenerator(d as any))
      .attr("fill", (d: { properties: { name: string } }) =>
        VISITED.includes(d.properties.name) ? "rgba(250,204,21,0.75)" : "rgba(148,163,184,0.12)"
      )
      .attr("stroke", (d: { properties: { name: string } }) =>
        VISITED.includes(d.properties.name) ? "rgba(250,204,21,0.9)" : "rgba(255,255,255,0.06)"
      )
      .attr("stroke-width", (d: { properties: { name: string } }) =>
        VISITED.includes(d.properties.name) ? 1 : 0.3
      );

    // Labels for visited countries
    VISITED.forEach((name) => {
      const feature = (worldData.features as any[]).find(
        (f: any) => f.properties?.name === name
      );
      if (!feature) return;
      const centroid = d3.geoCentroid(feature);
      const proj = projection(centroid);
      if (!proj) return;
      const [px, py] = proj;

      svg
        .append("text")
        .attr("x", px)
        .attr("y", py - 10)
        .attr("text-anchor", "middle")
        .attr("font-family", "'JetBrains Mono', monospace")
        .attr("font-size", "10px")
        .attr("fill", "rgba(250,204,21,0.95)")
        .attr("pointer-events", "none")
        .attr("class", `label-${name.replace(/\s/g, "")}`)
        .text(name);
    });

    // Auto-rotate + drag
    let isDragging = false;
    let lastX = 0;

    svg
      .on("pointerdown", (event: PointerEvent) => {
        isDragging = true;
        lastX = event.clientX;
        (event.target as Element).setPointerCapture?.(event.pointerId);
      })
      .on("pointermove", (event: PointerEvent) => {
        if (!isDragging) return;
        const dx = event.clientX - lastX;
        lastX = event.clientX;
        const r = projection.rotate();
        projection.rotate([r[0] + dx * (sensitivity / projection.scale()), r[1]]);
        svg.selectAll("path").attr("d", (d: any) => pathGenerator(d as any));
        // Update labels
        VISITED.forEach((name) => {
          const feature = (worldData.features as any[]).find(
            (f: any) => f.properties?.name === name
          );
          if (!feature) return;
          const centroid = d3.geoCentroid(feature);
          const proj2 = projection(centroid);
          if (!proj2) return;
          const visible = (d3.geoPath().projection(projection).measure(feature) > 0) ||
            (() => {
              const [lon, lat] = centroid;
              const r = projection.rotate();
              const lonDiff = Math.abs(((lon + r[0] + 180) % 360) - 180);
              return lonDiff < 90;
            })();
          svg
            .select(`.label-${name.replace(/\s/g, "")}`)
            .attr("x", proj2[0])
            .attr("y", proj2[1] - 10)
            .attr("opacity", visible ? 1 : 0);
        });
      })
      .on("pointerup pointercancel", () => { isDragging = false; });

    d3.timer((elapsed) => {
      if (isDragging) return;
      const k = sensitivity / projection.scale();
      const r = projection.rotate();
      projection.rotate([r[0] - 0.8 * k, r[1]]);
      svg.selectAll("path").attr("d", (d: any) => pathGenerator(d as any));
      // Update label positions
      VISITED.forEach((name) => {
        const feature = (worldData.features as any[]).find(
          (f: any) => f.properties?.name === name
        );
        if (!feature) return;
        const centroid = d3.geoCentroid(feature);
        const proj2 = projection(centroid);
        if (!proj2) return;
        svg
          .select(`.label-${name.replace(/\s/g, "")}`)
          .attr("x", proj2[0])
          .attr("y", proj2[1] - 10);
      });
    }, 200);
  });

  return (
    <div class="flex flex-col justify-center items-center w-full h-full">
      <div class="w-full" ref={mapContainer} />
    </div>
  );
};

export default GlobeComponent;
