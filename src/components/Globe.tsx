import { onMount } from "solid-js";
import * as d3 from "d3";
import worldData from "@lib/world.json";

// "Taiwan" is not in the GeoJSON dataset — using what's available
const VISITED = ["Vietnam", "Australia"];

const GlobeComponent = () => {
  let mapContainer: HTMLDivElement | undefined;

  onMount(() => {
    if (!mapContainer) return;

    const width       = mapContainer.clientWidth || 600;
    const height      = 500;
    const sensitivity = 75;

    const projection = d3
      .geoOrthographic()
      .scale(230)
      .center([0, 0])
      .rotate([0, -20])
      .translate([width / 2, height / 2]);

    const initialScale   = projection.scale();
    const pathGenerator  = d3.geoPath().projection(projection);

    const svg = d3
      .select(mapContainer)
      .append("svg")
      .attr("width", width)
      .attr("height", height);

    // Dark globe sphere
    svg
      .append("circle")
      .attr("fill", "#0f172a")
      .attr("stroke", "rgba(250,204,21,0.25)")
      .attr("stroke-width", 1)
      .attr("cx", width / 2)
      .attr("cy", height / 2)
      .attr("r", initialScale);

    // Graticule
    const graticule = d3.geoGraticule().step([30, 30]);
    const graticulePath = svg
      .append("path")
      .datum(graticule())
      .attr("d", (d: any) => pathGenerator(d as any))
      .attr("fill", "none")
      .attr("stroke", "rgba(255,255,255,0.06)")
      .attr("stroke-width", 0.5);

    // Countries
    const countries = svg
      .append("g")
      .selectAll("path")
      .data(worldData.features)
      .enter()
      .append("path")
      .attr("d", (d: any) => pathGenerator(d as any))
      .attr("fill", (d: any) =>
        VISITED.includes(d.properties.name) ? "rgba(250,204,21,0.8)" : "rgba(148,163,184,0.15)"
      )
      .attr("stroke", (d: any) =>
        VISITED.includes(d.properties.name) ? "rgba(250,204,21,0.9)" : "rgba(255,255,255,0.07)"
      )
      .attr("stroke-width", (d: any) =>
        VISITED.includes(d.properties.name) ? 1 : 0.3
      );

    // Drag to rotate
    svg.call(
      d3.drag<SVGSVGElement, unknown>().on("drag", (event: any) => {
        const rotate = projection.rotate();
        const k = sensitivity / projection.scale();
        projection.rotate([rotate[0] + event.dx * k, rotate[1] - event.dy * k]);
        countries.attr("d", (d: any) => pathGenerator(d as any));
        graticulePath.attr("d", (d: any) => pathGenerator(d as any));
      })
    );

    // Auto-spin
    d3.timer(() => {
      const rotate = projection.rotate();
      const k = sensitivity / projection.scale();
      projection.rotate([rotate[0] - 0.5 * k, rotate[1]]);
      countries.attr("d", (d: any) => pathGenerator(d as any));
      graticulePath.attr("d", (d: any) => pathGenerator(d as any));
    }, 200);
  });

  return (
    <div class="flex justify-center items-center w-full">
      <div class="w-full max-w-2xl" ref={mapContainer} />
    </div>
  );
};

export default GlobeComponent;
