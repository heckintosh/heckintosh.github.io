import { useEffect, useRef, useState } from "react";

export default function AsciiArtDisplay() {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const preRef     = useRef<HTMLPreElement>(null);
  const [text, setText] = useState("");

  useEffect(() => {
    const n = Math.floor(Math.random() * 9) + 1;
    fetch(`/ascii-art-${n}.txt`)
      .then((r) => r.text())
      .then(setText)
      .catch(() => {});
  }, []);

  useEffect(() => {
    const wrapper  = wrapperRef.current;
    const overlay  = overlayRef.current;
    const pre      = preRef.current;
    if (!wrapper || !overlay || !pre) return;

    function update(clientX: number, clientY: number) {
      const rect = wrapper!.getBoundingClientRect();
      const x = clientX - rect.left;
      const y = clientY - rect.top;

      // spotlight
      overlay!.style.background =
        `radial-gradient(ellipse 160px 120px at ${x}px ${y}px, transparent 0%, rgba(0,0,0,0.78) 65%)`;

      // translate pre toward cursor (relative to wrapper center)
      const cx = rect.width  / 2;
      const cy = rect.height / 2;
      const tx = ((x - cx) / cx) * 18;
      const ty = ((y - cy) / cy) * 12;
      pre!.style.transform = `translate(${tx}px, ${ty}px)`;
    }

    function onLeave() {
      overlay!.style.background = "rgba(0,0,0,0.78)";
      pre!.style.transform = "translate(0px, 0px)";
    }

    const onPointer = (e: PointerEvent) => update(e.clientX, e.clientY);
    document.addEventListener("pointermove", onPointer);
    document.addEventListener("pointerleave", onLeave);
    return () => {
      document.removeEventListener("pointermove", onPointer);
      document.removeEventListener("pointerleave", onLeave);
    };
  }, []);

  return (
    <div ref={wrapperRef} className="ascii-art">
      <pre ref={preRef} className="ascii-pre" style={{ transition: "transform 0.08s linear" }}>{text}</pre>
      {/* dark overlay with radial hole at cursor — no mask-image, no CSS vars */}
      <div
        ref={overlayRef}
        style={{
          position: "absolute",
          inset: 0,
          pointerEvents: "none",
          background: "rgba(0,0,0,0.78)",
        }}
      />
    </div>
  );
}
