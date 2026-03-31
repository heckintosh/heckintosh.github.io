import { useEffect, useRef, useState } from "react";

export default function AsciiArtDisplay() {
  const wrapperRef = useRef<HTMLDivElement>(null);
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
    const wrapper = wrapperRef.current;
    const pre     = preRef.current;
    if (!wrapper || !pre) return;

    const DIM = `radial-gradient(ellipse 130px 100px at -9999px -9999px, #facc15 0%, #f59e0b 30%, #94a3b8 65%, #cbd5e1 100%)`;

    pre.style.backgroundImage = DIM;

    function update(clientX: number, clientY: number) {
      const rect = wrapper!.getBoundingClientRect();
      const x = clientX - rect.left;
      const y = clientY - rect.top;
      // background-clip:text makes each character take the color at its position in the gradient
      pre!.style.backgroundImage =
        `radial-gradient(ellipse 130px 100px at ${x}px ${y}px, #facc15 0%, #f59e0b 30%, #94a3b8 65%, #cbd5e1 100%)`;
    }

    const onPointer = (e: PointerEvent) => update(e.clientX, e.clientY);
    const onLeave   = () => { pre!.style.backgroundImage = DIM; };

    document.addEventListener("pointermove", onPointer);
    document.addEventListener("pointerleave", onLeave);
    return () => {
      document.removeEventListener("pointermove", onPointer);
      document.removeEventListener("pointerleave", onLeave);
    };
  }, []);

  return (
    <div ref={wrapperRef} className="ascii-art">
      <pre ref={preRef} className="ascii-pre">{text}</pre>
    </div>
  );
}
