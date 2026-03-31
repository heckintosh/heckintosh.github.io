/**
 * Renders one of the hand-drawn Braille ASCII art files as a <pre> element
 * with a CSS spotlight mask that follows the cursor/touch.
 *
 * Note: the <style> in IntroCard.astro uses :global(.ascii-art) to bypass
 * Astro's scoped-CSS hash — React-rendered elements don't receive the hash
 * attribute so scoped rules would not match otherwise.
 */
import { useEffect, useRef, useState } from "react";

export default function AsciiArtDisplay() {
  const ref = useRef<HTMLPreElement>(null);
  const [text, setText] = useState("");

  // Fetch a random hand-drawn art file (ascii-art-1.txt … ascii-art-9.txt)
  useEffect(() => {
    const n = Math.floor(Math.random() * 9) + 1;
    fetch(`/ascii-art-${n}.txt`)
      .then((r) => r.text())
      .then(setText)
      .catch(() => {});
  }, []);

  // Spotlight: write mask-image directly — avoids React clobbering CSS vars on re-render
  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    function applyMask(x: string, y: string) {
      const v = `radial-gradient(ellipse 55% 55% at ${x} ${y}, rgba(0,0,0,1) 0%, rgba(0,0,0,0.3) 100%)`;
      el!.style.setProperty("-webkit-mask-image", v);
      el!.style.setProperty("mask-image", v);
    }

    applyMask("70%", "50%"); // initial

    function setPos(clientX: number, clientY: number) {
      const rect = el!.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return; // not laid out yet
      applyMask(
        `${((clientX - rect.left) / rect.width) * 100}%`,
        `${((clientY - rect.top) / rect.height) * 100}%`,
      );
    }

    const onPointer = (e: PointerEvent) => setPos(e.clientX, e.clientY);
    document.addEventListener("pointermove", onPointer);
    return () => document.removeEventListener("pointermove", onPointer);
  }, []);

  return (
    <pre ref={ref} className="ascii-art">
      {text}
    </pre>
  );
}
