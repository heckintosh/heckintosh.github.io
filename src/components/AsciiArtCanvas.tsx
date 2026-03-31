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

  // Mouse/touch spotlight — runs once on mount, independent of text
  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    function setPos(clientX: number, clientY: number) {
      const rect = el!.getBoundingClientRect();
      el!.style.setProperty("--mx", `${((clientX - rect.left) / rect.width) * 100}%`);
      el!.style.setProperty("--my", `${((clientY - rect.top) / rect.height) * 100}%`);
    }

    const onMove  = (e: MouseEvent)  => setPos(e.clientX, e.clientY);
    const onTouch = (e: TouchEvent)  => { const t = e.touches[0]; if (t) setPos(t.clientX, t.clientY); };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("touchmove", onTouch, { passive: true });
    return () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("touchmove", onTouch);
    };
  }, []);

  return (
    <pre
      ref={ref}
      className="ascii-art"
      style={{ "--mx": "70%", "--my": "50%" } as React.CSSProperties}
    >
      {text}
    </pre>
  );
}
