/**
 * Renders one of the hand-drawn Braille ASCII art files as a <pre> element
 * with a CSS spotlight mask that follows the cursor/touch.
 *
 * Why <pre> instead of canvas:
 *   - Native browser text rendering = crisp at any DPI, no pixelation
 *   - The user's actual artwork is preserved character-for-character
 *   - Interactive spotlight via CSS mask-image + CSS custom properties
 */
import { useEffect, useRef, useState } from "react";

export default function AsciiArtDisplay() {
  const ref = useRef<HTMLPreElement>(null);
  const [text, setText] = useState("");

  useEffect(() => {
    fetch("/ascii-art-1.txt")
      .then((r) => r.text())
      .then(setText)
      .catch(() => {});
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el || !text) return;

    function setPos(clientX: number, clientY: number) {
      const rect = el!.getBoundingClientRect();
      el!.style.setProperty(
        "--mx",
        `${((clientX - rect.left) / rect.width) * 100}%`
      );
      el!.style.setProperty(
        "--my",
        `${((clientY - rect.top) / rect.height) * 100}%`
      );
    }

    function onMove(e: MouseEvent) { setPos(e.clientX, e.clientY); }
    function onTouch(e: TouchEvent) {
      const t = e.touches[0];
      if (t) setPos(t.clientX, t.clientY);
    }

    document.addEventListener("mousemove", onMove);
    document.addEventListener("touchmove", onTouch, { passive: true });
    return () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("touchmove", onTouch);
    };
  }, [text]);

  return (
    <pre
      ref={ref}
      className="ascii-art"
      style={{ "--mx": "50%", "--my": "50%" } as React.CSSProperties}
    >
      {text}
    </pre>
  );
}
