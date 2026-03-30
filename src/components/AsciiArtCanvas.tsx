import { useEffect, useRef } from "react";
import { prepareWithSegments, layoutWithLines } from "@chenglou/pretext";

const artFiles = [
  "/ascii-art-1.txt",
  "/ascii-art-2.txt",
  "/ascii-art-3.txt",
  "/ascii-art-4.txt",
  "/ascii-art-5.txt",
  "/ascii-art-6.txt",
  "/ascii-art-7.txt",
];

export default function AsciiArtCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const file = artFiles[Math.floor(Math.random() * artFiles.length)];

    async function render() {
      const text = await fetch(file).then((r) => r.text());
      await document.fonts.ready;

      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      // Render at 6px — same base size used by the desktop CSS breakpoint.
      // CSS transforms in IntroCard scale the canvas up for each viewport.
      const fontSize = 6;
      const font = `${fontSize}px "JetBrains Mono", monospace`;
      const lineHeight = fontSize;

      // prepareWithSegments measures the text once using the browser font engine.
      // whiteSpace:'pre-wrap' preserves every newline as a hard line break so the
      // Braille art is never reflowed.
      const prepared = prepareWithSegments(text, font, {
        whiteSpace: "pre-wrap",
      });

      // layoutWithLines returns each line's measured text and width at the given
      // maxWidth / lineHeight.  999999 ensures lines are never soft-wrapped.
      const { lines, height } = layoutWithLines(prepared, 999999, lineHeight);

      const maxWidth = lines.reduce((m, l) => Math.max(m, l.width), 0);
      canvas.width = Math.ceil(maxWidth) || 1;
      canvas.height = Math.ceil(height) || 1;

      ctx.font = font;
      ctx.fillStyle = "#06b6d4"; // cyan (matches text-cyan in the card)
      ctx.globalAlpha = 0.5;
      ctx.textBaseline = "top";

      for (let i = 0; i < lines.length; i++) {
        ctx.fillText(lines[i].text, 0, i * lineHeight);
      }
    }

    render().catch(console.error);
  }, []);

  return <canvas ref={canvasRef} className="ascii-art" />;
}
