interface BackgroundScrimProps {
  variant?: "spline" | "local";
}

export default function BackgroundScrim({ variant = "local" }: BackgroundScrimProps) {
  const isSpline = variant === "spline";

  return (
    <div className="pointer-events-none absolute inset-0 z-[2]" aria-hidden>
      <div
        className={
          isSpline ? "absolute inset-0 bg-[#050505]/50" : "absolute inset-0 bg-[#050505]/40"
        }
      />
      <div
        className={
          isSpline
            ? "absolute inset-0 bg-[radial-gradient(ellipse_90%_55%_at_50%_0%,rgba(255,255,255,0.04),transparent_60%)]"
            : "absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(34,211,238,0.06),transparent_55%)]"
        }
      />
      <div className="absolute inset-0 bg-gradient-to-b from-[#050505]/25 via-[#050505]/10 to-[#050505]/75" />
    </div>
  );
}
