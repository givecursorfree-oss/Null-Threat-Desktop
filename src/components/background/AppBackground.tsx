import { useEffect, useState } from "react";
import BackgroundScrim from "./BackgroundScrim";
import GlassWaveBackground from "./GlassWaveBackground";

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return reduced;
}

export default function AppBackground() {
  const prefersReducedMotion = usePrefersReducedMotion();

  if (prefersReducedMotion) {
    return (
      <div className="pointer-events-none fixed inset-0 -z-10 bg-background" aria-hidden>
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_70%_45%_at_50%_-10%,rgba(255,255,255,0.04),transparent)]" />
      </div>
    );
  }

  return (
    <div className="app-background-layer pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-[#050505]" aria-hidden>
      <GlassWaveBackground />
      <BackgroundScrim variant="spline" />
    </div>
  );
}
