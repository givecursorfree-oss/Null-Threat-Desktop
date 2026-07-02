const SPLINE_URL =
  "https://my.spline.design/glasswave-6HLEnvJfCRsq1aKT2xqlgme7";

export default function SplineBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden">
      <iframe
        title="Null Threat glass wave background"
        src={SPLINE_URL}
        className="pointer-events-none absolute left-1/2 top-1/2 h-[120%] w-[120%] -translate-x-1/2 -translate-y-1/2 border-0"
        loading="eager"
        aria-hidden
        tabIndex={-1}
      />
    </div>
  );
}
