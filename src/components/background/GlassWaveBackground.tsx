export default function GlassWaveBackground() {
  return (
    <div className="glass-wave-bg pointer-events-none absolute inset-0 overflow-hidden" aria-hidden>
      <div className="glass-wave-bg__base" />
      <div className="glass-wave-bg__wave glass-wave-bg__wave--1" />
      <div className="glass-wave-bg__wave glass-wave-bg__wave--2" />
      <div className="glass-wave-bg__wave glass-wave-bg__wave--3" />
      <div className="glass-wave-bg__sheen" />
      <div className="glass-wave-bg__grid" />
    </div>
  );
}
