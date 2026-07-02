export default function OfflineMeshBackground() {
  return (
    <div className="offline-mesh-bg pointer-events-none absolute inset-0 overflow-hidden" aria-hidden>
      <div className="offline-mesh-bg__orb offline-mesh-bg__orb--1" />
      <div className="offline-mesh-bg__orb offline-mesh-bg__orb--2" />
      <div className="offline-mesh-bg__orb offline-mesh-bg__orb--3" />
      <div className="offline-mesh-bg__grid" />
    </div>
  );
}
