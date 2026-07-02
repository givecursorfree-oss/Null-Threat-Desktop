import { Routes, Route } from "react-router-dom";
import AppBackground from "./components/background/AppBackground";
import { ConsentProvider } from "./components/onboarding/ConsentProvider";
import OnboardingGate from "./components/onboarding/OnboardingGate";
import Sidebar from "./components/Sidebar";
import Dashboard from "./components/Dashboard";
import ScanFile from "./components/ScanFile";
import Quarantine from "./components/Quarantine";
import History from "./components/History";
import Settings from "./components/Settings";
import HashIntelBanner from "./components/HashIntelBanner";
import SignatureUpdateBanner from "./components/SignatureUpdateBanner";
import { useAppInit } from "./hooks/useAppInit";

export default function App() {
  useAppInit();

  return (
    <ConsentProvider>
      <OnboardingGate>
        <div className="relative flex h-screen w-screen overflow-hidden">
          <AppBackground />
          <Sidebar />

          <main className="relative z-10 flex-1 overflow-y-auto px-6 py-8 md:px-10 md:py-10">
            <HashIntelBanner />
            <SignatureUpdateBanner />
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scan" element={<ScanFile />} />
              <Route path="/quarantine" element={<Quarantine />} />
              <Route path="/history" element={<History />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </main>
        </div>
      </OnboardingGate>
    </ConsentProvider>
  );
}
