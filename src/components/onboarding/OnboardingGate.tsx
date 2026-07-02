import { useState, type ReactNode } from "react";
import { acceptTerms, hasAcceptedTerms } from "@/lib/consent";
import TermsAcceptanceModal from "./TermsAcceptanceModal";

export default function OnboardingGate({ children }: { children: ReactNode }) {
  const [termsAccepted, setTermsAccepted] = useState(hasAcceptedTerms);

  if (!termsAccepted) {
    return (
      <TermsAcceptanceModal
        onAccept={() => {
          acceptTerms();
          setTermsAccepted(true);
        }}
      />
    );
  }

  return children;
}
