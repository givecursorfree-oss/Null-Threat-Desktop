const TERMS_KEY = "null-threat-terms-accepted-v1";
const FOLDER_CONSENT_KEY = "null-threat-folder-consent-v1";

export function hasAcceptedTerms(): boolean {
  try {
    return localStorage.getItem(TERMS_KEY) === "true";
  } catch {
    return false;
  }
}

export function acceptTerms(): void {
  localStorage.setItem(TERMS_KEY, "true");
}

export function hasFolderWatchConsent(): boolean {
  try {
    return localStorage.getItem(FOLDER_CONSENT_KEY) === "true";
  } catch {
    return false;
  }
}

export function grantFolderWatchConsent(): void {
  localStorage.setItem(FOLDER_CONSENT_KEY, "true");
}

export function revokeFolderWatchConsent(): void {
  localStorage.removeItem(FOLDER_CONSENT_KEY);
}
