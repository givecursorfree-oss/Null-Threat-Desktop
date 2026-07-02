import { useEffect, useState } from "react";

const UNICORN_PROJECT_ID = "tPmIIl0vKqHO9yqmtge2";
const UNICORN_SCRIPT = "/vendor/unicornStudio.umd.js";
const UNICORN_PROJECT_JSON = "/background/unicorn-project.json";

declare global {
  interface Window {
    UnicornStudio?: {
      isInitialized: boolean;
      init: () => void;
    };
  }
}

export default function UnicornStudioBackground() {
  const [projectSrc, setProjectSrc] = useState<string | null>(null);

  useEffect(() => {
    fetch(UNICORN_PROJECT_JSON, { method: "HEAD" })
      .then((response) => {
        if (response.ok) setProjectSrc(UNICORN_PROJECT_JSON);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const existing = document.querySelector(`script[src="${UNICORN_SCRIPT}"]`);

    const initUnicorn = () => {
      if (window.UnicornStudio && !window.UnicornStudio.isInitialized) {
        window.UnicornStudio.init();
        window.UnicornStudio.isInitialized = true;
      }
    };

    if (existing) {
      initUnicorn();
      return;
    }

    const script = document.createElement("script");
    script.src = UNICORN_SCRIPT;
    script.async = true;
    script.onload = initUnicorn;
    document.head.appendChild(script);

    return () => {
      script.onload = null;
    };
  }, []);

  return (
    <div
      className="pointer-events-none absolute inset-0 overflow-hidden"
      aria-hidden
    >
      <div
        {...(projectSrc
          ? { "data-us-project-src": projectSrc }
          : { "data-us-project": UNICORN_PROJECT_ID })}
        className="absolute inset-0 h-full w-full"
      />
      <div
        className="absolute inset-0 z-[1]"
        style={{
          backgroundColor: "rgba(34, 211, 238, 0.1)",
          mixBlendMode: "soft-light",
        }}
      />
    </div>
  );
}
