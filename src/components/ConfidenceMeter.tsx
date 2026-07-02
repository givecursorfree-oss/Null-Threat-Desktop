interface ConfidenceMeterProps {
  score: number;
  size?: number;
}

function getScoreColor(score: number): string {
  if (score <= 20) return "#71717A";
  if (score <= 50) return "#EAB308";
  if (score <= 80) return "#F97316";
  return "#EF4444";
}

function getVerdictText(score: number): string {
  if (score <= 20) return "Clean";
  if (score <= 50) return "Suspicious";
  if (score <= 80) return "Likely Malicious";
  return "High Risk";
}

export default function ConfidenceMeter({ score, size = 160 }: ConfidenceMeterProps) {
  const color = getScoreColor(score);
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  const center = size / 2;

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} className="-rotate-90 transform">
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="#27272A"
          strokeWidth={8}
        />
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={8}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div
        className="absolute flex flex-col items-center justify-center"
        style={{ width: size, height: size }}
      >
        <span className="text-3xl font-bold" style={{ color }}>
          {score}
        </span>
        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
          risk score
        </span>
      </div>
      <span className="text-sm font-medium" style={{ color }}>
        {getVerdictText(score)}
      </span>
    </div>
  );
}
