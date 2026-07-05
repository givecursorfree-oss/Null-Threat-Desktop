/** Human-readable risk score label (not a statistical confidence). */
export function formatRiskScore(score: number): string {
  return `Risk score: ${Math.round(score)}/100`;
}

export function formatRiskScoreShort(score: number): string {
  return `${Math.round(score)}/100`;
}
