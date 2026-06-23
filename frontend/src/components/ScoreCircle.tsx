const gradeColor: Record<string, string> = {
  A: "text-green-500",
  B: "text-blue-500",
  C: "text-amber-500",
  D: "text-orange-500",
  F: "text-red-500",
};

const ringColor: Record<string, string> = {
  A: "stroke-green-500",
  B: "stroke-blue-500",
  C: "stroke-amber-500",
  D: "stroke-orange-500",
  F: "stroke-red-500",
};

interface Props {
  score: number;
  grade: string;
  size?: number;
}

export default function ScoreCircle({ score, grade, size = 140 }: Props) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 120 120" className="-rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#e5e7eb" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          strokeWidth="10"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className={`transition-all duration-700 ${ringColor[grade] ?? "stroke-gray-400"}`}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-2xl font-extrabold text-gray-800">{score}</span>
        <span className={`text-xl font-bold ${gradeColor[grade] ?? "text-gray-500"}`}>{grade}</span>
      </div>
    </div>
  );
}
