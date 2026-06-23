const colors: Record<string, string> = {
  Critical: "bg-red-100 text-red-700 border border-red-200",
  High: "bg-orange-100 text-orange-700 border border-orange-200",
  Medium: "bg-amber-100 text-amber-700 border border-amber-200",
  Low: "bg-blue-100 text-blue-700 border border-blue-200",
  Info: "bg-gray-100 text-gray-600 border border-gray-200",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${colors[severity] ?? colors.Info}`}>
      {severity}
    </span>
  );
}
