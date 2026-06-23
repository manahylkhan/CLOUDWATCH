import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine,
} from "recharts";
import { listScans, Scan } from "../api";
import ScoreCircle from "../components/ScoreCircle";
import SeverityBadge from "../components/SeverityBadge";
import { Plus, TrendingUp, TrendingDown, Minus, Shield, Activity } from "lucide-react";
import toast from "react-hot-toast";

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listScans()
      .then(setScans)
      .catch(() => toast.error("Failed to load scans"))
      .finally(() => setLoading(false));
  }, []);

  const completed = scans.filter((s) => s.status === "completed");
  const latest = completed[0];
  const prev = completed[1];

  const chartData = [...completed].reverse().slice(-8).map((s) => ({
    date: new Date(s.started_at).toLocaleDateString("en", { month: "short", day: "numeric" }),
    score: s.security_score ?? 0,
    grade: s.grade,
  }));

  const scoreDelta =
    latest?.security_score != null && prev?.security_score != null
      ? latest.security_score - prev.security_score
      : null;

  const critDelta =
    latest?.critical_count != null && prev?.critical_count != null
      ? latest.critical_count - prev.critical_count
      : null;

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-gray-400">Loading dashboard...</div>;
  }

  if (!latest) {
    return (
      <div className="flex flex-col items-center justify-center h-[72vh] gap-4">
        <Shield className="text-gray-200" size={80} />
        <h2 className="text-2xl font-bold text-gray-600">No scans yet</h2>
        <p className="text-gray-400 max-w-sm text-center">
          Connect your AWS account and run your first security scan to see your posture.
        </p>
        <div className="flex gap-3">
          <Link to="/settings" className="btn-secondary">Add AWS Account</Link>
          <Link to="/scan/new" className="btn-primary flex items-center gap-2">
            <Plus size={16} /> Start First Scan
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-800">Security Dashboard</h1>
          <p className="text-gray-500 text-sm mt-0.5">
            {latest.account_alias} · Last scanned {new Date(latest.started_at).toLocaleString()}
          </p>
        </div>
        <Link to="/scan/new" className="btn-primary flex items-center gap-2">
          <Plus size={16} /> New Scan
        </Link>
      </div>

      {/* Score + Severity cards */}
      <div className="grid grid-cols-5 gap-4">
        <div className="card flex flex-col items-center justify-center py-6 gap-1">
          <ScoreCircle score={latest.security_score ?? 0} grade={latest.grade ?? "F"} />
          <p className="text-xs text-gray-500 mt-1">Security Score</p>
          {scoreDelta !== null && (
            <div className={`flex items-center gap-1 text-xs font-semibold ${scoreDelta >= 0 ? "text-green-600" : "text-red-500"}`}>
              {scoreDelta > 0 ? <TrendingUp size={12} /> : scoreDelta < 0 ? <TrendingDown size={12} /> : <Minus size={12} />}
              {scoreDelta > 0 ? "+" : ""}{scoreDelta} vs last scan
            </div>
          )}
        </div>

        <div className="col-span-4 grid grid-cols-4 gap-4">
          {[
            { label: "Critical", count: latest.critical_count, delta: critDelta ? -critDelta : null, color: "border-red-200 bg-red-50 text-red-700" },
            { label: "High", count: latest.high_count, delta: null, color: "border-orange-200 bg-orange-50 text-orange-700" },
            { label: "Medium", count: latest.medium_count, delta: null, color: "border-amber-200 bg-amber-50 text-amber-700" },
            { label: "Low", count: latest.low_count, delta: null, color: "border-blue-200 bg-blue-50 text-blue-700" },
          ].map(({ label, count, delta, color }) => (
            <div key={label} className={`card border ${color} flex flex-col items-center justify-center py-5`}>
              <span className="text-4xl font-extrabold">{count}</span>
              <span className="text-sm font-medium mt-1">{label}</span>
              {delta !== null && (
                <span className={`text-xs mt-1 font-medium ${delta >= 0 ? "text-green-600" : "text-red-500"}`}>
                  {delta > 0 ? "↓" : "↑"} {Math.abs(delta)} vs prev
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* CIS Score + AI Summary row */}
      <div className="grid grid-cols-3 gap-4">
        {latest.cis_score != null && (
          <div className="card p-5 flex flex-col items-center justify-center">
            <p className="text-4xl font-extrabold text-[#E8651A]">{latest.cis_score}%</p>
            <p className="text-sm text-gray-500 mt-1">CIS Compliance</p>
            <Link to={`/scans/${latest.id}`} className="text-xs text-[#E8651A] hover:underline mt-1">
              View CIS →
            </Link>
          </div>
        )}
        {latest.ai_summary && (
          <div className={`card p-5 border-l-4 border-[#E8651A] bg-orange-50 ${latest.cis_score != null ? "col-span-2" : "col-span-3"}`}>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">AI Executive Summary</p>
            <p className="text-sm text-gray-700 leading-relaxed">{latest.ai_summary}</p>
          </div>
        )}
      </div>

      {/* Score History Chart */}
      {chartData.length > 1 && (
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-gray-700 flex items-center gap-2">
              <Activity size={16} className="text-[#E8651A]" /> Score History
            </h2>
            {scoreDelta !== null && scoreDelta > 0 && (
              <span className="text-xs text-green-600 font-medium bg-green-50 px-2 py-1 rounded-full">
                ↑ Improving over time
              </span>
            )}
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
              <Tooltip
                formatter={(value) => [`${value}/100`, "Score"]}
                contentStyle={{ fontSize: 12, borderRadius: 8 }}
              />
              <ReferenceLine y={75} stroke="#D97706" strokeDasharray="4 4" label={{ value: "B", fontSize: 10 }} />
              <ReferenceLine y={90} stroke="#16A34A" strokeDasharray="4 4" label={{ value: "A", fontSize: 10 }} />
              <Line type="monotone" dataKey="score" stroke="#E8651A" strokeWidth={2.5}
                dot={{ fill: "#E8651A", r: 4 }} activeDot={{ r: 6 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent Scans table */}
      <div className="card">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="font-semibold text-gray-700">Recent Scans</h2>
          <Link to="/scans" className="text-sm text-[#E8651A] hover:underline">View all →</Link>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-400 uppercase border-b border-gray-100">
              <th className="text-left px-6 py-3">Account</th>
              <th className="text-left px-6 py-3">Score</th>
              <th className="text-left px-6 py-3">CIS</th>
              <th className="text-left px-6 py-3">Findings</th>
              <th className="text-left px-6 py-3">Date</th>
              <th className="px-6 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {scans.slice(0, 6).map((scan) => (
              <tr key={scan.id} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td className="px-6 py-3 font-medium text-gray-800">{scan.account_alias}</td>
                <td className="px-6 py-3">
                  {scan.security_score != null ? (
                    <span className="font-bold">{scan.security_score} <span className="text-gray-400">{scan.grade}</span></span>
                  ) : "—"}
                </td>
                <td className="px-6 py-3 text-gray-500">
                  {scan.cis_score != null ? `${scan.cis_score}%` : "—"}
                </td>
                <td className="px-6 py-3">
                  <span className="text-red-600 font-semibold">{scan.critical_count}C</span>
                  {" "}
                  <span className="text-orange-600">{scan.high_count}H</span>
                </td>
                <td className="px-6 py-3 text-gray-400 text-xs">
                  {new Date(scan.started_at).toLocaleDateString()}
                </td>
                <td className="px-6 py-3">
                  <Link to={`/scans/${scan.id}`} className="text-[#E8651A] hover:underline font-medium text-xs">
                    {scan.status === "completed" ? "View →" : scan.status}
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
