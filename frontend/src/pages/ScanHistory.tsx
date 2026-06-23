import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listScans, Scan } from "../api";
import SeverityBadge from "../components/SeverityBadge";
import toast from "react-hot-toast";

export default function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listScans()
      .then(setScans)
      .catch(() => toast.error("Failed to load scans"))
      .finally(() => setLoading(false));
  }, []);

  const gradeColor: Record<string, string> = {
    A: "text-green-600 bg-green-50",
    B: "text-blue-600 bg-blue-50",
    C: "text-amber-600 bg-amber-50",
    D: "text-orange-600 bg-orange-50",
    F: "text-red-600 bg-red-50",
  };

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading...</div>;

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-800">Scan History</h1>
          <p className="text-gray-500 text-sm mt-1">{scans.length} total scans</p>
        </div>
        <Link to="/scan/new" className="btn-primary">New Scan</Link>
      </div>

      {scans.length === 0 ? (
        <div className="card p-12 text-center text-gray-400">
          No scans yet. <Link to="/scan/new" className="text-[#E8651A] hover:underline">Start your first scan →</Link>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-400 uppercase border-b border-gray-100">
                <th className="text-left px-6 py-3">Account</th>
                <th className="text-left px-6 py-3">Score</th>
                <th className="text-left px-6 py-3">Findings</th>
                <th className="text-left px-6 py-3">Modules</th>
                <th className="text-left px-6 py-3">Date</th>
                <th className="text-left px-6 py-3">Status</th>
                <th className="px-6 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4">
                    <p className="font-medium text-gray-800">{scan.account_alias}</p>
                    <p className="text-xs text-gray-400">{scan.account_id}</p>
                  </td>
                  <td className="px-6 py-4">
                    {scan.security_score != null ? (
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-gray-800">{scan.security_score}</span>
                        {scan.grade && (
                          <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${gradeColor[scan.grade] ?? ""}`}>
                            {scan.grade}
                          </span>
                        )}
                      </div>
                    ) : "—"}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex gap-2">
                      <SeverityBadge severity="Critical" />
                      <span className="text-red-600 font-bold">{scan.critical_count}</span>
                      <SeverityBadge severity="High" />
                      <span className="text-orange-600 font-bold">{scan.high_count}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-gray-500 text-xs">{scan.modules_run}</td>
                  <td className="px-6 py-4 text-gray-400 text-xs">
                    {new Date(scan.started_at).toLocaleString()}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`text-xs px-2 py-1 rounded-full font-medium ${
                      scan.status === "completed" ? "bg-green-100 text-green-700" :
                      scan.status === "running" ? "bg-blue-100 text-blue-700 animate-pulse" :
                      "bg-red-100 text-red-700"
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <Link to={`/scans/${scan.id}`} className="text-[#E8651A] hover:underline font-medium text-xs">
                      View →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
