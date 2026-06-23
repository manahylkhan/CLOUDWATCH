import { useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  getScan, getScanFindings, analyzeCloudTrail, runAIPrioritization,
  getReportPdfUrl, getReportWordUrl, Scan, Finding, CISResult,
} from "../api";
import ScoreCircle from "../components/ScoreCircle";
import SeverityBadge from "../components/SeverityBadge";
import toast from "react-hot-toast";
import {
  ChevronDown, ChevronUp, Filter, ArrowLeft, Upload,
  FileText, Brain, CheckCircle, XCircle, Download,
} from "lucide-react";

type Tab = "findings" | "iam" | "cis" | "cloudtrail" | "ai";

const TABS: { id: Tab; label: string }[] = [
  { id: "findings", label: "All Findings" },
  { id: "iam", label: "IAM Audit" },
  { id: "cis", label: "CIS Benchmark" },
  { id: "cloudtrail", label: "CloudTrail" },
  { id: "ai", label: "AI Insights" },
];

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

export default function ScanResults() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("findings");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filterSev, setFilterSev] = useState("");
  const [filterMod, setFilterMod] = useState("");
  const [filterSvc, setFilterSvc] = useState("");
  const [cisFilter, setCisFilter] = useState<"all" | "fail">("all");
  const [uploading, setUploading] = useState(false);
  const [aiRunning, setAiRunning] = useState(false);
  const [clientName, setClientName] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const reload = () => {
    if (!id) return;
    Promise.all([getScan(id), getScanFindings(id)])
      .then(([s, f]) => { setScan(s); setFindings(f); })
      .catch(() => toast.error("Failed to load scan results"))
      .finally(() => setLoading(false));
  };

  useEffect(reload, [id]);

  const toggle = (fid: string) =>
    setExpanded((prev) => { const n = new Set(prev); n.has(fid) ? n.delete(fid) : n.add(fid); return n; });

  const handleCloudTrailUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !id) return;
    setUploading(true);
    try {
      const result = await analyzeCloudTrail(id, file);
      toast.success(`CloudTrail analyzed: ${result.events_parsed} events, ${result.rule_findings} findings`);
      reload();
      setTab("cloudtrail");
    } catch (err: any) {
      toast.error(err?.response?.data?.detail ?? "CloudTrail analysis failed");
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const handleAIAnalysis = async () => {
    if (!id) return;
    setAiRunning(true);
    try {
      await runAIPrioritization(id);
      toast.success("AI analysis complete!");
      reload();
      setTab("ai");
    } catch (err: any) {
      toast.error(err?.response?.data?.detail ?? "AI analysis failed");
    } finally {
      setAiRunning(false);
    }
  };

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading...</div>;
  if (!scan) return <div className="p-8 text-gray-500">Scan not found.</div>;

  const allFindings = findings;
  const iamFindings = findings.filter((f) => f.module === "iam");
  const cisFindings = findings.filter((f) => f.module === "cis");
  const ctFindings = findings.filter((f) => f.module === "cloudtrail");
  const services = [...new Set(findings.map((f) => f.service))].sort();

  const filteredFindings = allFindings.filter((f) => {
    if (filterSev && f.severity !== filterSev) return false;
    if (filterMod && f.module !== filterMod) return false;
    if (filterSvc && !f.service.toLowerCase().includes(filterSvc.toLowerCase())) return false;
    return true;
  });

  const cisAll = scan.cis_results ?? [];
  const cisFiltered = cisFilter === "fail" ? cisAll.filter((r) => r.status === "Fail") : cisAll;
  const cisPassed = cisAll.filter((r) => r.status === "Pass").length;

  let roadmap: { immediate: string[]; this_week: string[]; this_month: string[] } | null = null;
  try { if (scan.ai_roadmap) roadmap = JSON.parse(scan.ai_roadmap); } catch { /* ignore */ }

  let chains: { name: string; finding_titles: string[]; combined_risk: string; scenario: string }[] = [];
  try { if (scan.ai_chains) chains = JSON.parse(scan.ai_chains); } catch { /* ignore */ }

  return (
    <div className="p-8 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to="/scans" className="text-gray-400 hover:text-gray-600"><ArrowLeft size={20} /></Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-gray-800">Scan Results</h1>
          <p className="text-gray-500 text-sm">{scan.account_alias} · {new Date(scan.started_at).toLocaleString()}</p>
        </div>
        {/* Report downloads */}
        {scan.status === "completed" && (
          <div className="flex items-center gap-2">
            <input
              type="text" placeholder="Client name (optional)"
              className="input-sm w-48" value={clientName}
              onChange={(e) => setClientName(e.target.value)}
            />
            <a href={getReportPdfUrl(scan.id, clientName || undefined)} download
              className="btn-secondary flex items-center gap-1 text-sm">
              <Download size={14} /> PDF
            </a>
            <a href={getReportWordUrl(scan.id, clientName || undefined)} download
              className="btn-secondary flex items-center gap-1 text-sm">
              <Download size={14} /> Word
            </a>
          </div>
        )}
      </div>

      {/* Score cards */}
      <div className="grid grid-cols-5 gap-4">
        <div className="card flex flex-col items-center justify-center py-6">
          {scan.security_score != null && scan.grade
            ? <ScoreCircle score={scan.security_score} grade={scan.grade} />
            : <div className="text-4xl font-bold text-gray-300">—</div>}
          <p className="text-xs text-gray-500 mt-2">Security Score</p>
        </div>
        <div className="col-span-4 grid grid-cols-4 gap-4">
          {[
            { label: "Critical", count: scan.critical_count, color: "border-red-200 bg-red-50 text-red-700" },
            { label: "High", count: scan.high_count, color: "border-orange-200 bg-orange-50 text-orange-700" },
            { label: "Medium", count: scan.medium_count, color: "border-amber-200 bg-amber-50 text-amber-700" },
            { label: "Low", count: scan.low_count, color: "border-blue-200 bg-blue-50 text-blue-700" },
          ].map(({ label, count, color }) => (
            <div key={label} onClick={() => { setFilterSev(filterSev === label ? "" : label); setTab("findings"); }}
              className={`card border ${color} flex flex-col items-center justify-center py-6 cursor-pointer hover:scale-[1.02] transition-transform`}>
              <span className="text-4xl font-extrabold">{count}</span>
              <span className="text-sm font-medium mt-1">{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* AI Summary banner */}
      {scan.ai_summary && (
        <div className="card p-4 border-l-4 border-[#E8651A] bg-orange-50">
          <p className="text-sm font-semibold text-gray-700 mb-1">AI Executive Summary</p>
          <p className="text-sm text-gray-600 leading-relaxed">{scan.ai_summary}</p>
        </div>
      )}

      {/* Tab bar */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-1">
          {TABS.map(({ id: tid, label }) => (
            <button key={tid} onClick={() => setTab(tid)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                tab === tid
                  ? "border-[#E8651A] text-[#E8651A]"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}>
              {label}
              {tid === "cis" && scan.cis_score != null && (
                <span className="ml-1.5 text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded-full">
                  {scan.cis_score}%
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ── TAB: All Findings ─────────────────────────────────────────────── */}
      {tab === "findings" && (
        <>
          <div className="card p-4 flex flex-wrap gap-3 items-center">
            <Filter size={16} className="text-gray-400" />
            <select className="input-sm" value={filterSev} onChange={(e) => setFilterSev(e.target.value)}>
              <option value="">All Severities</option>
              {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
            </select>
            <select className="input-sm" value={filterMod} onChange={(e) => setFilterMod(e.target.value)}>
              <option value="">All Modules</option>
              {["misconfig", "iam", "cis", "cloudtrail"].map((m) => <option key={m}>{m}</option>)}
            </select>
            <select className="input-sm" value={filterSvc} onChange={(e) => setFilterSvc(e.target.value)}>
              <option value="">All Services</option>
              {services.map((s) => <option key={s}>{s}</option>)}
            </select>
            {(filterSev || filterMod || filterSvc) && (
              <button onClick={() => { setFilterSev(""); setFilterMod(""); setFilterSvc(""); }}
                className="text-sm text-[#E8651A] hover:underline">Clear</button>
            )}
            <span className="ml-auto text-sm text-gray-400">{filteredFindings.length} findings</span>
          </div>
          <FindingsTable findings={filteredFindings} expanded={expanded} toggle={toggle} />
        </>
      )}

      {/* ── TAB: IAM ──────────────────────────────────────────────────────── */}
      {tab === "iam" && (
        <div className="space-y-4">
          {/* IAM Summary cards */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: "Root Account Findings", count: iamFindings.filter(f => f.resource_id === "root").length, color: "text-red-600" },
              { label: "No-MFA Users", count: iamFindings.filter(f => f.title.includes("MFA not enabled")).length, color: "text-orange-600" },
              { label: "Old Access Keys", count: iamFindings.filter(f => f.title.includes("days old")).length, color: "text-amber-600" },
              { label: "Policy Issues", count: iamFindings.filter(f => f.module === "iam" && (f.title.includes("Wildcard") || f.title.includes("policy"))).length, color: "text-blue-600" },
            ].map(({ label, count, color }) => (
              <div key={label} className="card p-4 text-center">
                <p className={`text-3xl font-extrabold ${color}`}>{count}</p>
                <p className="text-xs text-gray-500 mt-1">{label}</p>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="px-5 py-3 border-b border-gray-100 font-semibold text-gray-700">
              IAM Findings ({iamFindings.length})
            </div>
            {iamFindings.length === 0
              ? <div className="p-8 text-center text-gray-400">No IAM findings — great job!</div>
              : <FindingsTable findings={iamFindings} expanded={expanded} toggle={toggle} />}
          </div>
        </div>
      )}

      {/* ── TAB: CIS Benchmark ────────────────────────────────────────────── */}
      {tab === "cis" && (
        <div className="space-y-4">
          {cisAll.length === 0 ? (
            <div className="card p-8 text-center text-gray-400">
              No CIS results. Run a scan with the CIS Benchmark module enabled.
            </div>
          ) : (
            <>
              {/* CIS Score */}
              <div className="grid grid-cols-4 gap-4">
                <div className="card p-5 text-center col-span-1">
                  <p className="text-5xl font-extrabold text-[#E8651A]">{scan.cis_score ?? 0}%</p>
                  <p className="text-sm text-gray-500 mt-1">CIS Compliant</p>
                </div>
                <div className="col-span-3 grid grid-cols-3 gap-4">
                  {["iam", "storage", "logging", "monitoring", "networking"].slice(0, 3).map((sec) => {
                    const secResults = cisAll.filter((r) => r.section === sec);
                    const passed = secResults.filter((r) => r.status === "Pass").length;
                    const pct = secResults.length ? Math.round(passed / secResults.length * 100) : 0;
                    return (
                      <div key={sec} className="card p-4">
                        <div className="flex justify-between mb-1">
                          <span className="text-sm font-medium capitalize text-gray-700">{sec}</span>
                          <span className="text-sm font-bold text-gray-800">{pct}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div className={`h-2 rounded-full ${pct >= 80 ? "bg-green-500" : pct >= 50 ? "bg-amber-500" : "bg-red-500"}`}
                            style={{ width: `${pct}%` }} />
                        </div>
                        <p className="text-xs text-gray-400 mt-1">{passed}/{secResults.length} passed</p>
                      </div>
                    );
                  })}
                </div>
              </div>
              {/* Section bars row 2 */}
              <div className="grid grid-cols-2 gap-4">
                {["monitoring", "networking"].map((sec) => {
                  const secResults = cisAll.filter((r) => r.section === sec);
                  const passed = secResults.filter((r) => r.status === "Pass").length;
                  const pct = secResults.length ? Math.round(passed / secResults.length * 100) : 0;
                  return (
                    <div key={sec} className="card p-4">
                      <div className="flex justify-between mb-1">
                        <span className="text-sm font-medium capitalize text-gray-700">{sec}</span>
                        <span className="text-sm font-bold text-gray-800">{pct}%</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className={`h-2 rounded-full ${pct >= 80 ? "bg-green-500" : pct >= 50 ? "bg-amber-500" : "bg-red-500"}`}
                          style={{ width: `${pct}%` }} />
                      </div>
                      <p className="text-xs text-gray-400 mt-1">{passed}/{secResults.length} passed</p>
                    </div>
                  );
                })}
              </div>

              {/* CIS Check table */}
              <div className="card">
                <div className="px-5 py-3 border-b border-gray-100 flex items-center gap-4">
                  <span className="font-semibold text-gray-700">CIS Checks ({cisAll.length})</span>
                  <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer ml-auto">
                    <input type="checkbox" checked={cisFilter === "fail"}
                      onChange={(e) => setCisFilter(e.target.checked ? "fail" : "all")}
                      className="accent-[#E8651A]" />
                    Show failures only
                  </label>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-xs text-gray-400 uppercase border-b border-gray-100">
                        <th className="text-left px-5 py-3 w-20">ID</th>
                        <th className="text-left px-5 py-3">Title</th>
                        <th className="text-left px-5 py-3 w-20">Status</th>
                        <th className="text-left px-5 py-3">Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cisFiltered.map((r) => (
                        <tr key={r.cis_id} className="border-b border-gray-50 hover:bg-gray-50">
                          <td className="px-5 py-3 font-mono text-xs text-gray-500">{r.cis_id}</td>
                          <td className="px-5 py-3 text-gray-800">{r.title}</td>
                          <td className="px-5 py-3">
                            {r.status === "Pass"
                              ? <span className="flex items-center gap-1 text-green-600 text-xs font-medium"><CheckCircle size={14} /> Pass</span>
                              : <span className="flex items-center gap-1 text-red-600 text-xs font-medium"><XCircle size={14} /> Fail</span>}
                          </td>
                          <td className="px-5 py-3 text-xs text-gray-500">{r.evidence}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── TAB: CloudTrail ───────────────────────────────────────────────── */}
      {tab === "cloudtrail" && (
        <div className="space-y-4">
          {/* Upload area */}
          <div className="card p-6">
            <h2 className="font-semibold text-gray-700 mb-2 flex items-center gap-2">
              <Upload size={18} className="text-[#E8651A]" /> Upload CloudTrail Log
            </h2>
            <p className="text-sm text-gray-500 mb-3">
              In AWS Console: <strong>CloudTrail → Event History → Download → JSON</strong>. Then upload the file here.
            </p>
            <input ref={fileRef} type="file" accept=".json" className="hidden" onChange={handleCloudTrailUpload} />
            <button onClick={() => fileRef.current?.click()}
              className="btn-primary flex items-center gap-2" disabled={uploading}>
              {uploading ? <span className="animate-spin">⏳</span> : <Upload size={16} />}
              {uploading ? "Analyzing..." : "Choose CloudTrail JSON"}
            </button>
          </div>

          {/* Results */}
          {scan.cloudtrail_summary && (
            <>
              <div className={`card p-5 border-l-4 ${
                scan.cloudtrail_severity === "Critical" ? "border-red-500 bg-red-50" :
                scan.cloudtrail_severity === "High" ? "border-orange-500 bg-orange-50" :
                "border-blue-400 bg-blue-50"
              }`}>
                <div className="flex items-center gap-3 mb-2">
                  <span className="font-bold text-gray-800">AI Assessment:</span>
                  <SeverityBadge severity={scan.cloudtrail_severity ?? "Info"} />
                  <span className="text-sm text-gray-600 italic">{scan.cloudtrail_assessment}</span>
                </div>
                <p className="text-sm text-gray-700 leading-relaxed">{scan.cloudtrail_summary}</p>
              </div>

              {scan.cloudtrail_actions.length > 0 && (
                <div className="card p-5">
                  <h3 className="font-semibold text-gray-700 mb-3">Immediate Actions</h3>
                  <ul className="space-y-2">
                    {scan.cloudtrail_actions.map((action, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-gray-700">
                        <span className="text-[#E8651A] font-bold mt-0.5">{i + 1}.</span> {action}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {scan.cloudtrail_rule_findings.length > 0 && (
                <div className="card">
                  <div className="px-5 py-3 border-b border-gray-100 font-semibold text-gray-700">
                    Triggered Detection Rules
                  </div>
                  <div className="divide-y divide-gray-50">
                    {scan.cloudtrail_rule_findings.map((rf, i) => (
                      <div key={i} className="px-5 py-3 flex items-center gap-3">
                        <SeverityBadge severity={rf.severity} />
                        <span className="text-sm text-gray-800 flex-1">{rf.title}</span>
                        <span className="text-xs text-gray-400">{rf.count} event{rf.count !== 1 ? "s" : ""}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {ctFindings.length > 0 && (
                <div className="card">
                  <div className="px-5 py-3 border-b border-gray-100 font-semibold text-gray-700">
                    CloudTrail Findings ({ctFindings.length})
                  </div>
                  <FindingsTable findings={ctFindings} expanded={expanded} toggle={toggle} />
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ── TAB: AI Insights ──────────────────────────────────────────────── */}
      {tab === "ai" && (
        <div className="space-y-4">
          <div className="card p-6">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h2 className="font-semibold text-gray-700 flex items-center gap-2">
                  <Brain size={18} className="text-[#E8651A]" /> AI Risk Prioritization
                </h2>
                <p className="text-sm text-gray-500 mt-0.5">
                  Claude AI correlates all findings, identifies risk chains, and generates a prioritized fix roadmap.
                </p>
              </div>
              <button onClick={handleAIAnalysis} disabled={aiRunning || scan.status !== "completed"}
                className="btn-primary flex items-center gap-2">
                {aiRunning ? <span className="animate-spin">⏳</span> : <Brain size={16} />}
                {aiRunning ? "Analyzing..." : "Run AI Analysis"}
              </button>
            </div>
          </div>

          {scan.ai_summary && (
            <div className="card p-5 border-l-4 border-[#E8651A] bg-orange-50">
              <p className="text-sm font-semibold text-gray-700 mb-1">Executive Summary</p>
              <p className="text-sm text-gray-700 leading-relaxed">{scan.ai_summary}</p>
            </div>
          )}

          {roadmap && (
            <div className="card p-5">
              <h3 className="font-semibold text-gray-700 mb-4">Fix Roadmap</h3>
              <div className="grid grid-cols-3 gap-4">
                {([
                  ["Today (Immediate)", roadmap.immediate, "bg-red-50 border-red-200 text-red-800"],
                  ["This Week", roadmap.this_week, "bg-orange-50 border-orange-200 text-orange-800"],
                  ["This Month", roadmap.this_month, "bg-amber-50 border-amber-200 text-amber-800"],
                ] as [string, string[], string][]).map(([label, items, cls]) => (
                  <div key={label} className={`rounded-xl border p-4 ${cls}`}>
                    <p className="font-semibold text-sm mb-3">{label}</p>
                    {items.length === 0
                      ? <p className="text-xs opacity-60">Nothing urgent here</p>
                      : <ul className="space-y-2">
                          {items.map((item, i) => (
                            <li key={i} className="text-xs leading-relaxed">• {item}</li>
                          ))}
                        </ul>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {chains.length > 0 && (
            <div className="card p-5">
              <h3 className="font-semibold text-gray-700 mb-4">Risk Chains</h3>
              <div className="space-y-3">
                {chains.map((chain, i) => (
                  <div key={i} className="border border-red-200 rounded-xl p-4 bg-red-50">
                    <p className="font-semibold text-red-800 mb-1">{chain.name}</p>
                    <p className="text-sm text-red-700 mb-2">{chain.combined_risk}</p>
                    <p className="text-xs text-red-600 italic">Attack scenario: {chain.scenario}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {chain.finding_titles.map((t, j) => (
                        <span key={j} className="text-xs bg-red-200 text-red-800 px-2 py-0.5 rounded-full">{t}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!scan.ai_summary && !roadmap && (
            <div className="card p-12 text-center text-gray-400">
              <Brain size={48} className="mx-auto mb-3 opacity-30" />
              <p>No AI insights yet. Click "Run AI Analysis" above.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Shared Findings Table component
function FindingsTable({
  findings, expanded, toggle,
}: {
  findings: Finding[];
  expanded: Set<string>;
  toggle: (id: string) => void;
}) {
  if (findings.length === 0)
    return <div className="p-8 text-center text-gray-400">No findings.</div>;

  return (
    <div className="card divide-y divide-gray-50 overflow-hidden">
      {findings.map((f) => (
        <div key={f.id}>
          <button onClick={() => toggle(f.id)}
            className="w-full text-left px-5 py-4 flex items-center gap-3 hover:bg-gray-50 transition-colors">
            <SeverityBadge severity={f.severity} />
            <span className="text-xs text-gray-400 w-14 flex-shrink-0">{f.service}</span>
            <span className="flex-1 font-medium text-gray-800 text-sm">{f.title}</span>
            <span className="text-xs text-gray-400 hidden lg:block">{f.region}</span>
            {f.remediation_effort && (
              <span className={`text-xs px-2 py-0.5 rounded-full hidden md:block ${
                f.remediation_effort === "Easy" ? "bg-green-100 text-green-700" :
                f.remediation_effort === "Medium" ? "bg-amber-100 text-amber-700" :
                "bg-red-100 text-red-700"
              }`}>{f.remediation_effort}</span>
            )}
            {expanded.has(f.id) ? <ChevronUp size={15} className="text-gray-400 flex-shrink-0" /> : <ChevronDown size={15} className="text-gray-400 flex-shrink-0" />}
          </button>
          {expanded.has(f.id) && (
            <div className="px-5 pb-5 pt-3 bg-gray-50/60 border-t border-gray-100 space-y-3">
              {f.resource_id && (
                <span className="text-xs bg-gray-200 text-gray-600 px-2 py-1 rounded font-mono">{f.resource_id}</span>
              )}
              {(f.ai_explanation || f.description) && (
                <div>
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">
                    {f.ai_explanation ? "AI Explanation" : "Description"}
                  </p>
                  <p className="text-sm text-gray-700 leading-relaxed">{f.ai_explanation || f.description}</p>
                </div>
              )}
              {f.remediation && (
                <div>
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">Remediation</p>
                  <p className="text-sm text-gray-600 leading-relaxed">{f.remediation}</p>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
