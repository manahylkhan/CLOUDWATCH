import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listAccounts, startScan, getScanStatus, AWSAccount } from "../api";
import toast from "react-hot-toast";
import { Play, CheckCircle, AlertCircle } from "lucide-react";

const MODULES = [
  { id: "misconfig", label: "Misconfiguration Scanner", desc: "S3, EC2, RDS, Lambda, VPC security checks" },
  { id: "iam", label: "IAM Auditor", desc: "Root account, users, roles, policies, password policy" },
  { id: "cis", label: "CIS Benchmark v2.0", desc: "50+ industry-standard compliance checks" },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [accounts, setAccounts] = useState<AWSAccount[]>([]);
  const [selectedAccount, setSelectedAccount] = useState("");
  const [selectedModules, setSelectedModules] = useState(["misconfig", "iam", "cis"]);
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [task, setTask] = useState("Preparing scan...");

  useEffect(() => {
    listAccounts().then((accs) => {
      setAccounts(accs);
      if (accs.length > 0) setSelectedAccount(accs[0].id);
    }).catch(() => toast.error("Failed to load accounts"));
  }, []);

  useEffect(() => {
    if (!scanId) return;
    const interval = setInterval(async () => {
      try {
        const status = await getScanStatus(scanId);
        setProgress(status.progress);
        setTask(status.current_task ?? "Running...");
        if (status.status === "completed") {
          clearInterval(interval);
          toast.success("Scan complete!");
          navigate(`/scans/${scanId}`);
        } else if (status.status === "failed") {
          clearInterval(interval);
          toast.error(`Scan failed: ${status.current_task}`);
          setScanning(false);
          setScanId(null);
        }
      } catch { clearInterval(interval); setScanning(false); }
    }, 2000);
    return () => clearInterval(interval);
  }, [scanId, navigate]);

  const toggleModule = (id: string) =>
    setSelectedModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]);

  const handleStart = async () => {
    if (!selectedAccount) return toast.error("Select an AWS account");
    if (selectedModules.length === 0) return toast.error("Select at least one module");
    setScanning(true);
    try {
      const res = await startScan({ account_id: selectedAccount, modules: selectedModules });
      setScanId(res.scan_id);
      toast.success("Scan started!");
    } catch (err: any) {
      toast.error(err?.response?.data?.detail ?? "Failed to start scan");
      setScanning(false);
    }
  };

  if (scanning && scanId) {
    return (
      <div className="p-8 flex flex-col items-center justify-center min-h-[60vh] gap-6">
        <div className="w-28 h-28 relative">
          <svg className="w-full h-full" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="50" fill="none" stroke="#e5e7eb" strokeWidth="8" />
            <circle cx="60" cy="60" r="50" fill="none" stroke="#E8651A" strokeWidth="8"
              strokeDasharray="314" strokeDashoffset={314 - (progress / 100) * 314}
              strokeLinecap="round" className="transition-all duration-500"
              transform="rotate(-90 60 60)" />
          </svg>
          <span className="absolute inset-0 flex items-center justify-center text-2xl font-bold text-gray-700">
            {progress}%
          </span>
        </div>
        <div className="text-center">
          <h2 className="text-xl font-bold text-gray-800">Scanning AWS Account</h2>
          <p className="text-gray-500 mt-1 text-sm animate-pulse">{task}</p>
        </div>
        <div className="w-80 bg-gray-200 rounded-full h-2">
          <div className="bg-[#E8651A] h-2 rounded-full transition-all duration-500" style={{ width: `${progress}%` }} />
        </div>
        <p className="text-xs text-gray-400">This may take a few minutes depending on account size.</p>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-800">New Scan</h1>
        <p className="text-gray-500 text-sm mt-1">Configure and launch an AWS security scan</p>
      </div>

      {accounts.length === 0 ? (
        <div className="card p-8 text-center">
          <AlertCircle className="mx-auto text-amber-400 mb-3" size={40} />
          <p className="font-medium text-gray-700">No AWS accounts connected</p>
          <p className="text-sm text-gray-500 mt-1">
            Go to <a href="/settings" className="text-[#E8651A] hover:underline">Settings</a> to add an account first.
          </p>
        </div>
      ) : (
        <>
          <div className="card p-6 space-y-3">
            <h2 className="font-semibold text-gray-700">AWS Account</h2>
            <select className="input" value={selectedAccount}
              onChange={(e) => setSelectedAccount(e.target.value)}>
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.alias} ({a.account_id}) — {a.default_region}
                </option>
              ))}
            </select>
          </div>

          <div className="card p-6 space-y-4">
            <h2 className="font-semibold text-gray-700">Scan Modules</h2>
            {MODULES.map(({ id, label, desc }) => (
              <label key={id} className="flex items-start gap-3 cursor-pointer group p-3 rounded-lg hover:bg-gray-50 transition-colors">
                <input type="checkbox" checked={selectedModules.includes(id)}
                  onChange={() => toggleModule(id)} className="mt-0.5 accent-[#E8651A]" />
                <div className="flex-1">
                  <p className="font-medium text-gray-800 group-hover:text-[#E8651A] transition-colors">{label}</p>
                  <p className="text-sm text-gray-500">{desc}</p>
                </div>
                {selectedModules.includes(id) && <CheckCircle size={16} className="text-[#E8651A] mt-0.5 flex-shrink-0" />}
              </label>
            ))}
            <div className="p-3 rounded-lg bg-gray-50 opacity-60">
              <div className="flex items-start gap-3">
                <input type="checkbox" disabled className="mt-0.5" />
                <div>
                  <p className="font-medium text-gray-700">CloudTrail Analyzer</p>
                  <p className="text-sm text-gray-400">Upload a CloudTrail JSON file after scanning in the Results page → CloudTrail tab</p>
                </div>
              </div>
            </div>
          </div>

          <button onClick={handleStart} disabled={scanning || selectedModules.length === 0}
            className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-base">
            <Play size={18} /> Start Security Scan
          </button>
        </>
      )}
    </div>
  );
}
