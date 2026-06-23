import { useEffect, useState } from "react";
import { connectAWS, listAccounts, deleteAccount, getRequiredPolicy, AWSAccount } from "../api";
import toast from "react-hot-toast";
import { Trash2, CheckCircle, Copy } from "lucide-react";

export default function Settings() {
  const [accounts, setAccounts] = useState<AWSAccount[]>([]);
  const [form, setForm] = useState({
    alias: "",
    access_key: "",
    secret_key: "",
    region: "us-east-1",
    scan_all_regions: true,
  });
  const [policy, setPolicy] = useState<object | null>(null);
  const [testing, setTesting] = useState(false);
  const [showPolicy, setShowPolicy] = useState(false);

  const REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
  ];

  useEffect(() => {
    listAccounts().then(setAccounts).catch(() => {});
    getRequiredPolicy().then(setPolicy).catch(() => {});
  }, []);

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    setTesting(true);
    try {
      await connectAWS(form);
      toast.success("AWS account connected successfully!");
      setForm({ alias: "", access_key: "", secret_key: "", region: "us-east-1", scan_all_regions: true });
      listAccounts().then(setAccounts);
    } catch (err: any) {
      toast.error(err?.response?.data?.detail ?? "Connection failed. Check your credentials.");
    } finally {
      setTesting(false);
    }
  };

  const handleDelete = async (id: string, alias: string) => {
    if (!confirm(`Remove account "${alias}"?`)) return;
    try {
      await deleteAccount(id);
      toast.success("Account removed");
      setAccounts((prev) => prev.filter((a) => a.id !== id));
    } catch {
      toast.error("Failed to remove account");
    }
  };

  const copyPolicy = () => {
    navigator.clipboard.writeText(JSON.stringify(policy, null, 2));
    toast.success("Policy copied to clipboard");
  };

  return (
    <div className="p-8 max-w-3xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-gray-800">Settings</h1>
        <p className="text-gray-500 text-sm mt-1">Manage AWS accounts and configuration</p>
      </div>

      {/* Add Account */}
      <div className="card p-6">
        <h2 className="font-semibold text-gray-700 mb-4">Add AWS Account</h2>
        <form onSubmit={handleConnect} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">Account Alias</label>
              <input
                className="input"
                placeholder="e.g. Production"
                value={form.alias}
                onChange={(e) => setForm({ ...form, alias: e.target.value })}
                required
              />
            </div>
            <div>
              <label className="label">Default Region</label>
              <select
                className="input"
                value={form.region}
                onChange={(e) => setForm({ ...form, region: e.target.value })}
              >
                {REGIONS.map((r) => <option key={r}>{r}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="label">AWS Access Key ID</label>
            <input
              className="input font-mono"
              placeholder="AKIA..."
              value={form.access_key}
              onChange={(e) => setForm({ ...form, access_key: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="label">AWS Secret Access Key</label>
            <input
              className="input font-mono"
              type="password"
              placeholder="••••••••••••••••••••••••••••••••••••••••"
              value={form.secret_key}
              onChange={(e) => setForm({ ...form, secret_key: e.target.value })}
              required
            />
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="all-regions"
              checked={form.scan_all_regions}
              onChange={(e) => setForm({ ...form, scan_all_regions: e.target.checked })}
            />
            <label htmlFor="all-regions" className="text-sm text-gray-600">Scan all enabled regions</label>
          </div>
          <button type="submit" className="btn-primary flex items-center gap-2" disabled={testing}>
            {testing ? (
              <><span className="animate-spin">⏳</span> Validating...</>
            ) : (
              <><CheckCircle size={16} /> Connect & Validate</>
            )}
          </button>
        </form>
      </div>

      {/* Configured Accounts */}
      {accounts.length > 0 && (
        <div className="card">
          <div className="px-6 py-4 border-b border-gray-100">
            <h2 className="font-semibold text-gray-700">Connected Accounts</h2>
          </div>
          {accounts.map((a) => (
            <div key={a.id} className="flex items-center justify-between px-6 py-4 border-b border-gray-50 last:border-0">
              <div>
                <p className="font-medium text-gray-800">{a.alias}</p>
                <p className="text-xs text-gray-400">Account ID: {a.account_id} · {a.default_region}</p>
                {a.last_scan_at && (
                  <p className="text-xs text-gray-400">Last scan: {new Date(a.last_scan_at).toLocaleString()}</p>
                )}
              </div>
              <button onClick={() => handleDelete(a.id, a.alias)} className="text-red-400 hover:text-red-600 transition-colors">
                <Trash2 size={16} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Required IAM Policy */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold text-gray-700">Required IAM Policy</h2>
          <div className="flex gap-2">
            <button onClick={() => setShowPolicy(!showPolicy)} className="btn-secondary text-sm">
              {showPolicy ? "Hide" : "Show"} Policy
            </button>
            {policy && (
              <button onClick={copyPolicy} className="btn-secondary text-sm flex items-center gap-1">
                <Copy size={14} /> Copy
              </button>
            )}
          </div>
        </div>
        <p className="text-sm text-gray-500 mb-3">
          Create an IAM user in your AWS account, attach this read-only policy, then use its credentials above.
          CLOUDWATCH will never modify any AWS resources.
        </p>
        {showPolicy && policy && (
          <pre className="bg-gray-900 text-green-400 text-xs p-4 rounded-lg overflow-auto max-h-80">
            {JSON.stringify(policy, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
