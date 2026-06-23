import axios from "axios";

const api = axios.create({ baseURL: "http://localhost:8001" });

export interface AWSAccount {
  id: string;
  alias: string;
  account_id: string;
  default_region: string;
  scan_all_regions: boolean;
  created_at: string;
  last_scan_at: string | null;
}

export interface CISResult {
  cis_id: string;
  title: string;
  status: "Pass" | "Fail" | "NA";
  evidence: string;
  remediation: string;
  section: string;
}

export interface Scan {
  id: string;
  account_alias: string;
  account_id: string;
  status: "running" | "completed" | "failed";
  progress: number;
  current_task: string | null;
  security_score: number | null;
  grade: string | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  ai_summary: string | null;
  ai_roadmap: string | null;
  ai_chains: string | null;
  modules_run: string;
  cis_results: CISResult[] | null;
  cis_score: number | null;
  cloudtrail_summary: string | null;
  cloudtrail_severity: string | null;
  cloudtrail_assessment: string | null;
  cloudtrail_actions: string[];
  cloudtrail_rule_findings: { title: string; severity: string; count: number }[];
  started_at: string;
  completed_at: string | null;
}

export interface Finding {
  id: string;
  scan_id: string;
  module: string;
  service: string;
  resource_id: string | null;
  resource_arn: string | null;
  region: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  title: string;
  description: string | null;
  ai_explanation: string | null;
  remediation: string | null;
  remediation_effort: "Easy" | "Medium" | "Complex" | null;
  cis_check_id: string | null;
  is_false_positive: boolean;
}

// AWS Accounts
export const connectAWS = (data: {
  alias: string; access_key: string; secret_key: string;
  region: string; scan_all_regions: boolean;
}) => api.post("/api/aws/connect", data).then((r) => r.data);

export const listAccounts = () => api.get<AWSAccount[]>("/api/aws/accounts").then((r) => r.data);
export const deleteAccount = (id: string) => api.delete(`/api/aws/accounts/${id}`).then((r) => r.data);
export const getRequiredPolicy = () => api.get("/api/aws/policy").then((r) => r.data);

// Scans
export const startScan = (data: { account_id: string; modules: string[] }) =>
  api.post("/api/scans/start", data).then((r) => r.data);
export const getScanStatus = (scanId: string) =>
  api.get<Scan>(`/api/scans/${scanId}/status`).then((r) => r.data);
export const getScan = (scanId: string) =>
  api.get<Scan>(`/api/scans/${scanId}`).then((r) => r.data);
export const getScanFindings = (scanId: string, params?: { severity?: string; module?: string; service?: string }) =>
  api.get<Finding[]>(`/api/scans/${scanId}/findings`, { params }).then((r) => r.data);
export const listScans = () => api.get<Scan[]>("/api/scans/").then((r) => r.data);

// CloudTrail
export const analyzeCloudTrail = (scanId: string, file: File) => {
  const form = new FormData();
  form.append("file", file);
  return api.post(`/api/cloudtrail/${scanId}/analyze`, form, {
    headers: { "Content-Type": "multipart/form-data" },
  }).then((r) => r.data);
};

// AI
export const runAIPrioritization = (scanId: string) =>
  api.post(`/api/ai/${scanId}/prioritize`).then((r) => r.data);

// Reports
export const getReportPdfUrl = (scanId: string, clientName?: string) => {
  const params = clientName ? `?client_name=${encodeURIComponent(clientName)}` : "";
  return `http://localhost:8001/api/reports/${scanId}/pdf${params}`;
};
export const getReportWordUrl = (scanId: string, clientName?: string) => {
  const params = clientName ? `?client_name=${encodeURIComponent(clientName)}` : "";
  return `http://localhost:8001/api/reports/${scanId}/word${params}`;
};

export default api;
