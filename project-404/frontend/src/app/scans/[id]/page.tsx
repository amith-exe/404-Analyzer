"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";

const API_BASE = "";

type ScanStatus = {
  scan_id: number;
  target_id: number;
  status: string;
  progress: number;
  current_step: string;
  posture_score: number | null;
  started_at: string | null;
  finished_at: string | null;
  target: string | null;
};

type Asset = {
  id: number;
  type: string;
  value: string;
  metadata: Record<string, unknown>;
};

type Endpoint = {
  id: number;
  host: string;
  url: string;
  method: string;
  source: string;
  discovered_via: string;
  requires_auth: string;
  status_code: number | null;
  unauth_status_code: number | null;
  auth_status_code: number | null;
  content_similarity: number | null;
  auth_only_navigation: boolean;
  title: string | null;
};

type Finding = {
  id: number;
  title: string;
  severity: string;
  confidence: string;
  category: string;
  affected_url: string | null;
  evidence: Record<string, unknown>;
  recommendation: string | null;
  fingerprint_hash: string | null;
};

type CompanyContext = {
  source_url: string;
  description_raw: string;
  industry: string;
  business_model: string;
  keywords: string[];
  likely_attack_surface: string[];
  where_to_look_first: string;
  created_at: string;
} | null;

type DiffResponse = {
  previous_scan_id: number | null;
  webhook_sent: boolean;
  summary: {
    counts?: Record<string, number>;
    new_endpoints?: { method: string; url: string }[];
    removed_endpoints?: { method: string; url: string }[];
    status_changes?: { method: string; url: string; from: number | null; to: number | null }[];
    new_findings?: { title: string; severity: string; url: string | null }[];
    removed_findings?: { title: string; severity: string; url: string | null }[];
    context_change?: { changed: boolean; similarity?: number; previous_industry?: string; current_industry?: string };
  } | null;
} | null;

type Schedule = {
  id: number;
  interval: string;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  alert_webhook_url: string | null;
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-yellow-700 text-yellow-100",
  low: "bg-blue-700 text-blue-100",
  info: "bg-gray-700 text-gray-100",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_COLORS[severity] || "bg-gray-700 text-gray-100"}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function PostureScore({ score }: { score: number }) {
  const color = score >= 80 ? "text-green-400" : score >= 50 ? "text-yellow-400" : "text-red-400";
  return (
    <div className="text-center">
      <div className={`text-5xl font-bold ${color}`}>{score.toFixed(0)}</div>
      <div className="text-gray-400 text-sm mt-1">Posture Score</div>
    </div>
  );
}

function EvidenceDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/60" onClick={onClose} />
      <div className="w-full max-w-xl bg-gray-900 border-l border-gray-700 p-6 overflow-y-auto">
        <div className="flex items-start justify-between mb-4">
          <h2 className="text-lg font-bold text-white pr-4">{finding.title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl shrink-0">x</button>
        </div>
        <div className="flex gap-2 mb-4">
          <SeverityBadge severity={finding.severity} />
          <span className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded font-medium">
            confidence: {finding.confidence}
          </span>
          <span className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded font-medium">
            {finding.category}
          </span>
        </div>
        {finding.affected_url && (
          <div className="mb-4">
            <div className="text-xs font-semibold text-gray-400 uppercase mb-1">Affected URL</div>
            <div className="bg-gray-800 rounded px-3 py-2 text-blue-300 text-sm break-all">{finding.affected_url}</div>
          </div>
        )}
        <div className="mb-4">
          <div className="text-xs font-semibold text-gray-400 uppercase mb-1">Evidence</div>
          <pre className="bg-gray-800 rounded px-3 py-2 text-green-300 text-xs overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </div>
        {finding.recommendation && (
          <div className="mb-4">
            <div className="text-xs font-semibold text-gray-400 uppercase mb-1">Recommendation</div>
            <div className="bg-gray-800 rounded px-3 py-2 text-gray-200 text-sm">{finding.recommendation}</div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [context, setContext] = useState<CompanyContext>(null);
  const [changes, setChanges] = useState<DiffResponse>(null);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [tab, setTab] = useState<"summary" | "findings" | "assets" | "endpoints" | "changes" | "monitoring">("summary");
  const [severityFilter, setSeverityFilter] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [error, setError] = useState("");
  const [creatingSchedule, setCreatingSchedule] = useState(false);
  const [scheduleInterval, setScheduleInterval] = useState("daily");
  const [webhookUrl, setWebhookUrl] = useState("");

  const fetchAll = useCallback(async () => {
    try {
      const [s, a, e, f, c, d] = await Promise.all([
        fetch(`${API_BASE}/api/scans/${scanId}`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/assets`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/endpoints`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/findings`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/context`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/changes`).then((r) => r.json()),
      ]);
      setScan(s);
      if (Array.isArray(a)) setAssets(a);
      if (Array.isArray(e)) setEndpoints(e);
      if (Array.isArray(f)) setFindings(f);
      if (c && !c.detail) setContext(c);
      if (d && !d.detail) setChanges(d);
      if (s?.target_id) {
        const sched = await fetch(`${API_BASE}/api/targets/${s.target_id}/schedules`).then((r) => r.json());
        if (Array.isArray(sched)) setSchedules(sched);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
    }
  }, [scanId]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  useEffect(() => {
    if (!scan) return;
    if (scan.status === "running" || scan.status === "pending") {
      const t = setTimeout(fetchAll, 3000);
      return () => clearTimeout(t);
    }
  }, [scan, fetchAll]);

  const filteredFindings = severityFilter ? findings.filter((f) => f.severity === severityFilter) : findings;

  const findingCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const topRisks = useMemo(() => {
    const order = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };
    return [...findings].sort((a, b) => (order[b.severity as keyof typeof order] || 0) - (order[a.severity as keyof typeof order] || 0)).slice(0, 5);
  }, [findings]);

  async function createSchedule() {
    if (!scan) return;
    setCreatingSchedule(true);
    try {
      const body = {
        interval: scheduleInterval,
        enabled: true,
        ...(webhookUrl ? { alert_webhook_url: webhookUrl } : {}),
      };
      const res = await fetch(`${API_BASE}/api/scans/${scan.scan_id}/schedules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        throw new Error("Failed to create schedule");
      }
      await fetchAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create schedule");
    } finally {
      setCreatingSchedule(false);
    }
  }

  async function toggleSchedule(id: number, enabled: boolean) {
    await fetch(`${API_BASE}/api/schedules/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    await fetchAll();
  }

  if (error) {
    return (
      <div className="bg-red-900/40 border border-red-700 rounded-lg px-4 py-3 text-red-300">
        {error}
      </div>
    );
  }

  if (!scan) {
    return <div className="text-gray-400">Loading...</div>;
  }

  return (
    <div>
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Scan #{scan.scan_id}</h1>
          <div className="text-gray-400 text-sm mt-1">{scan.target}</div>
        </div>
        <div className="text-right">
          <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
            scan.status === "completed" ? "bg-green-800 text-green-200" :
            scan.status === "failed" ? "bg-red-800 text-red-200" :
            "bg-yellow-800 text-yellow-200"
          }`}>
            {scan.status}
          </span>
          <div className="text-gray-500 text-xs mt-1">{scan.current_step}</div>
        </div>
      </div>

      {(scan.status === "running" || scan.status === "pending") && (
        <div className="mb-6">
          <div className="flex justify-between text-xs text-gray-400 mb-1">
            <span>{scan.current_step}</span>
            <span>{scan.progress}%</span>
          </div>
          <div className="bg-gray-800 rounded-full h-2">
            <div className="bg-blue-500 h-2 rounded-full transition-all duration-500" style={{ width: `${scan.progress}%` }} />
          </div>
        </div>
      )}

      <div className="flex gap-3 mb-6 flex-wrap">
        <a href={`${API_BASE}/api/scans/${scanId}/export/endpoints.csv`} className="bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-semibold px-3 py-2 rounded">
          Export Endpoints CSV
        </a>
        <a href={`${API_BASE}/api/scans/${scanId}/export/findings.csv`} className="bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-semibold px-3 py-2 rounded">
          Export Findings CSV
        </a>
        <a href={`${API_BASE}/api/scans/${scanId}/report.html`} target="_blank" className="bg-blue-700 hover:bg-blue-600 text-white text-xs font-semibold px-3 py-2 rounded">
          Open HTML Report
        </a>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {scan.posture_score != null && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <PostureScore score={scan.posture_score} />
          </div>
        )}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
          <div className="text-3xl font-bold text-white">{assets.length}</div>
          <div className="text-gray-400 text-sm mt-1">Assets</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
          <div className="text-3xl font-bold text-white">{endpoints.length}</div>
          <div className="text-gray-400 text-sm mt-1">Endpoints</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
          <div className="text-3xl font-bold text-white">{findings.length}</div>
          <div className="text-gray-400 text-sm mt-1">Findings</div>
        </div>
      </div>

      <div className="flex border-b border-gray-800 mb-6 flex-wrap">
        {(["summary", "findings", "assets", "endpoints", "changes", "monitoring"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === t ? "border-blue-500 text-blue-400" : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {t === "monitoring" ? "Monitoring" : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === "summary" && (
        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <h2 className="text-white font-semibold mb-3">Top Risks</h2>
            {topRisks.length === 0 ? (
              <div className="text-gray-500 text-sm">No findings yet.</div>
            ) : (
              <ul className="space-y-2">
                {topRisks.map((risk) => (
                  <li key={risk.id} className="text-sm text-gray-200 flex items-center gap-2">
                    <SeverityBadge severity={risk.severity} />
                    <span>{risk.title}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <h2 className="text-white font-semibold mb-3">Company Context</h2>
            {!context ? (
              <div className="text-gray-500 text-sm">Context not available yet.</div>
            ) : (
              <div className="space-y-3 text-sm">
                <div className="text-gray-300">{context.description_raw}</div>
                <div className="text-gray-400">Industry: <span className="text-gray-200">{context.industry || "-"}</span></div>
                <div className="text-gray-400">Business Model: <span className="text-gray-200">{context.business_model || "-"}</span></div>
                <div className="text-gray-400">Keywords: <span className="text-gray-200">{context.keywords?.join(", ") || "-"}</span></div>
                <div>
                  <div className="text-gray-400 mb-1">Likely Attack Surface</div>
                  <ul className="list-disc ml-5 text-gray-200 space-y-1">
                    {(context.likely_attack_surface || []).map((item) => <li key={item}>{item}</li>)}
                  </ul>
                </div>
                <div className="bg-gray-800 rounded p-3 text-gray-200">
                  <div className="text-xs text-gray-400 uppercase mb-1">Where To Look First</div>
                  {context.where_to_look_first}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "findings" && (
        <div>
          {findings.length > 0 && (
            <div className="flex gap-2 mb-4 flex-wrap">
              {SEVERITY_ORDER.filter((s) => findingCounts[s]).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(severityFilter === s ? "" : s)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold border transition-colors ${
                    severityFilter === s ? `${SEVERITY_COLORS[s]} border-transparent` : "border-gray-700 text-gray-400 hover:text-white"
                  }`}
                >
                  {s.toUpperCase()} ({findingCounts[s]})
                </button>
              ))}
            </div>
          )}
          <div className="space-y-2">
            {filteredFindings.length === 0 ? (
              <div className="text-gray-500 text-center py-10">No findings.</div>
            ) : (
              filteredFindings.map((f) => (
                <div
                  key={f.id}
                  className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex items-start gap-3 cursor-pointer hover:border-gray-600 transition-colors"
                  onClick={() => setSelectedFinding(f)}
                >
                  <div className="mt-0.5 shrink-0"><SeverityBadge severity={f.severity} /></div>
                  <div className="flex-1 min-w-0">
                    <div className="text-white text-sm font-medium">{f.title}</div>
                    {f.affected_url && <div className="text-gray-500 text-xs truncate mt-0.5">{f.affected_url}</div>}
                  </div>
                  <div className="text-gray-600 text-xs shrink-0">{f.category}</div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {tab === "assets" && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-800"><th className="text-left py-2 pr-4">Type</th><th className="text-left py-2 pr-4">Value</th><th className="text-left py-2">Metadata</th></tr></thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                  <td className="py-2 pr-4"><span className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded">{a.type}</span></td>
                  <td className="py-2 pr-4 text-blue-300">{a.value}</td>
                  <td className="py-2 text-gray-500 text-xs">{JSON.stringify(a.metadata)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "endpoints" && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-800">
                <th className="text-left py-2 pr-3">Status</th>
                <th className="text-left py-2 pr-3">Method</th>
                <th className="text-left py-2 pr-3">URL</th>
                <th className="text-left py-2 pr-3">Source</th>
                <th className="text-left py-2 pr-3">Discovery</th>
                <th className="text-left py-2">Auth Delta</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep) => (
                <tr key={ep.id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                  <td className="py-2 pr-3 text-xs">{ep.status_code ?? "-"}</td>
                  <td className="py-2 pr-3 text-gray-400 text-xs">{ep.method}</td>
                  <td className="py-2 pr-3 text-blue-300 text-xs max-w-xs truncate">{ep.url}</td>
                  <td className="py-2 pr-3 text-gray-400 text-xs">{ep.source}</td>
                  <td className="py-2 pr-3 text-xs">
                    <span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded">{ep.discovered_via}</span>
                    {ep.auth_only_navigation && <span className="ml-2 text-orange-400">auth-only</span>}
                  </td>
                  <td className="py-2 text-xs text-gray-400">
                    {ep.unauth_status_code ?? "-"} / {ep.auth_status_code ?? "-"}
                    {ep.content_similarity != null && <span className="ml-2">sim {Math.round(ep.content_similarity * 100)}%</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "changes" && (
        <div className="space-y-5">
          {!changes?.summary ? (
            <div className="text-gray-500">No previous scan to diff against.</div>
          ) : (
            <>
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                <h2 className="text-white font-semibold mb-2">Change Counts</h2>
                <pre className="text-xs text-green-300">{JSON.stringify(changes.summary.counts || {}, null, 2)}</pre>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                <h2 className="text-white font-semibold mb-2">Context Change</h2>
                <pre className="text-xs text-gray-300">{JSON.stringify(changes.summary.context_change || {}, null, 2)}</pre>
              </div>
            </>
          )}
        </div>
      )}

      {tab === "monitoring" && (
        <div className="space-y-5">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <h2 className="text-white font-semibold mb-3">Create Schedule</h2>
            <div className="flex flex-wrap gap-3 items-center">
              <select value={scheduleInterval} onChange={(e) => setScheduleInterval(e.target.value)} className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white">
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
              <input
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="Webhook URL (optional)"
                className="min-w-72 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white"
              />
              <button onClick={createSchedule} disabled={creatingSchedule} className="bg-blue-700 hover:bg-blue-600 disabled:bg-blue-900 rounded px-4 py-2 text-sm text-white font-semibold">
                {creatingSchedule ? "Creating..." : "Create"}
              </button>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <h2 className="text-white font-semibold mb-3">Existing Schedules</h2>
            {schedules.length === 0 ? (
              <div className="text-gray-500 text-sm">No schedules yet.</div>
            ) : (
              <div className="space-y-2">
                {schedules.map((s) => (
                  <div key={s.id} className="flex items-center justify-between bg-gray-800 rounded px-3 py-2">
                    <div className="text-sm text-gray-200">
                      #{s.id} {s.interval} | next: {s.next_run_at || "-"} | webhook: {s.alert_webhook_url || "-"}
                    </div>
                    <button onClick={() => toggleSchedule(s.id, !s.enabled)} className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-white">
                      {s.enabled ? "Disable" : "Enable"}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {selectedFinding && <EvidenceDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </div>
  );
}
