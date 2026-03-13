"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type ScanStatus = {
  scan_id: number;
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
  requires_auth: string;
  status_code: number | null;
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
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl shrink-0">✕</button>
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
        {finding.fingerprint_hash && (
          <div className="text-xs text-gray-600 mt-2">Fingerprint: {finding.fingerprint_hash}</div>
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
  const [tab, setTab] = useState<"assets" | "endpoints" | "findings">("findings");
  const [severityFilter, setSeverityFilter] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [error, setError] = useState("");

  const fetchAll = useCallback(async () => {
    try {
      const [s, a, e, f] = await Promise.all([
        fetch(`${API_BASE}/api/scans/${scanId}`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/assets`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/endpoints`).then((r) => r.json()),
        fetch(`${API_BASE}/api/scans/${scanId}/findings`).then((r) => r.json()),
      ]);
      setScan(s);
      if (Array.isArray(a)) setAssets(a);
      if (Array.isArray(e)) setEndpoints(e);
      if (Array.isArray(f)) setFindings(f);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
    }
  }, [scanId]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  // Poll while scan is running
  useEffect(() => {
    if (!scan) return;
    if (scan.status === "running" || scan.status === "pending") {
      const t = setTimeout(fetchAll, 3000);
      return () => clearTimeout(t);
    }
  }, [scan, fetchAll]);

  const filteredFindings = severityFilter
    ? findings.filter((f) => f.severity === severityFilter)
    : findings;

  const findingCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  if (error) {
    return (
      <div className="bg-red-900/40 border border-red-700 rounded-lg px-4 py-3 text-red-300">
        {error}
      </div>
    );
  }

  if (!scan) {
    return <div className="text-gray-400">Loading…</div>;
  }

  return (
    <div>
      {/* Header */}
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

      {/* Progress bar */}
      {(scan.status === "running" || scan.status === "pending") && (
        <div className="mb-6">
          <div className="flex justify-between text-xs text-gray-400 mb-1">
            <span>{scan.current_step}</span>
            <span>{scan.progress}%</span>
          </div>
          <div className="bg-gray-800 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Summary cards */}
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

      {/* Severity breakdown */}
      {findings.length > 0 && (
        <div className="flex gap-2 mb-6 flex-wrap">
          {SEVERITY_ORDER.filter((s) => findingCounts[s]).map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(severityFilter === s ? "" : s)}
              className={`px-3 py-1 rounded-full text-xs font-semibold border transition-colors ${
                severityFilter === s ? SEVERITY_COLORS[s] + " border-transparent" : "border-gray-700 text-gray-400 hover:text-white"
              }`}
            >
              {s.toUpperCase()} ({findingCounts[s]})
            </button>
          ))}
          {severityFilter && (
            <button onClick={() => setSeverityFilter("")} className="text-xs text-gray-500 hover:text-gray-300">
              clear filter ✕
            </button>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-800 mb-6">
        {(["findings", "assets", "endpoints"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === t
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
            {t === "findings" && findings.length > 0 && <span className="ml-1 text-xs text-gray-500">({findings.length})</span>}
            {t === "assets" && assets.length > 0 && <span className="ml-1 text-xs text-gray-500">({assets.length})</span>}
            {t === "endpoints" && endpoints.length > 0 && <span className="ml-1 text-xs text-gray-500">({endpoints.length})</span>}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "findings" && (
        <div className="space-y-2">
          {filteredFindings.length === 0 ? (
            <div className="text-gray-500 text-center py-10">
              {scan.status === "completed" ? "No findings." : "Scan in progress…"}
            </div>
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
                  {f.affected_url && (
                    <div className="text-gray-500 text-xs truncate mt-0.5">{f.affected_url}</div>
                  )}
                </div>
                <div className="text-gray-600 text-xs shrink-0">{f.category}</div>
              </div>
            ))
          )}
        </div>
      )}

      {tab === "assets" && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-800">
                <th className="text-left py-2 pr-4">Type</th>
                <th className="text-left py-2 pr-4">Value</th>
                <th className="text-left py-2">Metadata</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                  <td className="py-2 pr-4">
                    <span className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded">{a.type}</span>
                  </td>
                  <td className="py-2 pr-4 text-blue-300">{a.value}</td>
                  <td className="py-2 text-gray-500 text-xs">
                    {a.metadata.live !== undefined && (
                      <span className={a.metadata.live ? "text-green-400" : "text-gray-600"}>
                        {a.metadata.live ? "live" : "offline"}
                      </span>
                    )}
                    {typeof a.metadata.provider === "string" && a.metadata.provider && <span className="ml-2">{a.metadata.provider}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {assets.length === 0 && (
            <div className="text-gray-500 text-center py-10">No assets yet.</div>
          )}
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
                <th className="text-left py-2 pr-3">Title</th>
                <th className="text-left py-2">Auth</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep) => (
                <tr key={ep.id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                  <td className="py-2 pr-3">
                    <span className={`text-xs ${
                      ep.status_code && ep.status_code < 300 ? "text-green-400" :
                      ep.status_code && ep.status_code < 400 ? "text-yellow-400" :
                      "text-red-400"
                    }`}>{ep.status_code || "-"}</span>
                  </td>
                  <td className="py-2 pr-3 text-gray-400 text-xs">{ep.method}</td>
                  <td className="py-2 pr-3 text-blue-300 text-xs max-w-xs truncate">{ep.url}</td>
                  <td className="py-2 pr-3 text-gray-400 text-xs max-w-xs truncate">{ep.title || "-"}</td>
                  <td className="py-2 text-xs">
                    <span className={
                      ep.requires_auth === "yes" ? "text-orange-400" :
                      ep.requires_auth === "no" ? "text-gray-500" : "text-gray-600"
                    }>{ep.requires_auth}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {endpoints.length === 0 && (
            <div className="text-gray-500 text-center py-10">No endpoints yet.</div>
          )}
        </div>
      )}

      {/* Evidence drawer */}
      {selectedFinding && (
        <EvidenceDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
