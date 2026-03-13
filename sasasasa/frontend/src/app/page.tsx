"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function HomePage() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [cookie, setCookie] = useState("");
  const [authHeader, setAuthHeader] = useState("");
  const [maxDepth, setMaxDepth] = useState(2);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const body: Record<string, unknown> = {
        url,
        scan_config: { max_depth: maxDepth },
      };
      if (cookie || authHeader) {
        body.auth_config = {
          ...(cookie ? { cookie_header: cookie } : {}),
          ...(authHeader ? { authorization_header: authHeader } : {}),
        };
      }
      const res = await fetch(`${API_BASE}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create scan");
      }
      const data = await res.json();
      router.push(`/scans/${data.scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-3xl font-bold text-white mb-2">New Scan</h1>
      <p className="text-gray-400 mb-8">
        Enter a target URL to enumerate subdomains, crawl endpoints, and detect security issues.
      </p>

      <form onSubmit={handleSubmit} className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Target URL <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Cookie Header <span className="text-gray-500 text-xs">(optional, for authenticated crawl)</span>
          </label>
          <input
            type="text"
            value={cookie}
            onChange={(e) => setCookie(e.target.value)}
            placeholder="session=abc123; csrf=xyz"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Authorization Header <span className="text-gray-500 text-xs">(optional)</span>
          </label>
          <input
            type="text"
            value={authHeader}
            onChange={(e) => setAuthHeader(e.target.value)}
            placeholder="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Max Crawl Depth
          </label>
          <select
            value={maxDepth}
            onChange={(e) => setMaxDepth(Number(e.target.value))}
            className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {[1, 2, 3, 4, 5].map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
        </div>

        {error && (
          <div className="bg-red-900/40 border border-red-700 rounded-lg px-4 py-3 text-red-300 text-sm">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-900 disabled:cursor-not-allowed text-white font-semibold rounded-lg px-6 py-3 transition-colors"
        >
          {loading ? "Starting scan…" : "Start Scan"}
        </button>
      </form>

      <div className="mt-10 bg-gray-900 border border-gray-800 rounded-lg p-5">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Sample Config</h2>
        <pre className="text-xs text-gray-300 overflow-x-auto">{JSON.stringify({
          url: "http://localhost:3000",
          scan_config: { max_depth: 2 },
          auth_config: { cookie_header: "session=<your-session-cookie>" }
        }, null, 2)}</pre>
      </div>
    </div>
  );
}
