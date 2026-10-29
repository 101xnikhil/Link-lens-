import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowRight, AlertCircle, Loader2 } from 'lucide-react';

export const SAMPLE_URLS = [
  { label: "Legitimate", url: "https://www.wikipedia.org/wiki/Cybersecurity" },
  { label: "Brand Spoofing", url: "http://paypal-security-update-account.com/verify" },
  { label: "Raw IP Target", url: "http://192.168.1.100/admin/login.php" },
  { label: "Shortened Link", url: "https://bit.ly/secure-login-portal-392" },
  { label: "Punycode Link", url: "https://xn--e1afmkfd.xn--p1ai/signin" }
];

export default function QuickScanInput({ onScanSubmit, isLoading = false, initialUrl = "" }) {
  const [url, setUrl] = useState(initialUrl);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    setError("");

    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a link to check.");
      return;
    }

    if (trimmed.length > 2048) {
      setError("URL is too long (over 2048 characters).");
      return;
    }

    const lower = trimmed.toLowerCase();
    if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("file:")) {
      setError("Only HTTP and HTTPS links can be analyzed.");
      return;
    }

    if (onScanSubmit) {
      onScanSubmit(trimmed);
    } else {
      navigate(`/analyzer?url=${encodeURIComponent(trimmed)}`);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit}>
        <div className="flex items-center rounded-xl bg-slate-900 border border-slate-700 focus-within:border-cyan-500 transition-colors p-1.5 shadow-sm">
          <div className="pl-3 pr-2 text-slate-400">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (error) setError("");
            }}
            placeholder="Paste a link to check (e.g., https://example.com/login)..."
            disabled={isLoading}
            className="w-full bg-transparent text-slate-100 placeholder-slate-400 text-sm focus:outline-none px-2 py-1.5"
          />
          <button
            type="submit"
            disabled={isLoading}
            className="shrink-0 flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors disabled:opacity-50"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Checking...</span>
              </>
            ) : (
              <>
                <span>Check Link</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>

        {error && (
          <div className="mt-2 text-xs text-red-400 flex items-center space-x-1.5 px-1">
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </form>

      {/* Clean sample presets */}
      <div className="mt-3 flex flex-wrap items-center gap-1.5 justify-center sm:justify-start text-xs text-slate-400">
        <span className="text-[11px] text-slate-400">Try sample:</span>
        {SAMPLE_URLS.map((sample) => (
          <button
            key={sample.label}
            type="button"
            onClick={() => {
              setUrl(sample.url);
              setError("");
            }}
            className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[11px] transition-colors"
          >
            {sample.label}
          </button>
        ))}
      </div>
    </div>
  );
}
