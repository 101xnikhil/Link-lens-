import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Search, ArrowRight, Loader2, AlertCircle, Info } from 'lucide-react';
import { api } from '../services/api';
import { SAMPLE_URLS } from '../components/QuickScanInput';

const SCAN_STEPS = [
  "Validating URL syntax...",
  "Extracting domain and checking Public Suffix List...",
  "Evaluating brand typosquatting heuristics...",
  "Checking homoglyphs and Punycode...",
  "Calculating Shannon entropy...",
  "Generating final security score..."
];

export default function AnalyzerPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [url, setUrl] = useState(searchParams.get('url') || '');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [stepIndex, setStepIndex] = useState(0);

  useEffect(() => {
    const queryUrl = searchParams.get('url');
    if (queryUrl && !isLoading) {
      setUrl(queryUrl);
      executeScan(queryUrl);
    }
  }, [searchParams]);

  useEffect(() => {
    let interval;
    if (isLoading) {
      interval = setInterval(() => {
        setStepIndex((prev) => (prev + 1) % SCAN_STEPS.length);
      }, 400);
    } else {
      setStepIndex(0);
    }
    return () => clearInterval(interval);
  }, [isLoading]);

  const executeScan = async (targetUrl) => {
    const trimmed = (targetUrl || url).trim();
    if (!trimmed) {
      setError("Please enter a URL to analyze.");
      return;
    }

    const lower = trimmed.toLowerCase();
    if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("file:")) {
      setError("Only HTTP and HTTPS links can be analyzed.");
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const report = await api.analyzeUrl(trimmed);
      navigate(`/results/${report.scan_id}`, { state: { scanReport: report } });
    } catch (err) {
      setError(err.message || 'An error occurred while analyzing the URL.');
      setIsLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    executeScan(url);
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-12 space-y-8">
      {/* Header */}
      <div className="space-y-1 text-center sm:text-left border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-white tracking-tight">URL Security Scanner</h1>
        <p className="text-xs text-slate-400">
          Enter any URL to test its domain, structure, and security indicators.
        </p>
      </div>

      {/* Main Form */}
      <div className="p-6 rounded-xl panel space-y-4">
        <form onSubmit={handleSubmit} className="space-y-3">
          <label className="block text-xs font-medium text-slate-300">
            Web Link or Destination URL
          </label>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center rounded-lg bg-slate-900 border border-slate-700 focus-within:border-cyan-500 p-1.5 gap-2">
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (error) setError('');
              }}
              placeholder="e.g., https://paypal-security-verification.xyz/login"
              disabled={isLoading}
              className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-400 focus:outline-none px-3 py-1.5"
            />
            <button
              type="submit"
              disabled={isLoading}
              className="shrink-0 flex items-center justify-center space-x-1.5 px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>Scan URL</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300 text-xs flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </form>

        {/* Step indicator during scan */}
        {isLoading && (
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
            <div className="flex items-center space-x-2 text-xs text-cyan-400 font-mono">
              <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
              <span>{SCAN_STEPS[stepIndex]}</span>
            </div>
            <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
              <div className="bg-cyan-400 h-full w-2/3 animate-pulse rounded-full" />
            </div>
          </div>
        )}

        {/* Sample presets */}
        <div className="pt-4 border-t border-slate-800">
          <p className="text-xs text-slate-400 mb-2">Or select a sample URL to test:</p>
          <div className="flex flex-wrap gap-1.5">
            {SAMPLE_URLS.map((sample) => (
              <button
                key={sample.label}
                type="button"
                onClick={() => {
                  setUrl(sample.url);
                  setError('');
                }}
                className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Info note */}
      <div className="p-4 rounded-lg border border-slate-800 text-xs text-slate-400 flex items-start space-x-2">
        <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          LinkLens evaluates link syntax and reputation offline. It never opens or runs the website, keeping your device safe from malicious downloads or browser exploits.
        </p>
      </div>
    </div>
  );
}
