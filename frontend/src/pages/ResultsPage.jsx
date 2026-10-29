import React, { useState, useEffect } from 'react';
import { useParams, useLocation, Link, useNavigate } from 'react-router-dom';
import {
  Shield, AlertCircle, CheckCircle, Copy, Check, Download,
  ArrowLeft, RefreshCw, Lock, Unlock, ExternalLink
} from 'lucide-react';

import { api } from '../services/api';
import RiskGauge from '../components/RiskGauge';
import IndicatorCard from '../components/IndicatorCard';
import { getRiskLevelConfig, formatDate } from '../utils/formatters';

export default function ResultsPage() {
  const { scanId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();

  const [report, setReport] = useState(location.state?.scanReport || null);
  const [isLoading, setIsLoading] = useState(!report);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [filterDetectedOnly, setFilterDetectedOnly] = useState(false);

  useEffect(() => {
    if (!report && scanId) {
      setIsLoading(true);
      api.getScanById(scanId)
        .then((data) => {
          setReport(data);
          setIsLoading(false);
        })
        .catch((err) => {
          setError(err.message || 'Failed to retrieve scan report.');
          setIsLoading(false);
        });
    }
  }, [scanId]);

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-20 text-center space-y-3">
        <RefreshCw className="w-6 h-6 animate-spin mx-auto text-cyan-400" />
        <p className="text-sm text-slate-300">Loading analysis report...</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-md mx-auto px-4 py-20 text-center space-y-4">
        <AlertCircle className="w-8 h-8 text-red-400 mx-auto" />
        <h2 className="text-lg font-bold text-white">Report Not Found</h2>
        <p className="text-xs text-slate-400">{error || "This scan ID does not exist in local history."}</p>
        <Link
          to="/analyzer"
          className="inline-flex items-center space-x-1 px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-medium text-xs"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Analyze a new URL</span>
        </Link>
      </div>
    );
  }

  const {
    submitted_url, normalized_url, hostname, domain, risk_score,
    risk_level, summary, indicators = [], url_details = {},
    recommendations = [], threat_intelligence = {}, analyzed_at
  } = report;

  const riskConfig = getRiskLevelConfig(risk_level);

  const handleCopyReport = () => {
    const text = `LinkLens Scan Report\nURL: ${submitted_url}\nRisk Score: ${risk_score}/100 (${riskConfig.label})\nSummary: ${summary}\nDate: ${formatDate(analyzed_at)}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `linklens-${report.scan_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredIndicators = indicators.filter((ind) => {
    if (filterDetectedOnly && ind.status !== 'detected') return false;
    return true;
  });

  const detectedCount = indicators.filter((i) => i.status === 'detected').length;

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => navigate('/analyzer')}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            title="Back to scanner"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h1 className="text-sm font-semibold text-white truncate max-w-lg font-mono" title={submitted_url}>
              {submitted_url}
            </h1>
            <p className="text-[11px] text-slate-400">
              Scanned on {formatDate(analyzed_at)}
            </p>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center space-x-2 shrink-0">
          <button
            onClick={handleCopyReport}
            className="px-3 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-colors flex items-center space-x-1.5"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            onClick={handleExportJson}
            className="px-3 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-colors flex items-center space-x-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
          <Link
            to="/analyzer"
            className="px-3 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors"
          >
            Scan Another
          </Link>
        </div>
      </div>

      {/* Main Score Box */}
      <div className="p-6 rounded-xl panel space-y-4">
        <RiskGauge score={risk_score} riskLevel={risk_level} size="lg" />

        <div className="pt-2 border-t border-slate-800/80">
          <h2 className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1">
            Analysis Summary
          </h2>
          <p className="text-sm text-slate-200 leading-relaxed">
            {summary}
          </p>
          <p className="text-xs text-slate-400 mt-1">
            Identified <strong className="text-slate-300">{detectedCount}</strong> flagged signal{detectedCount === 1 ? '' : 's'} across URL structure, domain characteristics, and reputation feeds.
          </p>
        </div>
      </div>

      {/* Actionable recommendations */}
      {recommendations.length > 0 && (
        <div className="p-5 rounded-xl panel space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Safety Recommendations
          </h3>
          <ul className="space-y-2">
            {recommendations.map((rec, idx) => (
              <li key={idx} className="flex items-start space-x-2 text-xs text-slate-300 leading-relaxed">
                <span className="text-cyan-400 font-bold shrink-0 mt-0.5">•</span>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* URL Specifications Table */}
      <div className="p-5 rounded-xl panel space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
          URL Details
        </h3>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Hostname</span>
            <span className="font-mono text-slate-200 truncate block mt-0.5" title={hostname}>{hostname}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Domain</span>
            <span className="font-mono text-slate-200 truncate block mt-0.5">{domain || 'None (IP)'}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Protocol</span>
            <span className="font-mono text-slate-200 flex items-center space-x-1 mt-0.5">
              {url_details.scheme === 'https' ? (
                <span className="text-emerald-400">HTTPS (Encrypted)</span>
              ) : (
                <span className="text-amber-400">HTTP (Unencrypted)</span>
              )}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Raw IP Address</span>
            <span className="font-mono text-slate-200 mt-0.5 block">
              {url_details.has_ip ? 'Yes (Numeric IP)' : 'No (Domain)'}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Length</span>
            <span className="font-mono text-slate-200 mt-0.5 block">{url_details.url_length} chars</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Subdomains</span>
            <span className="font-mono text-slate-200 mt-0.5 block">{url_details.subdomain_count}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Shannon Entropy</span>
            <span className="font-mono text-slate-200 mt-0.5 block">{url_details.entropy} bits</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Reputation Feed</span>
            <span className="font-mono text-slate-200 mt-0.5 block uppercase text-[10px]">
              {threat_intelligence.status || 'not_configured'}
            </span>
          </div>
        </div>
      </div>

      {/* Indicators Checklist */}
      <div className="p-5 rounded-xl panel space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Security Indicators ({indicators.length})
            </h3>
            <p className="text-[11px] text-slate-400">Click any indicator to view detailed explanation</p>
          </div>
          <button
            onClick={() => setFilterDetectedOnly(!filterDetectedOnly)}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              filterDetectedOnly
                ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            {filterDetectedOnly ? 'Showing Flagged Only' : 'Show Flagged Only'}
          </button>
        </div>

        <div className="space-y-2">
          {filteredIndicators.map((ind) => (
            <IndicatorCard key={ind.id} indicator={ind} />
          ))}
        </div>
      </div>
    </div>
  );
}
