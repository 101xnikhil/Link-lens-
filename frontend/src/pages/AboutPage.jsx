import React from 'react';
import { Shield, Lock, AlertTriangle, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function AboutPage() {
  const tiers = [
    { range: '0–24', level: 'Low Observed Risk', color: 'border-emerald-500/30 text-emerald-400', desc: 'No recognized malicious indicators detected. Appears consistent with normal web destinations.' },
    { range: '25–49', level: 'Moderate Observed Risk', color: 'border-amber-500/30 text-amber-400', desc: 'Anomalies detected, such as unencrypted HTTP, link shorteners, or non-standard ports. Caution advised.' },
    { range: '50–74', level: 'High Observed Risk', color: 'border-orange-500/30 text-orange-400', desc: 'Suspicious patterns detected, such as brand lookalike domain strings, excessive subdomains, or high credential keyword density.' },
    { range: '75–100', level: 'Critical Observed Risk', color: 'border-red-500/30 text-red-400', desc: 'Severe threat indicators identified, such as executable downloads, Punycode homoglyphs, or verified threat database matches.' },
  ];

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-10 space-y-10">
      {/* Title */}
      <div className="space-y-2 border-b border-slate-800 pb-4">
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">About LinkLens</h1>
        <p className="text-xs sm:text-sm text-slate-400">
          AI & Heuristic URL Security Analyzer — B.Tech Computer Science Engineering Mini-Project
        </p>
      </div>

      {/* Project Overview */}
      <div className="p-5 rounded-xl panel space-y-3">
        <h2 className="text-sm font-semibold text-white">Project Objective</h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          LinkLens was built to address the increasing sophistication of modern web phishing and social engineering lures. While traditional advice instructed users to rely on the browser's "lock icon", today over 80% of phishing pages use free SSL certificates. LinkLens inspects structural anomalies, typosquatting heuristics, and domain characteristics to help users assess risk before clicking.
        </p>
      </div>

      {/* Zero-Fetch Architecture */}
      <div className="p-5 rounded-xl panel space-y-3">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Lock className="w-4 h-4" />
          <h2 className="text-sm font-semibold text-white">Safe Zero-Fetch Inspection</h2>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          The backend parses URL components, Public Suffix List rules, and known threat lists without sending HTTP requests to the target URL. This prevents Server-Side Request Forgery (SSRF) and protects the server and user from executing malicious payloads.
        </p>
      </div>

      {/* Scoring Tiers */}
      <div className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Risk Scoring Convention</h2>
          <p className="text-xs text-slate-400">Scores range from 0 to 100, where higher scores indicate greater observed risk.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {tiers.map((t) => (
            <div key={t.range} className={`p-4 rounded-xl border bg-slate-900/60 ${t.color}`}>
              <div className="flex items-center justify-between mb-1.5 font-medium">
                <span className="text-xs font-semibold">{t.level}</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-850 border border-slate-700">{t.range}</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{t.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="pt-2">
        <Link
          to="/analyzer"
          className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors"
        >
          <span>Try URL Scanner</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  );
}
