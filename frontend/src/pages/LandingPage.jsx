import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, ArrowRight, CheckCircle, AlertTriangle, Search, Lock, ExternalLink } from 'lucide-react';
import QuickScanInput from '../components/QuickScanInput';

export default function LandingPage() {
  const steps = [
    {
      num: '1',
      title: 'Enter any URL',
      desc: 'Paste a suspicious link from an email, SMS, or message.'
    },
    {
      num: '2',
      title: 'Structural Inspection',
      desc: 'LinkLens checks the domain, brand lookalikes, encryption, and redirect paths.'
    },
    {
      num: '3',
      title: 'Get an Honest Report',
      desc: 'Review the 0–100 risk score and clear guidance on whether to proceed.'
    }
  ];

  const features = [
    {
      title: 'Brand Impersonation',
      desc: 'Detects fake domains copying brands like PayPal, Google, Apple, or banks with typosquatting.'
    },
    {
      title: 'Punycode & Homoglyphs',
      desc: 'Catches deceptive domains that look identical to normal letters using foreign Cyrillic or Greek symbols.'
    },
    {
      title: 'Raw IP & Port Exploits',
      desc: 'Flags links using numeric IP addresses or weird port numbers instead of verified domain names.'
    },
    {
      title: 'Credential Lures',
      desc: 'Identifies URLs stuffed with account-recovery, login, or verification keywords designed to steal passwords.'
    },
    {
      title: 'Shortened Link Flagging',
      desc: 'Detects bit.ly, tinyurl, and other redirect shorteners that hide where the user is actually going.'
    },
    {
      title: 'Zero-Fetch Safety',
      desc: 'LinkLens never visits or executes user-submitted links, so testing a link will never trigger downloads.'
    }
  ];

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-12 sm:py-20 space-y-20">
      {/* Hero Section */}
      <section className="text-center space-y-6">
        <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-white max-w-3xl mx-auto leading-tight">
          Check if a web link is safe before you click
        </h1>
        <p className="text-sm sm:text-base text-slate-400 max-w-xl mx-auto leading-relaxed">
          LinkLens inspects link structure, brand impersonation, and hidden destinations to spot phishing and malicious URLs.
        </p>

        {/* Search input */}
        <div className="pt-2">
          <QuickScanInput />
        </div>

        <p className="text-xs text-slate-400">
          LinkLens never visits or downloads from the links you enter. Your tests are private and safe.
        </p>
      </section>

      {/* How It Works */}
      <section className="space-y-6">
        <div className="border-b border-slate-800 pb-3">
          <h2 className="text-base font-semibold text-white">How it works</h2>
          <p className="text-xs text-slate-400">Three simple steps to evaluate any link</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {steps.map((s) => (
            <div key={s.num} className="p-4 rounded-xl panel space-y-2">
              <span className="inline-block w-6 h-6 rounded-full bg-slate-800 text-cyan-400 text-xs font-mono font-bold text-center leading-6">
                {s.num}
              </span>
              <h3 className="text-sm font-semibold text-white">{s.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Features Grid */}
      <section className="space-y-6">
        <div className="border-b border-slate-800 pb-3">
          <h2 className="text-base font-semibold text-white">What LinkLens checks</h2>
          <p className="text-xs text-slate-400">15+ structural and heuristic security signals</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((f) => (
            <div key={f.title} className="p-4 rounded-xl panel space-y-1.5">
              <h3 className="text-xs font-semibold text-slate-200">{f.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Realistic Limitations Notice */}
      <section className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 text-xs text-slate-400 space-y-2">
        <div className="flex items-center space-x-2 text-slate-200 font-medium">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>Understanding Automated Link Analysis</span>
        </div>
        <p className="leading-relaxed">
          Automated URL analysis evaluates observable patterns, known threat feeds, and domain characteristics. A "Low Risk" result means no suspicious indicators were detected—it is not a 100% guarantee that a website is benign. Always check the sender's identity and never enter passwords on unfamiliar domains.
        </p>
      </section>

      {/* Simple CTA */}
      <section className="text-center space-y-3 pt-4">
        <h2 className="text-xl font-semibold text-white">Ready to inspect a link?</h2>
        <p className="text-xs text-slate-400">Paste any URL into the scanner or check stored scans in the dashboard.</p>
        <div className="flex items-center justify-center space-x-3 pt-2">
          <Link
            to="/analyzer"
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors"
          >
            Open URL Scanner
          </Link>
          <Link
            to="/dashboard"
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
          >
            View Scan Dashboard
          </Link>
        </div>
      </section>
    </div>
  );
}
