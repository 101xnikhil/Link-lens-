import React from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="border-t border-slate-800/80 bg-[#090d14] text-slate-400 text-xs mt-auto">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-200">LinkLens</span>
            <span className="text-slate-400">— AI & Heuristic URL Security</span>
          </div>

          <div className="flex items-center space-x-4 text-slate-400">
            <Link to="/" className="hover:text-slate-200">Home</Link>
            <Link to="/dashboard" className="hover:text-slate-200">Dashboard</Link>
            <Link to="/analyzer" className="hover:text-slate-200">Scanner</Link>
            <Link to="/about" className="hover:text-slate-200">About</Link>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t border-slate-800/60 flex flex-col sm:flex-row items-center justify-between text-slate-400 text-[11px] gap-2">
          <p>
            Note: Automated URL analysis evaluates observable structural signals. Low observed risk does not guarantee 100% safety.
          </p>
          <p>© {new Date().getFullYear()} LinkLens • B.Tech CSE Mini-Project</p>
        </div>
      </div>
    </footer>
  );
}
