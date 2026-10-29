import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Menu, X, ArrowUpRight } from 'lucide-react';
import { api } from '../services/api';

export default function Navbar() {
  const location = useLocation();
  const [backendOnline, setBackendOnline] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    let isMounted = true;
    api.checkHealth()
      .then(() => { if (isMounted) setBackendOnline(true); })
      .catch(() => { if (isMounted) setBackendOnline(false); });
    return () => { isMounted = false; };
  }, [location.pathname]);

  const navLinks = [
    { name: 'Home', path: '/' },
    { name: 'Dashboard', path: '/dashboard' },
    { name: 'Scan URL', path: '/analyzer' },
    { name: 'About', path: '/about' },
  ];

  const isActive = (path) => {
    if (path === '/' && location.pathname === '/') return true;
    if (path !== '/' && location.pathname.startsWith(path)) return true;
    return false;
  };

  return (
    <header className="border-b border-slate-800/80 bg-[#0c1017]/95 sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
            <span className="font-semibold text-white tracking-tight text-base">
              Link<span className="text-cyan-400">Lens</span>
            </span>
          </Link>

          {/* Nav links */}
          <nav className="hidden md:flex items-center space-x-1">
            {navLinks.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  isActive(link.path)
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {link.name}
              </Link>
            ))}
          </nav>

          {/* Right items */}
          <div className="hidden md:flex items-center space-x-3">
            {/* Backend status */}
            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
              <span className={`w-1.5 h-1.5 rounded-full ${backendOnline ? 'bg-emerald-400' : backendOnline === false ? 'bg-red-400' : 'bg-amber-400'}`} />
              <span>{backendOnline ? 'Ready' : backendOnline === false ? 'Backend Offline' : 'Connecting'}</span>
            </div>

            <Link
              to="/analyzer"
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-cyan-500 text-slate-950 hover:bg-cyan-400 transition-colors"
            >
              Analyze Link
            </Link>
          </div>

          {/* Mobile button */}
          <div className="md:hidden flex items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-slate-800 bg-[#0e131d] px-4 py-3 space-y-1">
          {navLinks.map((link) => (
            <Link
              key={link.path}
              to={link.path}
              onClick={() => setMobileMenuOpen(false)}
              className={`block px-3 py-2 rounded-md text-sm ${
                isActive(link.path) ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              {link.name}
            </Link>
          ))}
          <div className="pt-2">
            <Link
              to="/analyzer"
              onClick={() => setMobileMenuOpen(false)}
              className="block w-full text-center px-3 py-2 rounded-lg text-xs font-semibold bg-cyan-500 text-slate-950"
            >
              Analyze Link
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
