import React from 'react';

export default function StatsCard({ title, value, subtitle, icon: Icon, colorClass = "text-cyan-400" }) {
  return (
    <div className="p-4 rounded-xl panel transition-colors hover:border-slate-700">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-slate-400">{title}</p>
        <Icon className={`w-4 h-4 ${colorClass}`} />
      </div>
      <div className="mt-2 flex items-baseline space-x-2">
        <span className="text-2xl font-bold font-mono text-white tracking-tight">{value}</span>
      </div>
      {subtitle && (
        <p className="text-[11px] text-slate-400 mt-1">{subtitle}</p>
      )}
    </div>
  );
}
