import React, { useState } from 'react';
import { AlertCircle, CheckCircle, ChevronDown, ChevronUp } from 'lucide-react';
import { getSeverityConfig } from '../utils/formatters';

export default function IndicatorCard({ indicator }) {
  const [expanded, setExpanded] = useState(false);
  const isDetected = indicator.status === 'detected';
  const severityConfig = getSeverityConfig(indicator.severity);

  return (
    <div
      className={`rounded-lg border transition-colors ${
        isDetected
          ? 'bg-slate-900/90 border-slate-700/80'
          : 'bg-slate-900/30 border-slate-800/60'
      }`}
    >
      <div
        onClick={() => setExpanded(!expanded)}
        className="p-3.5 flex items-center justify-between cursor-pointer space-x-3 select-none"
      >
        <div className="flex items-center space-x-3 min-w-0">
          <div className="shrink-0">
            {isDetected ? (
              <AlertCircle className={`w-4 h-4 ${
                indicator.severity === 'critical' ? 'text-red-400' :
                indicator.severity === 'high' ? 'text-orange-400' :
                'text-amber-400'
              }`} />
            ) : (
              <CheckCircle className="w-4 h-4 text-emerald-500/70" />
            )}
          </div>
          <div className="min-w-0">
            <div className="flex items-center space-x-2">
              <h4 className="text-xs font-semibold text-slate-200 truncate">
                {indicator.name}
              </h4>
              <span className={`text-[10px] uppercase font-mono px-1.5 py-0.2 rounded border ${severityConfig.badge}`}>
                {indicator.severity}
              </span>
              {isDetected && indicator.weight > 0 && (
                <span className="text-[10px] font-mono text-slate-400">
                  +{indicator.weight} pts
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400 truncate mt-0.5">
              {indicator.explanation}
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <span
            className={`text-[11px] px-2 py-0.5 rounded font-medium ${
              isDetected
                ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
            }`}
          >
            {isDetected ? 'Flagged' : 'Passed'}
          </span>
          <button className="text-slate-400 hover:text-slate-200">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-3.5 pt-1 text-xs space-y-2 border-t border-slate-800 text-slate-300">
          <p className="text-slate-400 leading-relaxed text-[11px]">
            {indicator.explanation}
          </p>
          {indicator.recommended_action && (
            <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-[11px] text-slate-300">
              <strong className="text-slate-200">Advice: </strong>
              <span>{indicator.recommended_action}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
