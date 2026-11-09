import React, { useState } from 'react';

export default function ThreatIntelligencePanel({ scanResult }) {
  const [copied, setCopied] = useState(false);

  if (!scanResult || !scanResult.threat_intelligence) {
    return null;
  }

  const { feed, infrastructure, visual, advanced_heuristics, dom_exfiltration, takedown_notice } = scanResult.threat_intelligence;

  const handleCopyTakedown = () => {
    if (takedown_notice && takedown_notice.report_body) {
      navigator.clipboard.writeText(takedown_notice.report_body);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    }
  };

  return (
    <div className="mt-6 bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-2xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
        <h3 className="text-lg font-bold flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></span>
          Advanced Threat Intelligence & Zero-Day Telemetry
        </h3>
        <span className="text-xs uppercase tracking-wider px-3 py-1 rounded-full bg-slate-800 text-slate-300 font-semibold">
          KavachTI Engine v2.1
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        
        {/* 1. Threat Feed Status */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Blacklist & Feed Status</h4>
          {feed?.is_blacklisted ? (
            <div className="text-red-400 font-bold text-sm">
              🚨 Blacklisted ({feed.feed_name})
              <p className="text-xs text-slate-300 font-normal mt-1">Threat Type: {feed.threat_type}</p>
            </div>
          ) : (
            <div className="text-green-400 font-semibold text-sm">
              ✅ Clean across public feeds
            </div>
          )}
        </div>

        {/* 2. Infrastructure & ASN */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Network Infrastructure</h4>
          <p className="text-sm font-medium">IP: <span className="text-slate-300">{infrastructure?.resolved_ip || 'N/A'}</span></p>
          <p className="text-sm font-medium">ASN: <span className="text-slate-300">{infrastructure?.asn_description || 'Unknown'}</span></p>
          <p className="text-xs text-slate-400 mt-1">Country: {infrastructure?.country || 'N/A'}</p>
        </div>

        {/* 3. Visual Phishing & pHash */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Visual Brand Impersonation</h4>
          {visual?.visual_phishing_detected ? (
            <div className="text-amber-400 font-bold text-sm">
              ⚠️ Visual Clone Detected!
              {visual.matched_brands?.map((b, idx) => (
                <p key={idx} className="text-xs text-slate-300 font-normal mt-1">
                  Matches {b.brand} ({b.visual_similarity_score}% similarity)
                </p>
              ))}
            </div>
          ) : (
            <div className="text-slate-300 text-sm">
              No visual template clones matched.
            </div>
          )}
        </div>

      </div>

      {/* Advanced Heuristics & Exfiltration Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        
        <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
          <h4 className="text-xs font-semibold text-amber-500 uppercase tracking-wider mb-2">Typosquatting & Homographs</h4>
          {advanced_heuristics?.deception_flags?.length > 0 ? (
            <ul className="list-disc list-inside text-xs space-y-1 text-slate-300">
              {advanced_heuristics.deception_flags.map((flag, idx) => (
                <li key={idx}>{flag}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-400">No homograph or typosquatting flags found.</p>
          )}
        </div>

        <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
          <h4 className="text-xs font-semibold text-red-500 uppercase tracking-wider mb-2">DOM Exfiltration & Credential Traps</h4>
          {dom_exfiltration?.indicators?.length > 0 ? (
            <ul className="list-disc list-inside text-xs space-y-1 text-red-300">
              {dom_exfiltration.indicators.map((ind, idx) => (
                <li key={idx}>{ind}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-400">No Telegram/Discord webhooks or harvesting inputs found.</p>
          )}
        </div>

      </div>

      {/* Automated Takedown Notice Box */}
      {takedown_notice && (
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h4 className="text-sm font-bold text-slate-200">Automated CERT-In & Host Abuse Takedown Notice</h4>
              <p className="text-xs text-slate-400">Ready-to-send complaint draft compiled with resolved IP, ASN, and forensics.</p>
            </div>
            <button
              onClick={handleCopyTakedown}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95"
            >
              {copied ? 'Copied to Clipboard!' : 'Copy Takedown Notice'}
            </button>
          </div>
          <pre className="bg-slate-900 text-slate-300 p-3 rounded text-xs font-mono overflow-x-auto max-h-40 border border-slate-800">
            {takedown_notice.report_body}
          </pre>
        </div>
      )}

    </div>
  );
}