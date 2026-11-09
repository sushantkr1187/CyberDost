import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ShieldCheck, Lock, Globe, Terminal, Activity,
  ThumbsUp, ThumbsDown, Search, KeyRound, FileCode2, AlertTriangle,
  CheckCircle2, XCircle, RefreshCw, Copy, Check, ExternalLink, Server, Eye
} from 'lucide-react';
import ThreatIntelligencePanel from './components/ThreatIntelligencePanel';


const PRESET_SCENARIOS = [
  {
    id: 'sbi-phish',
    label: 'Fake SBI KYC Portal',
    badge: 'CRITICAL PHISH',
    url: 'https://on1inesbi-kyc-pan-update.xyz/login',
    summary: {
      target_url: 'https://on1inesbi-kyc-pan-update.xyz/login',
      composite_risk_score: 96,
      verdict: 'CRITICAL_THREAT',
      layer_breakdown: {
        pki_trust_risk: 65,
        domain_deception_risk: 95,
        sandbox_behavioral_risk: 95,
        web_posture_risk: 80
      }
    },
    domain_analysis: {
      is_legitimate_brand: false,
      decoded_hostname: 'on1inesbi-kyc-pan-update.xyz',
      impersonated_brand: 'onlinesbi.sbi',
      deception_reasons: [
        "Homoglyph substitution ('1' for 'l') impersonating 'onlinesbi.sbi'",
        'High-abuse TLD detected (.xyz) registered < 24 hours ago'
      ],
      domain_risk_score: 95
    },
    pki_certificate_audit: {
      subject_cn: 'on1inesbi-kyc-pan-update.xyz',
      issuer_cn: "Let's Encrypt E5 (DV - NRD < 24h)",
      serial_hex: '04a98bc1920fe192837465a1b2c3d4e5',
      sha256_fingerprint: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      days_remaining: 89,
      os_trusted: true,
      crypto_audit: { type: 'ECDSA-secp256r1', vulnerable: false, entropy_bits: 256 },
      warnings: [
        'Newly issued DV certificate (< 24h old) on financial lookalike domain',
        'No Organization (O) or Extended Validation (EV) identity attributes present'
      ],
      pki_risk_score: 65
    },
    web_security_posture: {
      security_grade: 'F',
      server_banner: 'nginx/1.18.0 (Ubuntu)',
      missing_headers: ['CSP', 'HSTS', 'X-Frame-Options'],
      exposed_sensitive_paths: ['/.env', '/.git/config'],
      posture_risk_score: 80
    },
    sandbox_behavioral_analysis: {
      page_title: 'State Bank of India - Instant PAN & KYC Update',
      visual_analysis: {
        computed_phash: 'f0e8c8d8b2a69492',
        closest_brand_template: 'SBI NetBanking Portal',
        visual_similarity_pct: 94.2,
        visual_clone_alert: true
      },
      behavioral_flags: [
        'Contains 1 password input field and 2 OTP/PIN fields',
        'Telegram Bot Exfiltration Endpoint: https://api.telegram.org/bot692104:AAE.../sendMessage',
        'Disables context menu (oncontextmenu=false) to block DOM inspection',
        'High visual similarity (94.2%) to SBI NetBanking Portal'
      ],
      sandbox_risk_score: 95
    },
    threat_intelligence: {
      feed: { is_blacklisted: true, feed_name: 'URLhaus (abuse.ch)', threat_type: 'phishing', threat_status: 'online' },
      infrastructure: { resolved_ip: '104.21.92.11', asn: 13335, asn_description: 'CLOUDFLARENET', country: 'US' },
      visual: { visual_phishing_detected: true, matched_brands: [{ brand: 'State Bank of India (SBI)', visual_similarity_score: 94.2 }] },
      advanced_heuristics: { deception_flags: ["Homoglyph substitution", "Lure tokens in domain"] },
      dom_exfiltration: { indicators: ["Telegram Bot API Exfiltration", "Sensitive Indian KYC / OTP / PIN harvesting input fields"] },
      takedown_notice: {
        recipient_suggestion: 'incident@cert-in.org.in, abuse@cloudflare.com',
        subject: '[URGENT] Phishing Takedown Request - https://on1inesbi-kyc-pan-update.xyz/login',
        report_body: 'URGENT ABUSE & PHISHING TAKEDOWN REQUEST\n\nMalicious URL: https://on1inesbi-kyc-pan-update.xyz/login\nResolved IP: 104.21.92.11\nTargeted Brand: State Bank of India'
      }
    }
  },
  {
    id: 'emudhra-ca',
    label: 'Compromised CA MITM (CVE-2026-111943)',
    badge: 'PKI COMPROMISE',
    url: 'https://accounts.google.com.auth-gateway-in.com/o/oauth2',
    summary: {
      target_url: 'https://accounts.google.com.auth-gateway-in.com/o/oauth2',
      composite_risk_score: 100,
      verdict: 'CRITICAL_THREAT',
      layer_breakdown: {
        pki_trust_risk: 100,
        domain_deception_risk: 85,
        sandbox_behavioral_risk: 90,
        web_posture_risk: 45
      }
    },
    domain_analysis: {
      is_legitimate_brand: false,
      decoded_hostname: 'accounts.google.com.auth-gateway-in.com',
      impersonated_brand: 'google.com',
      deception_reasons: [
        "Deceptive brand keyword inclusion: embeds 'google.com' as deep subdomain",
        'Excessive subdomain nesting (4 levels) used to mask root domain'
      ],
      domain_risk_score: 85
    },
    pki_certificate_audit: {
      subject_cn: 'accounts.google.com',
      issuer_cn: 'EM OV TLS CA – G3B',
      serial_hex: 'c7c41efe92d825f05eae841a4a82c1',
      sha256_fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      days_remaining: 42,
      os_trusted: false,
      crypto_audit: {
        type: 'ECC-secp384r1',
        vulnerable: true,
        recovered_scalar: 4,
        entropy_bits: 2.0
      },
      warnings: [
        "CRITICAL (CVE-2026-111943): Chains to compromised/revoked CA 'EM OV TLS CA – G3B'",
        'CRITICAL: Private key recovered via small-scalar search (d=4, < 8 bits entropy)',
        'OS/Browser Trust Store rejected chain: Distrusted by Mozilla NSS, Chrome, Apple & Microsoft'
      ],
      pki_risk_score: 100
    },
    web_security_posture: {
      security_grade: 'C',
      server_banner: 'cloudflare',
      missing_headers: ['CSP', 'X-Frame-Options'],
      exposed_sensitive_paths: [],
      posture_risk_score: 45
    },
    sandbox_behavioral_analysis: {
      page_title: 'Sign in - Google Accounts',
      visual_analysis: {
        computed_phash: 'f8f8f0e0c0808002',
        closest_brand_template: 'Google Workspace Sign-In',
        visual_similarity_pct: 96.8,
        visual_clone_alert: true
      },
      behavioral_flags: [
        'Adversary-in-the-Middle (AiTM) reverse proxy session cookie interception detected',
        'Cross-Origin POST Exfiltration: https://auth-gateway-in.com/collect/oauth_token',
        'High visual similarity (96.8%) to Google Workspace Sign-In'
      ],
      sandbox_risk_score: 90
    }
  },
  {
    id: 'sbi-legit',
    label: 'Verified Legitimate SBI Portal',
    badge: 'SAFE VERIFIED',
    url: 'https://onlinesbi.sbi/',
    summary: {
      target_url: 'https://onlinesbi.sbi/',
      composite_risk_score: 4,
      verdict: 'SAFE_VERIFIED',
      layer_breakdown: {
        pki_trust_risk: 0,
        domain_deception_risk: 0,
        sandbox_behavioral_risk: 0,
        web_posture_risk: 0
      }
    },
    domain_analysis: {
      is_legitimate_brand: true,
      decoded_hostname: 'onlinesbi.sbi',
      impersonated_brand: null,
      deception_reasons: [],
      domain_risk_score: 0
    },
    pki_certificate_audit: {
      subject_cn: 'www.onlinesbi.sbi',
      issuer_cn: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1',
      serial_hex: '0a81f92c837e910293847561029384',
      sha256_fingerprint: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
      days_remaining: 248,
      os_trusted: true,
      crypto_audit: { type: 'ECC-secp384r1', vulnerable: false, entropy_bits: 384 },
      warnings: [],
      pki_risk_score: 0
    },
    web_security_posture: {
      security_grade: 'A+',
      server_banner: 'Hidden (Hardened)',
      missing_headers: [],
      exposed_sensitive_paths: [],
      posture_risk_score: 0
    },
    sandbox_behavioral_analysis: {
      page_title: 'State Bank of India - Personal Banking',
      visual_analysis: {
        computed_phash: 'f0e8c8d8b2a69496',
        closest_brand_template: 'SBI NetBanking Portal (Verified Origin)',
        visual_similarity_pct: 100.0,
        visual_clone_alert: false
      },
      behavioral_flags: [
        'Verified Extended Validation (EV) origin matching canonical brand domain',
        'Zero external form actions or unauthorized third-party exfiltration hooks'
      ],
      sandbox_risk_score: 0
    }
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [subTab, setSubTab] = useState('overview');
  const [urlInput, setUrlInput] = useState(PRESET_SCENARIOS[0].url);
  const [scanResult, setScanResult] = useState(PRESET_SCENARIOS[0]);
  const [isScanning, setIsScanning] = useState(false);
  const [liveBackendOnline, setLiveBackendOnline] = useState(false);
  const [copied, setCopied] = useState(false);
  const [iocs, setIocs] = useState([
    {
      id: 'ioc-001',
      indicator: 'https://sbi-kyc-update-pan.xyz/login',
      threat_type: 'Credential Harvesting / Banking Phishing',
      issuer_ca: "Let's Encrypt E5 (NRD < 24h)",
      confidence: 96,
      upvotes: 42,
      downvotes: 1
    },
    {
      id: 'ioc-002',
      indicator: 'https://accounts-google-verify.com',
      threat_type: 'MITM Impersonation via Compromised CA (CVE-2026-111943)',
      issuer_ca: 'EM OV TLS CA – G3B (Weak P-384 Key d=4)',
      confidence: 100,
      upvotes: 118,
      downvotes: 0
    }
  ]);

  useEffect(() => {
    fetch('https://cyberdost-2.onrender.com/api/v1/intel/feed')
      .then((r) => r.ok && r.json())
      .then((data) => {
        if (data?.iocs) {
          setIocs(data.iocs);
          setLiveBackendOnline(true);
        }
      })
      .catch(() => setLiveBackendOnline(false));
  }, []);

  const handleLiveScan = async (e) => {
    e?.preventDefault();
    setIsScanning(true);
    try {
      const response = await fetch('https://cyberdost-2.onrender.com/api/v1/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput, run_headless_sandbox: false })
      });
      if (response.ok) {
        const data = await response.json();
        setScanResult(data);
        setLiveBackendOnline(true);
      } else {
        throw new Error('Fallback to preset');
      }
    } catch {
      const matched = PRESET_SCENARIOS.find((p) => p.url === urlInput) || PRESET_SCENARIOS[0];
      setScanResult(matched);
    } finally {
      setIsScanning(false);
    }
  };

  const selectPreset = (preset) => {
    setUrlInput(preset.url);
    setScanResult(preset);
  };

  const handleVote = async (id, dir) => {
    setIocs((prev) =>
      prev.map((item) =>
        item.id === id
          ? {
              ...item,
              upvotes: dir === 'up' ? item.upvotes + 1 : item.upvotes,
              downvotes: dir === 'down' ? item.downvotes + 1 : item.downvotes,
              confidence: dir === 'up' ? Math.min(100, item.confidence + 2) : Math.max(0, item.confidence - 5)
            }
          : item
      )
    );
    try {
      await fetch(`https://cyberdost-2.onrender.com/api/v1/intel/vote/${id}/${dir}`, { method: 'POST' });
    } catch {}
  };

  const score = scanResult?.summary?.composite_risk_score ?? 0;
  const verdict = scanResult?.summary?.verdict ?? 'SAFE_VERIFIED';
  const isCritical = score >= 75;
  const isSuspicious = score >= 45 && score < 75;

  const stixBundle = scanResult?.stix_2_1_bundle || {
    type: 'bundle',
    id: 'bundle--CyberDost-99281-stix21',
    objects: [
      {
        type: 'indicator',
        spec_version: '2.1',
        name: `Malicious/Phishing URL Indicator: ${scanResult?.summary?.target_url}`,
        pattern: `[url:value = '${scanResult?.summary?.target_url}']`,
        pattern_type: 'stix',
        confidence: score,
        extensions: {
          'x-CyberDost-pki': {
            issuer: scanResult?.pki_certificate_audit?.issuer_cn,
            serial_hex: scanResult?.pki_certificate_audit?.serial_hex,
            crypto: scanResult?.pki_certificate_audit?.crypto_audit
          }
        }
      }
    ]
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Top Navbar */}
      <nav className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-xl font-extrabold tracking-tight text-white">CyberDost</h1>
                <span className="text-[11px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  Zero-Trust SOC v2.1
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Phishing Sandbox • CVE-2026-111943 PKI Entropy Screen • Collaborative STIX 2.1 Intelligence
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800">
            {[
              { id: 'scanner', label: 'Deep URL Scanner', icon: Search },
              { id: 'pki', label: 'PKI & Entropy Lab', icon: KeyRound },
              { id: 'intel', label: 'Threat Intel & STIX Hub', icon: Activity }
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
                    activeTab === tab.id
                      ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20'
                      : 'text-slate-400 hover:text-white hover:bg-slate-900'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                liveBackendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <span className="text-slate-400 font-mono">
              {liveBackendOnline ? 'FastAPI :8000 Connected' : 'Simulation Mode Ready'}
            </span>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        {activeTab === 'scanner' && (
          <>
            {/* Search & Scenario Bar */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Interactive Threat Scenarios (One-Click Load)
                </span>
                <div className="flex flex-wrap gap-2">
                  {PRESET_SCENARIOS.map((preset) => (
                    <button
                      key={preset.id}
                      onClick={() => selectPreset(preset)}
                      className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition flex items-center gap-2 ${
                        urlInput === preset.url
                          ? 'bg-emerald-500/15 border-emerald-500 text-emerald-300'
                          : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <span
                        className={`w-2 h-2 rounded-full ${
                          preset.summary.composite_risk_score >= 75 ? 'bg-red-400' : 'bg-emerald-400'
                        }`}
                      />
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              <form onSubmit={handleLiveScan} className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <Globe className="w-5 h-5 text-slate-500 absolute left-4 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="Enter suspicious URL, banking portal, or domain to inspect..."
                    className="w-full pl-12 pr-4 py-3.5 bg-slate-950 border border-slate-800 rounded-xl text-sm font-mono text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isScanning}
                  className="bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold px-6 py-3.5 rounded-xl text-sm flex items-center justify-center gap-2 transition shadow-lg shadow-emerald-500/20"
                >
                  {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  {isScanning ? 'Inspecting Stack...' : 'Execute Multi-Layer Scan'}
                </button>
              </form>
            </div>

            {/* Top Verdict & 4-Layer Score Cards */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Verdict Banner */}
              <div
                className={`lg:col-span-5 rounded-2xl p-6 border flex flex-col justify-between ${
                  isCritical
                    ? 'bg-gradient-to-br from-red-950/60 via-slate-900 to-slate-900 border-red-500/40'
                    : isSuspicious
                    ? 'bg-gradient-to-br from-amber-950/60 via-slate-900 to-slate-900 border-amber-500/40'
                    : 'bg-gradient-to-br from-emerald-950/60 via-slate-900 to-slate-900 border-emerald-500/40'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-xs font-mono uppercase tracking-widest text-slate-400">
                      Zero-Trust Verdict
                    </span>
                    <h2
                      className={`text-2xl font-black mt-1 ${
                        isCritical ? 'text-red-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
                      }`}
                    >
                      {verdict.replace('_', ' ')}
                    </h2>
                  </div>
                  <div className="text-right">
                    <div
                      className={`text-5xl font-black font-mono ${
                        isCritical ? 'text-red-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
                      }`}
                    >
                      {score}
                      <span className="text-lg text-slate-500">/100</span>
                    </div>
                    <span className="text-[11px] text-slate-400">Composite Risk Index</span>
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-slate-800/80 space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Target URL:</span>
                    <span className="font-mono text-slate-200 truncate max-w-[260px]">
                      {scanResult?.summary?.target_url}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Impersonated Brand:</span>
                    <span className="font-semibold text-amber-300">
                      {scanResult?.domain_analysis?.impersonated_brand || 'None (Authentic Origin)'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Certificate Issuer:</span>
                    <span className="font-mono text-slate-200">
                      {scanResult?.pki_certificate_audit?.issuer_cn}
                    </span>
                  </div>
                </div>
              </div>

              {/* 4 Layer Progress Breakdown */}
              <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-2xl p-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
                {[
                  {
                    title: 'Layer A: PKI & Key Entropy Risk',
                    val: scanResult?.summary?.layer_breakdown?.pki_trust_risk ?? 0,
                    sub: scanResult?.pki_certificate_audit?.crypto_audit?.type || 'X.509 Chain Verified',
                    icon: Lock
                  },
                  {
                    title: 'Layer B: Domain & Homograph Risk',
                    val: scanResult?.summary?.layer_breakdown?.domain_deception_risk ?? 0,
                    sub: scanResult?.domain_analysis?.decoded_hostname || 'Canonical Hostname',
                    icon: Globe
                  },
                  {
                    title: 'Layer C: Headless Sandbox & pHash',
                    val: scanResult?.summary?.layer_breakdown?.sandbox_behavioral_risk ?? 0,
                    sub:
                      scanResult?.sandbox_behavioral_analysis?.visual_analysis?.closest_brand_template ||
                      'DOM Telemetry',
                    icon: Eye
                  },
                  {
                    title: 'Layer D: HTTP Security Posture',
                    val: scanResult?.summary?.layer_breakdown?.web_posture_risk ?? 0,
                    sub: `Header Security Grade: ${scanResult?.web_security_posture?.security_grade || 'A'}`,
                    icon: Server
                  }
                ].map((layer, idx) => {
                  const Icon = layer.icon;
                  const high = layer.val >= 65;
                  return (
                    <div key={idx} className="bg-slate-950/80 border border-slate-800/90 rounded-xl p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                          <Icon className="w-4 h-4 text-emerald-400" />
                          {layer.title}
                        </span>
                        <span
                          className={`text-sm font-mono font-bold ${
                            high ? 'text-red-400' : 'text-emerald-400'
                          }`}
                        >
                          {layer.val}/100
                        </span>
                      </div>
                      <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden mb-2">
                        <div
                          className={`h-full rounded-full ${high ? 'bg-red-500' : 'bg-emerald-500'}`}
                          style={{ width: `${Math.max(4, layer.val)}%` }}
                        />
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 truncate">{layer.sub}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Deep Forensic Sub-Tabs */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="border-b border-slate-800 px-6 py-3 flex flex-wrap gap-2 bg-slate-950/50">
                {[
                  { id: 'overview', label: 'Correlated Forensic Findings' },
                  { id: 'pki_detail', label: 'X.509 Trust Chain & Entropy' },
                  { id: 'posture', label: 'HTTP Headers & Exposed Paths' },
                  { id: 'stix', label: 'STIX 2.1 JSON Bundle' }
                ].map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setSubTab(t.id)}
                    className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
                      subTab === t.id
                        ? 'bg-slate-800 text-emerald-400 border border-emerald-500/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div className="p-6">
                {subTab === 'overview' && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                        Domain & Cryptographic Warnings
                      </h3>
                      <div className="space-y-2.5">
                        {[
                          ...(scanResult?.domain_analysis?.deception_reasons || []),
                          ...(scanResult?.pki_certificate_audit?.warnings || [])
                        ].length === 0 ? (
                          <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/50 text-emerald-300 text-xs flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 shrink-0" />
                            Zero domain deception or PKI cryptographic anomalies found.
                          </div>
                        ) : (
                          [
                            ...(scanResult?.domain_analysis?.deception_reasons || []),
                            ...(scanResult?.pki_certificate_audit?.warnings || [])
                          ].map((w, i) => (
                            <div
                              key={i}
                              className="p-3.5 rounded-xl bg-red-950/30 border border-red-900/50 text-red-200 text-xs flex items-start gap-2.5"
                            >
                              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                              <span>{w}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>

                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                        Headless Sandbox & Visual DCT pHash Telemetry
                      </h3>
                      <div className="space-y-2.5">
                        {(scanResult?.sandbox_behavioral_analysis?.behavioral_flags || []).map((flag, i) => (
                          <div
                            key={i}
                            className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs flex items-start gap-2.5"
                          >
                            <Terminal className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                            <span>{flag}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {subTab === 'pki_detail' && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
                      <div className="text-slate-400 font-semibold">Subject & Issuer</div>
                      <div><span className="text-slate-500">Subject CN:</span> <span className="font-mono text-white">{scanResult?.pki_certificate_audit?.subject_cn}</span></div>
                      <div><span className="text-slate-500">Issuer CN:</span> <span className="font-mono text-amber-300">{scanResult?.pki_certificate_audit?.issuer_cn}</span></div>
                      <div><span className="text-slate-500">Serial (Hex):</span> <span className="font-mono text-slate-300 break-all">{scanResult?.pki_certificate_audit?.serial_hex}</span></div>
                    </div>

                    <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
                      <div className="text-slate-400 font-semibold">Key Entropy & CVE-2026-111943 Check</div>
                      <div><span className="text-slate-500">Algorithm:</span> <span className="font-mono text-white">{scanResult?.pki_certificate_audit?.crypto_audit?.type}</span></div>
                      <div><span className="text-slate-500">Effective Entropy:</span> <span className="font-mono text-emerald-400">{scanResult?.pki_certificate_audit?.crypto_audit?.entropy_bits} bits</span></div>
                      {scanResult?.pki_certificate_audit?.crypto_audit?.recovered_scalar && (
                        <div className="text-red-400 font-bold">
                          Recovered Private Scalar d = {scanResult.pki_certificate_audit.crypto_audit.recovered_scalar}
                        </div>
                      )}
                    </div>

                    <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
                      <div className="text-slate-400 font-semibold">Root Store Trust Matrix</div>
                      {['Mozilla NSS', 'Chrome Root Store', 'Apple Trust Store', 'Microsoft Root Program'].map((store) => (
                        <div key={store} className="flex items-center justify-between">
                          <span className="text-slate-300">{store}</span>
                          {scanResult?.pki_certificate_audit?.os_trusted ? (
                            <span className="text-emerald-400 font-mono flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" /> TRUSTED
                            </span>
                          ) : (
                            <span className="text-red-400 font-mono flex items-center gap-1">
                              <XCircle className="w-3.5 h-3.5" /> DISTRUSTED
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {subTab === 'posture' && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
                    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                      <div className="text-slate-400 font-semibold mb-2">Missing HTTP Security Headers</div>
                      {(scanResult?.web_security_posture?.missing_headers || []).length === 0 ? (
                        <div className="text-emerald-400">All recommended security headers (CSP, HSTS, XFO) are enforced.</div>
                      ) : (
                        scanResult.web_security_posture.missing_headers.map((h) => (
                          <div key={h} className="px-3 py-2 bg-red-950/30 border border-red-900/40 rounded-lg text-red-300 font-mono">
                            Missing: {h}
                          </div>
                        ))
                      )}
                    </div>

                    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                      <div className="text-slate-400 font-semibold mb-2">Exposed Sensitive Endpoints</div>
                      {(scanResult?.web_security_posture?.exposed_sensitive_paths || []).length === 0 ? (
                        <div className="text-emerald-400">No exposed /.env, /.git/config, or debug artifacts detected.</div>
                      ) : (
                        scanResult.web_security_posture.exposed_sensitive_paths.map((p) => (
                          <div key={p} className="px-3 py-2 bg-amber-950/40 border border-amber-800/50 rounded-lg text-amber-300 font-mono">
                            HTTP 200 Exposed Artifact: {p}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {subTab === 'stix' && (
                  <div className="relative">
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(stixBundle, null, 2));
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      }}
                      className="absolute right-4 top-4 bg-slate-800 hover:bg-slate-700 text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copied ? 'Copied STIX 2.1' : 'Copy JSON'}
                    </button>
                    <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-emerald-300 overflow-x-auto">
                      {JSON.stringify(stixBundle, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>

            {/* Embedded Threat Intelligence & Automated Takedown Panel */}
            <ThreatIntelligencePanel scanResult={scanResult} />
          </>
        )}

        {activeTab === 'pki' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h2 className="text-lg font-bold text-white">
              CVE-2026-111943 Low-Entropy Elliptic-Curve Scalar & CA Trust Auditor
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              During the eMudhra TLS incident, eight intermediate CAs were generated using P-384 private keys with
              1-byte scalars (4, 56, 66, 115, 155, 156, 230, 237). Our backend module{' '}
              <code className="text-emerald-300">module_1_pki_auditor.py</code> tests candidate scalars{' '}
              <code className="text-emerald-300">Q = d * G</code> and screens RSA moduli via Batch-GCD.
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              {[4, 56, 66, 115, 155, 156, 230, 237].map((scalar) => (
                <div key={scalar} className="bg-slate-950 border border-red-900/40 rounded-xl p-3.5">
                  <div className="text-[11px] text-slate-400 font-mono">Compromised P-384 Scalar</div>
                  <div className="text-xl font-black font-mono text-red-400 mt-1">d = {scalar}</div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    Entropy: {Math.log2(scalar).toFixed(2)} bits / 384 bits
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'intel' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h2 className="text-lg font-bold text-white">Collaborative SOC Threat Intelligence Feed</h2>
            <div className="space-y-3">
              {iocs.map((item) => (
                <div
                  key={item.id}
                  className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4"
                >
                  <div>
                    <div className="font-mono text-sm text-white font-semibold">{item.indicator}</div>
                    <div className="text-xs text-slate-400 mt-1 flex items-center gap-2">
                      <span>{item.threat_type}</span>
                      <span className="text-amber-300">{item.issuer_ca}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono px-2.5 py-1 rounded bg-red-500/15 text-red-300 border border-red-500/30">
                      Confidence: {item.confidence}%
                    </span>
                    <button
                      onClick={() => handleVote(item.id, 'up')}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs text-emerald-400 border border-slate-800"
                    >
                      <ThumbsUp className="w-3.5 h-3.5" /> {item.upvotes}
                    </button>
                    <button
                      onClick={() => handleVote(item.id, 'down')}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs text-slate-400 border border-slate-800"
                    >
                      <ThumbsDown className="w-3.5 h-3.5" /> {item.downvotes}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}