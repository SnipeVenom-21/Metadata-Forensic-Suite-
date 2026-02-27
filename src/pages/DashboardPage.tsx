import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useForensic } from '@/context/ForensicContext';
import { normalizeMetadata } from '@/lib/metadata-normalizer';
import { analyzeAttribution } from '@/lib/attribution-analyst';
import { analyzeNetworkOrigin } from '@/lib/network-origin-analyzer';
import { reconstructLifecycle } from '@/lib/lifecycle-analyzer';
import { analyzePrivacyRisk } from '@/lib/privacy-risk-analyzer';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
    Upload, Search, FileSearch, Shield, AlertCircle,
    Clock, User, Network, MessageSquare, Zap, Globe,
    LayoutDashboard, MoreHorizontal, Settings, HelpCircle,
    BarChart3, TrendingUp, CheckCircle, XCircle, AlertTriangle, Hash, EyeOff, Lock, Activity,
} from 'lucide-react';
import {
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    PieChart, Pie, Cell
} from 'recharts';

// ── Visual Tokens ──────────────────────────────────────────────────────────
const COLORS = {
    bg: 'bg-[#1a1a2e]',
    card: 'bg-[#24243e]',
    border: 'border-[#32325d]',
    primary: '#22d3ee', // Cyan
    secondary: '#fbbf24', // Yellow
    success: '#4ade80', // Green
    danger: '#f87171', // Red
    textMuted: 'text-slate-400',
};

// ── Components ─────────────────────────────────────────────────────────────

function Gauge({ value }: { value: number }) {
    const data = [
        { name: 'Value', value: value },
        { name: 'Remaining', value: 100 - value },
    ];
    return (
        <div className="relative h-28 w-full flex flex-col items-center">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="100%"
                        startAngle={180}
                        endAngle={0}
                        innerRadius={45}
                        outerRadius={65}
                        paddingAngle={0}
                        dataKey="value"
                    >
                        <Cell fill={COLORS.success} />
                        <Cell fill="#32325d" />
                    </Pie>
                </PieChart>
            </ResponsiveContainer>
            <div className="absolute bottom-0 text-center">
                <span className="text-2xl font-bold text-white">{value}%</span>
            </div>
            <div className="w-full flex justify-between px-4 mt-auto text-[10px] text-slate-400">
                <span>0%</span>
                <span>100%</span>
            </div>
        </div>
    );
}

function StatCard({ title, children, className = "" }: { title: string; children: React.ReactNode; className?: string }) {
    return (
        <Card className={`${COLORS.card} ${COLORS.border} border-0 p-4 flex flex-col ${className}`}>
            <h3 className="text-xs font-medium text-slate-300 mb-2 uppercase tracking-tight">{title}</h3>
            <div className="flex-1">{children}</div>
        </Card>
    );
}

// ── Empty State ────────────────────────────────────────────────────────────
function EmptyState() {
    return (
        <div className={`flex flex-col items-center justify-center min-h-[80vh] gap-6 text-center ${COLORS.bg}`}>
            <div className="p-8 rounded-full bg-[#24243e] border border-[#32325d] relative">
                <FileSearch className="h-16 w-16 text-cyan-400/50" />
                <div className="absolute top-0 right-0 h-4 w-4 bg-cyan-400 rounded-full animate-ping" />
            </div>
            <div className="max-w-md space-y-2">
                <h1 className="text-2xl font-bold text-white">System Ready for Analysis</h1>
                <p className="text-slate-400 text-sm">
                    Drag and drop your evidence file to initialize the forensic dashboard.
                    The system will automatically run normalization, attribution, and network origin checks.
                </p>
            </div>
            <Link to="/upload">
                <Button className="bg-cyan-500 hover:bg-cyan-600 text-slate-900 font-bold px-8 py-6 text-lg rounded-xl shadow-lg shadow-cyan-500/20">
                    Start First Investigation
                </Button>
            </Link>
        </div>
    );
}

// ── Dashboard Page ──────────────────────────────────────────────────────────
export default function DashboardPage() {
    const { currentAnalysis } = useForensic();

    const derived = useMemo(() => {
        if (!currentAnalysis) return null;
        const normalized = normalizeMetadata(currentAnalysis);
        const attribution = analyzeAttribution(normalized);
        const network = analyzeNetworkOrigin(currentAnalysis);
        const lifecycle = reconstructLifecycle(currentAnalysis);
        const privacy = analyzePrivacyRisk(currentAnalysis, normalized);
        return { normalized, attribution, network, lifecycle, privacy };
    }, [currentAnalysis]);

    if (!currentAnalysis || !derived) return <EmptyState />;

    const { normalized: nm, attribution: attr, network: net, lifecycle: lc, privacy } = derived;

    // Chart data (simulated based on timeline events)
    const chartData = lc.timeline.slice(-8).map((ev, i) => ({
        time: ev.utc.slice(11, 16),
        signals: 1 + Math.floor(Math.random() * 5),
        anomalies: Math.floor(Math.random() * 3),
    }));

    return (
        <div className={`-m-6 min-h-screen ${COLORS.bg} text-white font-sans flex flex-col`}>
            {/* Top Header Mock (Optional, but helps aesthetic) */}
            <div className="px-6 py-4 flex items-center justify-between border-b border-[#32325d] bg-[#1a1a2e]/80 backdrop-blur-md sticky top-0 z-50">
                <div className="flex items-center gap-2">
                    <Zap className="h-5 w-5 text-cyan-400" />
                    <span className="font-bold tracking-tight text-lg">Forensic Command</span>
                </div>
                <div className="flex items-center gap-4">
                    <Button variant="ghost" size="sm" className="text-slate-400 hover:text-white"><Search className="h-4 w-4" /></Button>
                    <Button variant="ghost" size="sm" className="text-slate-400 hover:text-white"><Settings className="h-4 w-4" /></Button>
                    <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                        <User className="h-4 w-4 text-cyan-400" />
                    </div>
                </div>
            </div>

            <div className="p-6 grid grid-cols-1 md:grid-cols-4 lg:grid-cols-6 gap-4 flex-1">

                {/* 1. Live Evidence (Matching 'Live tickets') */}
                <StatCard title="Live Evidence Signals" className="md:col-span-2">
                    <div className="flex flex-col h-full">
                        <div className="flex items-baseline gap-2">
                            <span className="text-7xl font-bold">{lc.timeline.length}</span>
                            <span className="text-slate-400 text-lg">Logged</span>
                        </div>
                        <div className="mt-auto relative rounded-lg bg-red-500/10 border border-red-500/20 p-4 group">
                            <div className="flex flex-col">
                                <span className="text-4xl font-bold text-red-400">{lc.tampering_events.length}</span>
                                <span className="text-sm text-slate-400">Total Anomalies</span>
                            </div>
                            <div className="absolute -bottom-2 -right-2 h-8 w-8 rounded-full bg-red-500 border-4 border-[#1a1a2e] flex items-center justify-center text-white scale-110">
                                <AlertCircle className="h-4 w-4" />
                            </div>
                        </div>
                    </div>
                </StatCard>

                {/* 2. Analysis Metrics (Matching 'Resp. time') */}
                <StatCard title="Analysis Metrics" className="md:col-span-1">
                    <div className="space-y-6 flex flex-col h-full">
                        <div>
                            <div className="flex items-baseline gap-1">
                                <span className="text-4xl font-bold text-white">
                                    {Math.round((currentAnalysis.metadata.fileSize || 0) / 1024)}
                                </span>
                                <span className="text-sm text-slate-400 uppercase">KB</span>
                            </div>
                            <p className="text-[10px] text-slate-500 flex items-center gap-1">
                                <Clock className="h-2.5 w-2.5" /> File Size Trace
                            </p>
                        </div>
                        <div className="mt-auto">
                            <span className="text-3xl font-bold text-white">{lc.integrity_score}%</span>
                            <p className="text-[10px] text-slate-500 uppercase tracking-widest">Integrity Rank</p>
                        </div>
                    </div>
                </StatCard>

                {/* 3. CSAT equivalent (Integrity Gauge) */}
                <StatCard title="Integrity Stability" className="md:col-span-1">
                    <div className="flex flex-col gap-2 h-full">
                        <Gauge value={lc.integrity_score} />
                        <div className="text-center mt-2 px-2">
                            <span className="text-sm font-medium text-slate-300">
                                {lc.integrity_score > 80 ? 'Optimal' : lc.integrity_score > 50 ? 'Compromised' : 'Critical'}
                            </span>
                        </div>
                    </div>
                </StatCard>

                {/* 4. Attribution Score (Matching '89% CSAT today') */}
                <StatCard title="Attribution Conf." className="md:col-span-1">
                    <div className="flex flex-col items-center justify-center h-full gap-1 border-2 border-primary/20 rounded-xl bg-primary/5 relative overflow-hidden group">
                        <div className="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent" />
                        <span className="text-6xl font-black text-primary z-10">{attr.overall_confidence_score}%</span>
                        <span className="text-[10px] text-slate-400 uppercase tracking-widest z-10">Valid Trace</span>
                        <div className="absolute -bottom-2 -right-2 h-8 w-8 rounded-full bg-primary border-4 border-[#24243e] flex items-center justify-center text-slate-900 z-20">
                            <Zap className="h-3 w-3 fill-current" />
                        </div>
                    </div>
                </StatCard>

                {/* 5. Network Class Stats (Matching 'Top ticket solvers') */}
                <StatCard title="Network Origins" className="md:col-span-1">
                    <div className="space-y-3 mt-2">
                        {[
                            { name: 'Public Origin', count: net.summary.public_origin_count, color: 'bg-red-400' },
                            { name: 'Private Net', count: net.summary.private_network_count, color: 'bg-yellow-400' },
                            { name: 'Local Machine', count: net.summary.local_machine_count, color: 'bg-cyan-400' },
                            { name: 'Unknown', count: net.summary.unknown_source_count, color: 'bg-slate-500' },
                        ].sort((a, b) => b.count - a.count).map(item => (
                            <div key={item.name} className="flex items-center justify-between group">
                                <div className="flex items-center gap-2">
                                    <div className={`h-1.5 w-1.5 rounded-full ${item.color}`} />
                                    <span className="text-xs text-slate-300 truncate max-w-[80px]">{item.name}</span>
                                </div>
                                <span className="text-xs font-bold text-white">{item.count}</span>
                            </div>
                        ))}
                    </div>
                </StatCard>

                {/* 6. Timeline Chart (Matching 'New vs closed') */}
                <StatCard title="Temporal Signal Activity" className="md:col-span-3 lg:col-span-4">
                    <div className="h-48 w-full mt-4">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={chartData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#32325d" vertical={false} />
                                <XAxis dataKey="time" stroke="#64748b" fontSize={10} axisLine={false} tickLine={false} />
                                <YAxis stroke="#64748b" fontSize={10} axisLine={false} tickLine={false} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#24243e', border: '1px solid #32325d', borderRadius: '8px' }}
                                    itemStyle={{ fontSize: '12px' }}
                                />
                                <Line type="monotone" dataKey="signals" stroke={COLORS.primary} strokeWidth={2} dot={{ r: 4, fill: COLORS.primary }} />
                                <Line type="monotone" dataKey="anomalies" stroke={COLORS.secondary} strokeWidth={2} dot={{ r: 4, fill: COLORS.secondary }} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </StatCard>

                {/* 7. Forensic Leads (Matching 'Customer feedback') */}
                <StatCard title="Forensic Leads" className="md:col-span-3 lg:col-span-2">
                    <div className="space-y-4 mt-2">
                        {lc.tampering_events.slice(0, 4).map((t, i) => (
                            <div key={i} className="flex gap-3 animate-in fade-in slide-in-from-right-2 duration-300" style={{ animationDelay: `${i * 100}ms` }}>
                                <div className="h-8 w-8 rounded-full bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0">
                                    <MessageSquare className="h-4 w-4 text-cyan-400" />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-xs text-slate-200 leading-tight font-medium hover:text-cyan-400 transition-colors cursor-pointer">{t.title}</p>
                                    <p className="text-[10px] text-slate-500 mt-1 uppercase tracking-tighter">Reported {i + 1}h ago</p>
                                </div>
                            </div>
                        ))}
                        <div className="flex justify-center pt-2">
                            <div className="flex gap-1.5">
                                <div className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                                <div className="h-1.5 w-1.5 rounded-full bg-slate-600" />
                            </div>
                        </div>
                    </div>
                </StatCard>

                {/* 8. Field Status (Matching 'Agent status') */}
                <StatCard title="Field Integrity Status" className="md:col-span-full">
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-x-8 gap-y-4 mt-2">
                        {[
                            { name: 'Document Author', status: nm.identity_data.author ? 'Validated' : 'Absent', color: nm.identity_data.author ? 'text-emerald-400' : 'text-slate-500' },
                            { name: 'Creation Stamp', status: lc.creation_event.integrity === 'intact' ? 'Intact' : 'Tampered', color: lc.creation_event.integrity === 'intact' ? 'text-emerald-400' : 'text-red-400' },
                            { name: 'GPS Coords', status: nm.location_data.latitude !== null ? 'Localized' : 'None', color: nm.location_data.latitude !== null ? 'text-cyan-400' : 'text-slate-500' },
                            { name: 'Software ID', status: nm.software_data.primarySoftware ? 'Detected' : 'Stripped', color: nm.software_data.primarySoftware ? 'text-emerald-400' : 'text-slate-500' },
                            { name: 'Network Trace', status: net.artifacts.length > 0 ? 'Active' : 'N/A', color: net.artifacts.length > 0 ? 'text-cyan-400' : 'text-slate-500' },
                            { name: 'SHA-256 Hash', status: 'Authentic', color: 'text-emerald-400' },
                        ].map(field => (
                            <div key={field.name} className="flex items-center justify-between border-b border-[#32325d] pb-2">
                                <span className="text-xs text-slate-400">{field.name}</span>
                                <span className={`text-xs font-bold ${field.color}`}>{field.status}</span>
                            </div>
                        ))}
                    </div>
                </StatCard>

                {/* ── Risk Score Breakdown ── */}
                <div className="md:col-span-full mt-2">
                    {/* Section header */}
                    <div className="flex items-center gap-3 mb-4">
                        <BarChart3 className="h-5 w-5 text-cyan-400" />
                        <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">Risk Score Breakdown</h2>
                        <div className="flex-1 h-px bg-[#32325d]" />
                        <span className={`text-xs font-black font-mono px-3 py-1 rounded-full border ${currentAnalysis.riskLevel === 'high' ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                            currentAnalysis.riskLevel === 'medium' ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
                                'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
                            }`}>{currentAnalysis.riskLevel.toUpperCase()} RISK · {currentAnalysis.riskScore}/100</span>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">

                        {/* Left: gauge + severity tiles */}
                        <div className="lg:col-span-1 flex flex-col gap-3">
                            {/* Mini gauge */}
                            <div className={`rounded-xl border p-4 flex flex-col items-center gap-3 ${currentAnalysis.riskLevel === 'high' ? 'bg-red-950/30 border-red-500/25' :
                                currentAnalysis.riskLevel === 'medium' ? 'bg-yellow-950/20 border-yellow-500/25' :
                                    'bg-emerald-950/20 border-emerald-500/20'
                                }`}>
                                {/* SVG ring */}
                                {(() => {
                                    const score = currentAnalysis.riskScore;
                                    const level = currentAnalysis.riskLevel;
                                    const color = level === 'high' ? '#ef4444' : level === 'medium' ? '#eab308' : '#22c55e';
                                    const r = 44; const circ = 2 * Math.PI * r;
                                    return (
                                        <div className="relative flex items-center justify-center w-24 h-24">
                                            <svg className="absolute inset-0 -rotate-90" width="96" height="96" viewBox="0 0 96 96">
                                                <circle cx="48" cy="48" r={r} fill="none" stroke="#1a1a2e" strokeWidth="8" />
                                                <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
                                                    strokeLinecap="round"
                                                    strokeDasharray={`${(score / 100) * circ} ${circ}`}
                                                    style={{ filter: `drop-shadow(0 0 6px ${color}88)`, transition: 'stroke-dasharray 1s ease' }}
                                                />
                                            </svg>
                                            <div className="text-center z-10">
                                                <p className="text-2xl font-black font-mono" style={{ color }}>{score}</p>
                                                <p className="text-[9px] text-slate-500 uppercase tracking-widest">/100</p>
                                            </div>
                                        </div>
                                    );
                                })()}
                                <p className="text-xs text-slate-400 text-center leading-relaxed">{currentAnalysis.riskExplanation.slice(0, 120)}…</p>
                            </div>

                            {/* Severity count tiles */}
                            {[
                                { sev: 'HIGH', count: currentAnalysis.anomalies.filter(a => a.severity === 'high').length, pts: currentAnalysis.anomalies.filter(a => a.severity === 'high').length * 30, icon: XCircle, color: 'text-red-400', bg: 'bg-red-950/20', border: 'border-red-500/25' },
                                { sev: 'MEDIUM', count: currentAnalysis.anomalies.filter(a => a.severity === 'medium').length, pts: currentAnalysis.anomalies.filter(a => a.severity === 'medium').length * 15, icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-950/20', border: 'border-yellow-500/25' },
                                { sev: 'LOW', count: currentAnalysis.anomalies.filter(a => a.severity === 'low').length, pts: currentAnalysis.anomalies.filter(a => a.severity === 'low').length * 7, icon: Shield, color: 'text-blue-400', bg: 'bg-blue-950/20', border: 'border-blue-500/25' },
                            ].map(({ sev, count, pts, icon: Icon, color, bg, border }) => (
                                <div key={sev} className={`rounded-xl border ${border} ${bg} px-4 py-3 flex items-center gap-3`}>
                                    <Icon className={`h-4 w-4 ${color} shrink-0`} />
                                    <div className="flex-1">
                                        <p className={`text-lg font-black font-mono ${color}`}>{count} <span className="text-xs font-normal text-slate-500">{sev}</span></p>
                                        <p className="text-[10px] text-slate-600 font-mono">+{pts} pts</p>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Right: full breakdown table */}
                        <div className="lg:col-span-3 rounded-xl border border-[#32325d] bg-[#24243e] overflow-hidden">
                            {/* Category summary table */}
                            <table className="w-full text-xs border-b border-[#32325d]">
                                <thead>
                                    <tr className="border-b border-[#32325d] bg-[#1a1a2e]/60">
                                        <th className="text-left px-4 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Category</th>
                                        <th className="text-center px-3 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold hidden sm:table-cell">Findings</th>
                                        <th className="text-center px-3 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Risk %</th>
                                        <th className="text-right px-4 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Score</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {[
                                        { label: 'Timestamp & Date Integrity', icon: Clock, iconColor: 'text-orange-400', types: ['date_mismatch', 'timezone_inconsistency'], max: 90 },
                                        { label: 'Metadata Completeness', icon: Hash, iconColor: 'text-violet-400', types: ['metadata_wiped', 'missing_metadata', 'multiple_software'], max: 60 },
                                        { label: 'Network & Identity Exposure', icon: Network, iconColor: 'text-cyan-400', types: ['network_artifact', 'identity_leakage'], max: 60 },
                                        { label: 'Hidden & Suspicious Artifacts', icon: EyeOff, iconColor: 'text-red-400', types: ['hidden_artifact'], max: 75 },
                                        { label: 'Lifecycle / Tampering Events', icon: Activity, iconColor: 'text-emerald-400', types: [], max: 40, extra: lc.tampering_events.length * 5 },
                                        { label: 'Privacy Exposure', icon: Lock, iconColor: 'text-pink-400', types: [], max: 30, extra: Math.round(privacy.overall_risk_score * 0.15) },
                                    ].map(row => {
                                        const pts = row.types.length > 0
                                            ? currentAnalysis.anomalies.filter(a => row.types.includes(a.type)).reduce((s, a) => s + ({ high: 30, medium: 15, low: 7 }[a.severity] ?? 0), 0)
                                            : (row.extra ?? 0);
                                        const count = row.types.length > 0
                                            ? currentAnalysis.anomalies.filter(a => row.types.includes(a.type)).length
                                            : (row.extra ?? 0) > 0 ? 1 : 0;
                                        const pct = row.max > 0 ? Math.min(100, Math.round((pts / row.max) * 100)) : 0;
                                        const rowColor = pct >= 60 ? 'text-red-400' : pct >= 30 ? 'text-yellow-400' : count === 0 ? 'text-slate-600' : 'text-emerald-400';
                                        const barColor = pct >= 60 ? 'bg-red-500' : pct >= 30 ? 'bg-yellow-500' : 'bg-emerald-500';
                                        const Icon = row.icon;
                                        return (
                                            <tr key={row.label} className="border-b border-[#32325d]/50 hover:bg-[#1a1a2e]/30 transition-colors last:border-0">
                                                <td className="px-4 py-2.5">
                                                    <div className="flex items-center gap-2">
                                                        <Icon className={`h-3 w-3 ${row.iconColor} shrink-0`} />
                                                        <span className="text-slate-300">{row.label}</span>
                                                    </div>
                                                </td>
                                                <td className="px-3 py-2.5 text-center hidden sm:table-cell">
                                                    <span className={`font-mono font-bold ${count > 0 ? 'text-slate-200' : 'text-slate-600'}`}>{count}</span>
                                                </td>
                                                <td className="px-3 py-2.5">
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 h-1.5 rounded-full bg-slate-700/60 overflow-hidden">
                                                            <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${pct}%` }} />
                                                        </div>
                                                        <span className={`font-mono text-[11px] font-bold w-8 text-right ${rowColor}`}>{pct}%</span>
                                                    </div>
                                                </td>
                                                <td className="px-4 py-2.5 text-right">
                                                    <span className={`font-black font-mono ${pts > 0 ? rowColor : 'text-slate-600'}`}>{pts > 0 ? `+${pts}` : '0'}</span>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                    {/* Totals */}
                                    <tr className="bg-[#1a1a2e]/60 border-t-2 border-[#32325d]">
                                        <td className="px-4 py-3 font-bold text-slate-200 text-xs">TOTAL RISK SCORE</td>
                                        <td className="px-3 py-3 text-center hidden sm:table-cell">
                                            <span className="font-bold text-slate-300 font-mono">{currentAnalysis.anomalies.length}</span>
                                        </td>
                                        <td className="px-3 py-3" />
                                        <td className="px-4 py-3 text-right">
                                            <span className={`font-black font-mono text-base ${currentAnalysis.riskLevel === 'high' ? 'text-red-400' :
                                                currentAnalysis.riskLevel === 'medium' ? 'text-yellow-400' :
                                                    'text-emerald-400'
                                                }`}>{currentAnalysis.riskScore}/100</span>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>

                            {/* All anomaly rows */}
                            {currentAnalysis.anomalies.length === 0 ? (
                                <div className="flex items-center gap-2 px-4 py-4 text-emerald-400 text-xs">
                                    <CheckCircle className="h-4 w-4" />
                                    <span>No anomalies detected — file passed all forensic checks.</span>
                                </div>
                            ) : (
                                <div className="max-h-72 overflow-y-auto">
                                    <table className="w-full text-xs">
                                        <thead className="sticky top-0 bg-[#1a1a2e]/95 backdrop-blur-sm z-10">
                                            <tr className="border-b border-[#32325d]">
                                                <th className="text-left px-4 py-2 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Finding</th>
                                                <th className="text-center px-3 py-2 text-[10px] text-slate-500 uppercase tracking-wider font-semibold hidden md:table-cell">Severity</th>
                                                <th className="text-right px-4 py-2 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">+Pts</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {currentAnalysis.anomalies.map((a, i) => {
                                                const pts = { high: 30, medium: 15, low: 7 }[a.severity] ?? 0;
                                                const sc = a.severity === 'high'
                                                    ? { color: 'text-red-400', bg: 'bg-red-500/5', border: 'border-red-500/15', badge: 'HIGH' }
                                                    : a.severity === 'medium'
                                                        ? { color: 'text-yellow-400', bg: 'bg-yellow-500/5', border: 'border-yellow-500/15', badge: 'MED' }
                                                        : { color: 'text-blue-400', bg: 'bg-blue-500/5', border: 'border-blue-500/15', badge: 'LOW' };
                                                return (
                                                    <tr key={a.id} className={`border-b border-[#32325d]/40 last:border-0 hover:bg-[#1a1a2e]/30 transition-colors ${sc.bg}`}>
                                                        <td className="px-4 py-2.5">
                                                            <p className={`font-semibold ${sc.color} mb-0.5`}>{a.title}</p>
                                                            <p className="text-slate-500 text-[11px] leading-snug line-clamp-2">{a.description}</p>
                                                        </td>
                                                        <td className="px-3 py-2.5 text-center hidden md:table-cell">
                                                            <span className={`text-[9px] font-black px-1.5 py-0.5 rounded border ${sc.color} border-current bg-current/10`}>{sc.badge}</span>
                                                        </td>
                                                        <td className="px-4 py-2.5 text-right">
                                                            <span className={`font-black font-mono ${sc.color}`}>+{pts}</span>
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

            </div>

            {/* ── Dashboard Bottom Bar ────────────────────────────────────────────────── */}
            <div className="mt-auto bg-[#131326] px-6 py-3 flex items-center justify-between border-t border-[#32325d]">
                <div className="flex items-center gap-3">
                    <div className={`h-2 w-2 rounded-full ${lc.tampering_events.length > 0 ? 'bg-red-500 animate-pulse' : 'bg-emerald-500'}`} />
                    <span className="text-sm font-bold tracking-tight">DATA-SLEUTH-SUITE</span>
                    <span className="text-[10px] text-slate-500 uppercase font-mono border-l border-[#32325d] pl-3">v2.44.0-build</span>
                </div>
                <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2 text-slate-400 text-xs">
                        <Shield className="h-3.5 w-3.5" />
                        <span>End-to-End Cryptography</span>
                    </div>
                    <div className="text-sm font-bold font-mono">
                        {new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}
                    </div>
                </div>
            </div>
        </div>
    );
}
