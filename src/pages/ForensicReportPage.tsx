import { useMemo, useState } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { useNavigate } from 'react-router-dom';
import { normalizeMetadata } from '@/lib/metadata-normalizer';
import { analyzeAttribution } from '@/lib/attribution-analyst';
import { reconstructLifecycle } from '@/lib/lifecycle-analyzer';
import { analyzeNetworkOrigin } from '@/lib/network-origin-analyzer';
import { analyzeGeoDevice } from '@/lib/geo-device-analyzer';
import { analyzePrivacyRisk } from '@/lib/privacy-risk-analyzer';
import { generateForensicReport, ForensicAnalystReport, ForensicFinding, FindingSeverity, ConfidenceTier } from '@/lib/forensic-report-generator';
import {
    FileText, Shield, AlertTriangle, Info, CheckCircle2, XCircle,
    ChevronDown, ChevronUp, BookOpen, Hash, Clock, User, MapPin,
    Cpu, Wifi, Eye, Layers, Download, ExternalLink, Circle,
    ShieldCheck, ShieldX, ShieldAlert
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

// ── Severity config ──────────────────────────────────────────────────────────

const SEV_CFG: Record<FindingSeverity, { label: string; color: string; bg: string; border: string; badge: string; icon: React.ElementType }> = {
    critical: { label: 'CRITICAL', color: 'text-red-400', bg: 'bg-red-950/30', border: 'border-red-500/40', badge: 'bg-red-500/20 text-red-400 border-red-500/30', icon: XCircle },
    high: { label: 'HIGH', color: 'text-orange-400', bg: 'bg-orange-950/20', border: 'border-orange-500/30', badge: 'bg-orange-500/20 text-orange-400 border-orange-500/30', icon: AlertTriangle },
    medium: { label: 'MEDIUM', color: 'text-amber-400', bg: 'bg-amber-950/20', border: 'border-amber-500/30', badge: 'bg-amber-500/20 text-amber-400 border-amber-500/30', icon: AlertTriangle },
    low: { label: 'LOW', color: 'text-sky-400', bg: 'bg-sky-950/20', border: 'border-sky-500/30', badge: 'bg-sky-500/20 text-sky-400 border-sky-500/30', icon: Info },
    informational: { label: 'INFO', color: 'text-slate-400', bg: 'bg-slate-800/40', border: 'border-slate-600/40', badge: 'bg-slate-700/50 text-slate-300 border-slate-600/30', icon: Info },
};

const CONF_CFG: Record<ConfidenceTier, { label: string; color: string }> = {
    definitive: { label: 'Definitive', color: 'text-emerald-400' },
    high: { label: 'High', color: 'text-sky-400' },
    moderate: { label: 'Moderate', color: 'text-amber-400' },
    low: { label: 'Low', color: 'text-orange-400' },
    insufficient: { label: 'Insufficient', color: 'text-red-400' },
};

const CAT_ICONS: Record<string, React.ElementType> = {
    identity: User, timeline: Clock, location: MapPin, device: Cpu,
    network: Wifi, integrity: Shield, privacy: Eye, content: Layers,
};

const VERDICT_CFG = {
    authentic: { icon: ShieldCheck, color: 'text-emerald-400', bg: 'bg-emerald-950/30', border: 'border-emerald-500/40', label: 'AUTHENTIC' },
    suspicious: { icon: ShieldAlert, color: 'text-amber-400', bg: 'bg-amber-950/20', border: 'border-amber-500/40', label: 'SUSPICIOUS' },
    tampered: { icon: ShieldX, color: 'text-red-400', bg: 'bg-red-950/30', border: 'border-red-500/40', label: 'TAMPERED' },
    insufficient_data: { icon: Shield, color: 'text-slate-400', bg: 'bg-slate-800/40', border: 'border-slate-600/40', label: 'INSUFFICIENT DATA' },
};

const SOURCE_LABELS: Record<string, string> = {
    exif: 'EXIF', xmp: 'XMP', iptc: 'IPTC', docx_core: 'DOCX Core',
    pdf_info: 'PDF Info', content_scan: 'Content Scan', filesystem: 'Filesystem', derived: 'Computed',
};

// ── Finding Card ─────────────────────────────────────────────────────────────

function FindingCard({ finding, expanded }: { finding: ForensicFinding; expanded?: boolean }) {
    const [open, setOpen] = useState(expanded ?? false);
    const cfg = SEV_CFG[finding.severity];
    const CatIcon = CAT_ICONS[finding.category] ?? Layers;
    const SevIcon = cfg.icon;

    return (
        <div className={`rounded-xl border ${cfg.border} ${cfg.bg} overflow-hidden`}>
            <button
                onClick={() => setOpen(v => !v)}
                className="w-full flex items-start gap-3 p-4 text-left hover:bg-white/3 transition-colors"
            >
                {/* Number */}
                <div className="flex-shrink-0 w-7 h-7 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mt-0.5">
                    <span className="text-[10px] font-black text-slate-400">{finding.number}</span>
                </div>

                {/* Category icon */}
                <div className={`flex-shrink-0 p-1.5 rounded-lg ${cfg.bg} border ${cfg.border} mt-0.5`}>
                    <CatIcon className={`h-3.5 w-3.5 ${cfg.color}`} />
                </div>

                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className={`text-[9px] px-2 py-0.5 rounded border font-black uppercase tracking-widest ${cfg.badge}`}>{cfg.label}</span>
                        <span className="text-[10px] text-slate-500 uppercase tracking-wider">{finding.category.replace('_', ' ')}</span>
                    </div>
                    <p className="text-sm font-semibold text-slate-100">{finding.title}</p>
                    {!open && <p className="text-xs text-slate-400 mt-1 line-clamp-2">{finding.what_was_discovered}</p>}
                </div>

                <div className="flex-shrink-0 flex items-center gap-2">
                    <div className="text-right hidden sm:block">
                        <p className={`text-[10px] font-bold ${CONF_CFG[finding.confidence.tier].color}`}>{CONF_CFG[finding.confidence.tier].label}</p>
                        <p className="text-[9px] text-slate-500">confidence</p>
                    </div>
                    {open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
                </div>
            </button>

            {open && (
                <div className="border-t border-white/5 px-4 pb-5 pt-4 space-y-4">
                    {/* What was discovered */}
                    <div>
                        <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2 font-bold">What Was Discovered</p>
                        <p className="text-sm text-slate-200 leading-relaxed">{finding.what_was_discovered}</p>
                    </div>

                    {/* Why it matters */}
                    <div>
                        <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2 font-bold">Why It Matters</p>
                        <p className="text-sm text-slate-300 leading-relaxed">{finding.why_it_matters}</p>
                    </div>

                    {/* Evidence references */}
                    {finding.evidence_references.length > 0 && (
                        <div>
                            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2 font-bold">Evidence References</p>
                            <div className="space-y-2">
                                {finding.evidence_references.map((ref, i) => (
                                    <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-black/30 border border-white/5">
                                        <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${ref.role === 'primary' ? 'bg-violet-400' : ref.role === 'contradicting' ? 'bg-red-400' : 'bg-slate-400'}`} />
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                                                <code className="text-[10px] text-violet-300 font-mono">{ref.field}</code>
                                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-slate-400">{SOURCE_LABELS[ref.source] ?? ref.source}</span>
                                                <span className={`text-[9px] font-semibold ${ref.role === 'primary' ? 'text-violet-400' : ref.role === 'contradicting' ? 'text-red-400' : 'text-slate-400'}`}>{ref.role}</span>
                                            </div>
                                            <p className="text-xs font-mono text-slate-200 break-all">"{ref.value}"</p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Confidence reasoning */}
                    <div className={`p-3 rounded-lg ${CONF_CFG[finding.confidence.tier].color.replace('text-', 'bg-').replace('400', '950/30')} border border-white/5`}>
                        <div className="flex items-center gap-2 mb-2">
                            <CheckCircle2 className={`h-3.5 w-3.5 ${CONF_CFG[finding.confidence.tier].color}`} />
                            <span className={`text-[10px] font-bold uppercase tracking-wider ${CONF_CFG[finding.confidence.tier].color}`}>
                                {CONF_CFG[finding.confidence.tier].label} Confidence — {finding.confidence.score}/100
                            </span>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">{finding.confidence.reasoning}</p>
                        {finding.confidence.limiting_factors.length > 0 && (
                            <div className="mt-2 pt-2 border-t border-white/5">
                                <p className="text-[10px] text-slate-500 mb-1">To increase confidence:</p>
                                {finding.confidence.limiting_factors.map((f, i) => (
                                    <div key={i} className="flex items-start gap-1.5">
                                        <Circle className="h-1 w-1 text-slate-500 fill-current mt-1.5 shrink-0" />
                                        <p className="text-[11px] text-slate-400">{f}</p>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Limitations */}
                    {finding.limitations.length > 0 && (
                        <div>
                            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2 font-bold">Limitations & Caveats</p>
                            {finding.limitations.map((l, i) => (
                                <div key={i} className="flex items-start gap-2 py-0.5">
                                    <AlertTriangle className="h-3 w-3 text-slate-500 shrink-0 mt-0.5" />
                                    <p className="text-xs text-slate-400">{l}</p>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ── Section Panel ────────────────────────────────────────────────────────────

const SEC_ICONS: Record<string, React.ElementType> = {
    'File Identity & Integrity': Shield,
    'Author & Identity Attribution': User,
    'Temporal Chronology': Clock,
    'Geographic & Device Origin': MapPin,
    'Network & Infrastructure Exposure': Wifi,
    'Privacy Exposure Assessment': Eye,
};

function SectionPanel({ section }: { section: NonNullable<ForensicAnalystReport['sections']>[number] }) {
    const [open, setOpen] = useState(true);
    const SIcon = SEC_ICONS[section.title] ?? FileText;
    const hasCritical = section.severity_counts.critical > 0;
    const hasHigh = section.severity_counts.high > 0;

    return (
        <div className="rounded-2xl border border-slate-700/50 bg-slate-800/30 overflow-hidden">
            <button
                onClick={() => setOpen(v => !v)}
                className="w-full flex items-center gap-3 p-4 hover:bg-white/3 transition-colors text-left"
            >
                <div className="p-1.5 rounded-lg bg-white/5 border border-white/10">
                    <SIcon className={`h-4 w-4 ${hasCritical ? 'text-red-400' : hasHigh ? 'text-orange-400' : 'text-slate-400'}`} />
                </div>
                <div className="flex-1">
                    <p className="text-sm font-bold text-slate-100">{section.title}</p>
                    <div className="flex gap-2 flex-wrap mt-0.5">
                        {section.severity_counts.critical > 0 && <span className="text-[10px] text-red-400">● {section.severity_counts.critical} critical</span>}
                        {section.severity_counts.high > 0 && <span className="text-[10px] text-orange-400">● {section.severity_counts.high} high</span>}
                        {section.severity_counts.medium > 0 && <span className="text-[10px] text-amber-400">● {section.severity_counts.medium} medium</span>}
                        {section.severity_counts.low > 0 && <span className="text-[10px] text-sky-400">● {section.severity_counts.low} low</span>}
                        {section.severity_counts.informational > 0 && <span className="text-[10px] text-slate-400">● {section.severity_counts.informational} info</span>}
                    </div>
                </div>
                <div className="text-right mr-2">
                    <span className="text-xs text-slate-300 font-semibold">{section.findings.length} finding{section.findings.length !== 1 ? 's' : ''}</span>
                </div>
                {open ? <ChevronUp className="h-4 w-4 text-slate-500 shrink-0" /> : <ChevronDown className="h-4 w-4 text-slate-500 shrink-0" />}
            </button>

            {open && (
                <div className="border-t border-white/5 p-4 space-y-3">
                    {/* Section summary */}
                    <div className="flex items-start gap-2 p-3 rounded-lg bg-black/20 border border-white/5">
                        <Info className="h-4 w-4 text-slate-400 shrink-0 mt-0.5" />
                        <p className="text-xs text-slate-400 italic">{section.section_summary}</p>
                    </div>
                    {section.findings.map(f => (
                        <FindingCard key={f.id} finding={f} expanded={f.severity === 'critical'} />
                    ))}
                </div>
            )}
        </div>
    );
}

// ── Download as text ─────────────────────────────────────────────────────────

function downloadReport(report: ForensicAnalystReport) {
    const lines: string[] = [
        '═══════════════════════════════════════════════════════════════════',
        '   FORENSIC ANALYST REPORT',
        '═══════════════════════════════════════════════════════════════════',
        `   Report ID   : ${report.meta.report_id}`,
        `   Generated   : ${report.meta.generated_at}`,
        `   Engine      : Metadata Forensic Suite v2.0`,
        '═══════════════════════════════════════════════════════════════════',
        '',
        '── SUBJECT FILE ────────────────────────────────────────────────────',
        `   Name        : ${report.subject.file_name}`,
        `   Type        : ${report.subject.file_type}  (${report.subject.mime_type})`,
        `   Size        : ${(report.subject.file_size_bytes / 1024).toFixed(2)} KB`,
        `   SHA-256     : ${report.subject.sha256}`,
        `   Analyzed    : ${report.subject.analyzed_at}`,
        '',
        '── INTEGRITY VERDICT ───────────────────────────────────────────────',
        `   Status      : ${report.integrity_verdict.status.toUpperCase()}`,
        `   Confidence  : ${report.integrity_verdict.confidence}`,
        `   Summary     : ${report.integrity_verdict.summary}`,
        '',
        '── EXECUTIVE SUMMARY ───────────────────────────────────────────────',
        '',
        ...report.executive_summary.match(/.{1,70}(\s|$)/g)?.map(l => `   ${l.trim()}`) ?? [],
        '',
        `── FINDINGS SUMMARY: ${report.total_findings} finding(s) ─────────────────────────────`,
        `   Critical : ${report.findings_by_severity.critical}`,
        `   High     : ${report.findings_by_severity.high}`,
        `   Medium   : ${report.findings_by_severity.medium}`,
        `   Low      : ${report.findings_by_severity.low}`,
        `   Info     : ${report.findings_by_severity.informational}`,
        '',
    ];

    for (const section of report.sections) {
        lines.push(`── SECTION: ${section.title.toUpperCase()} ─────────────────────────────────────`);
        lines.push(`   ${section.section_summary}`);
        lines.push('');
        for (const f of section.findings) {
            lines.push(`   [${f.severity.toUpperCase().padEnd(13)}] F${String(f.number).padStart(3, '0')} ${f.title}`);
            lines.push(`   Confidence  : ${f.confidence.tier} (${f.confidence.score}/100)`);
            lines.push('');
            lines.push('   WHAT WAS DISCOVERED:');
            lines.push(`   ${f.what_was_discovered}`);
            lines.push('');
            lines.push('   WHY IT MATTERS:');
            lines.push(`   ${f.why_it_matters}`);
            lines.push('');
            if (f.evidence_references.length > 0) {
                lines.push('   EVIDENCE REFERENCES:');
                for (const ref of f.evidence_references) {
                    lines.push(`     [${ref.source.toUpperCase()} / ${ref.role}] ${ref.field} = "${ref.value}"`);
                }
                lines.push('');
            }
            lines.push('   CONFIDENCE REASONING:');
            lines.push(`   ${f.confidence.reasoning}`);
            lines.push('');
            if (f.limitations.length > 0) {
                lines.push('   LIMITATIONS:');
                f.limitations.forEach(l => lines.push(`     • ${l}`));
                lines.push('');
            }
            lines.push('   ' + '─'.repeat(64));
            lines.push('');
        }
    }

    if (report.established_timeline.length > 0) {
        lines.push('── ESTABLISHED TIMELINE ────────────────────────────────────────────');
        for (const e of report.established_timeline) {
            lines.push(`   ${e.utc}  ${e.flagged ? '⚠' : '✓'}  ${e.event}`);
            lines.push(`     Field: ${e.field}  Confidence: ${e.confidence}`);
        }
        lines.push('');
    }

    if (report.gaps_and_unknowns.length > 0) {
        lines.push('── GAPS & UNKNOWNS ─────────────────────────────────────────────────');
        for (const g of report.gaps_and_unknowns) {
            lines.push(`   • ${g}`);
        }
        lines.push('');
    }

    lines.push('── EXAMINER NOTE ───────────────────────────────────────────────────');
    lines.push(`   ${report.meta.examiner_note}`);
    lines.push('');
    lines.push('═══════════════════════════════════════════════════════════════════');
    lines.push('   END OF REPORT');
    lines.push('═══════════════════════════════════════════════════════════════════');

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-report-${report.subject.sha256.slice(0, 8)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ForensicReportPage() {
    const { analyses, currentAnalysis } = useForensic();
    const navigate = useNavigate();
    const latest = currentAnalysis ?? analyses[0] ?? null;

    const report: ForensicAnalystReport | null = useMemo(() => {
        if (!latest) return null;
        try {
            const n = normalizeMetadata(latest);
            const attribution = analyzeAttribution(n);
            const lifecycle = reconstructLifecycle(latest);
            const networkReport = analyzeNetworkOrigin(latest);
            const geo = analyzeGeoDevice(n);
            const privacy = analyzePrivacyRisk(latest, n);
            return generateForensicReport(latest, n, attribution, lifecycle, networkReport, geo, privacy);
        } catch (e) {
            console.error('Report generation error:', e);
            return null;
        }
    }, [latest]);

    const [activeTab, setActiveTab] = useState<'report' | 'timeline' | 'gaps' | 'meta'>('report');

    if (!latest || !report) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4 p-8">
                <div className="p-5 rounded-2xl bg-violet-500/10 border border-violet-500/20">
                    <BookOpen className="h-10 w-10 text-violet-400" />
                </div>
                <div className="text-center">
                    <h2 className="text-xl font-bold text-white mb-2">No File Analyzed Yet</h2>
                    <p className="text-slate-400 text-sm max-w-md">Upload and analyze a file first to generate a forensic analyst report.</p>
                </div>
                <Button onClick={() => navigate('/upload')} className="bg-violet-600 hover:bg-violet-700 text-white">Upload a File</Button>
            </div>
        );
    }

    const vCfg = VERDICT_CFG[report.integrity_verdict.status];
    const VIcon = vCfg.icon;

    return (
        <div className="max-w-5xl mx-auto px-4 py-6 space-y-6">

            {/* ── Header ── */}
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <BookOpen className="h-5 w-5 text-violet-400" />
                        <h1 className="text-xl font-bold text-white">Forensic Analyst Report</h1>
                    </div>
                    <p className="text-slate-400 text-sm">Evidence-cited findings · Confidence reasoning · No speculation beyond metadata</p>
                    <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                        <code className="text-[10px] text-slate-500 font-mono">{report.meta.report_id}</code>
                        <span className="text-[10px] text-slate-600">·</span>
                        <code className="text-[10px] text-slate-500 font-mono">{report.subject.sha256.slice(0, 16)}…</code>
                    </div>
                </div>
                <Button
                    onClick={() => downloadReport(report)}
                    className="flex items-center gap-2 bg-violet-600 hover:bg-violet-700 text-white text-sm shrink-0"
                >
                    <Download className="h-3.5 w-3.5" />
                    Download .txt
                </Button>
            </div>

            {/* ── Verdict Hero ── */}
            <Card className={`border-2 ${vCfg.border} ${vCfg.bg} backdrop-blur-sm`}>
                <CardContent className="p-5">
                    <div className="flex items-center gap-4">
                        <div className={`p-3 rounded-xl ${vCfg.bg} border ${vCfg.border}`}>
                            <VIcon className={`h-8 w-8 ${vCfg.color}`} />
                        </div>
                        <div className="flex-1">
                            <div className="flex items-center gap-3 mb-1">
                                <span className={`text-xs px-3 py-1 rounded-full border font-black uppercase tracking-widest ${vCfg.border} ${vCfg.bg} ${vCfg.color}`}>
                                    {vCfg.label}
                                </span>
                                <span className={`text-xs ${CONF_CFG[report.integrity_verdict.confidence].color} font-semibold`}>
                                    {CONF_CFG[report.integrity_verdict.confidence].label} Confidence
                                </span>
                            </div>
                            <p className="text-sm text-slate-300 leading-relaxed">{report.integrity_verdict.summary}</p>
                        </div>
                    </div>

                    {/* Finding counts */}
                    <div className="grid grid-cols-5 gap-2 mt-4">
                        {([
                            { sev: 'critical', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
                            { sev: 'high', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
                            { sev: 'medium', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
                            { sev: 'low', color: 'text-sky-400', bg: 'bg-sky-500/10 border-sky-500/20' },
                            { sev: 'informational', color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/20' },
                        ] as const).map(({ sev, color, bg }) => (
                            <div key={sev} className={`rounded-lg border ${bg} p-2 text-center`}>
                                <p className={`text-xl font-black ${color}`}>{report.findings_by_severity[sev]}</p>
                                <p className="text-[9px] text-slate-400 uppercase tracking-wide capitalize">{sev === 'informational' ? 'Info' : sev}</p>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>

            {/* ── Executive Summary ── */}
            <Card className="bg-slate-800/40 border-slate-700/50">
                <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-semibold text-slate-100">Executive Summary</CardTitle>
                </CardHeader>
                <CardContent>
                    <p className="text-sm text-slate-300 leading-relaxed">{report.executive_summary}</p>
                </CardContent>
            </Card>

            {/* ── Tab Navigation ── */}
            <div className="flex gap-1 p-1 bg-slate-800/60 border border-slate-700/50 rounded-xl w-full overflow-x-auto">
                {[
                    { key: 'report', label: `Findings (${report.total_findings})`, icon: FileText },
                    { key: 'timeline', label: `Timeline (${report.established_timeline.length})`, icon: Clock },
                    { key: 'gaps', label: `Gaps (${report.gaps_and_unknowns.length})`, icon: AlertTriangle },
                    { key: 'meta', label: 'Methodology', icon: Info },
                ].map(({ key, label, icon: Icon }) => (
                    <button
                        key={key}
                        onClick={() => setActiveTab(key as typeof activeTab)}
                        className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold transition-all whitespace-nowrap ${activeTab === key ? 'bg-white/10 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                            }`}
                    >
                        <Icon className="h-3.5 w-3.5" />
                        {label}
                    </button>
                ))}
            </div>

            {/* ── Findings Sections ── */}
            {activeTab === 'report' && (
                <div className="space-y-4">
                    {report.sections.map((section, i) => (
                        <SectionPanel key={i} section={section} />
                    ))}
                </div>
            )}

            {/* ── Timeline ── */}
            {activeTab === 'timeline' && (
                <Card className="bg-slate-800/40 border-slate-700/50">
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                            <Clock className="h-4 w-4 text-violet-400" />
                            Established Chronological Timeline
                        </CardTitle>
                        <CardDescription className="text-xs text-slate-400">
                            All provable temporal events extracted from metadata, sorted chronologically.
                            Flagged (⚠) events have integrity concerns.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {report.established_timeline.length === 0 ? (
                            <p className="text-sm text-slate-500 text-center py-6">No timestamp metadata available to build a timeline.</p>
                        ) : (
                            <div className="relative">
                                <div className="absolute left-[52px] top-0 bottom-0 w-px bg-white/10" />
                                <div className="space-y-4">
                                    {report.established_timeline.map((entry, i) => (
                                        <div key={i} className="flex items-start gap-4 relative">
                                            {/* Dot */}
                                            <div className={`flex-shrink-0 w-6 h-6 rounded-full border-2 ${entry.flagged ? 'border-red-500 bg-red-950/50' : 'border-violet-500 bg-violet-950/50'} flex items-center justify-center z-10 mt-0.5 ml-6`}>
                                                {entry.flagged
                                                    ? <AlertTriangle className="h-3 w-3 text-red-400" />
                                                    : <Circle className="h-2 w-2 text-violet-400 fill-current" />}
                                            </div>
                                            {/* Content */}
                                            <div className="flex-1 pb-2">
                                                <p className="text-xs text-slate-100 font-semibold">{entry.event}</p>
                                                <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                                                    <code className="text-[10px] text-violet-300 font-mono">{entry.utc}</code>
                                                    <span className={`text-[10px] font-semibold ${CONF_CFG[entry.confidence].color}`}>{CONF_CFG[entry.confidence].label} confidence</span>
                                                </div>
                                                <code className="text-[10px] text-slate-500 font-mono">{entry.field}</code>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </CardContent>
                </Card>
            )}

            {/* ── Gaps & Unknowns ── */}
            {activeTab === 'gaps' && (
                <Card className="bg-slate-800/40 border-slate-700/50">
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4 text-amber-400" />
                            Gaps & Unknowns
                        </CardTitle>
                        <CardDescription className="text-xs text-slate-400">
                            Information that could not be determined from available metadata. Explicitly stated to avoid misrepresentation.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {report.gaps_and_unknowns.length === 0 ? (
                            <div className="flex items-center gap-2 py-6 justify-center">
                                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                                <p className="text-sm text-emerald-400">No significant gaps detected</p>
                            </div>
                        ) : (
                            <div className="space-y-2">
                                {report.gaps_and_unknowns.map((gap, i) => (
                                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-amber-950/10 border border-amber-500/20">
                                        <span className="text-[10px] font-black text-amber-400 mt-0.5 shrink-0">G{String(i + 1).padStart(2, '0')}</span>
                                        <p className="text-sm text-slate-300 leading-relaxed">{gap}</p>
                                    </div>
                                ))}
                            </div>
                        )}
                    </CardContent>
                </Card>
            )}

            {/* ── Methodology ── */}
            {activeTab === 'meta' && (
                <div className="space-y-4">
                    <Card className="bg-slate-800/40 border-slate-700/50">
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-semibold text-slate-100">Scope of Analysis</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-1.5">
                                {report.meta.scope_of_analysis.map((s, i) => (
                                    <div key={i} className="flex items-start gap-2">
                                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
                                        <p className="text-xs text-slate-300">{s}</p>
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>

                    <Card className="bg-slate-800/40 border-slate-700/50">
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-semibold text-slate-100">Limitations of This Analysis</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-1.5">
                                {report.meta.limitations_of_analysis.map((l, i) => (
                                    <div key={i} className="flex items-start gap-2">
                                        <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
                                        <p className="text-xs text-slate-300">{l}</p>
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>

                    <Card className="bg-slate-800/40 border-slate-700/50">
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-semibold text-slate-100">Examiner Note</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <p className="text-xs text-slate-400 leading-relaxed italic">{report.meta.examiner_note}</p>
                        </CardContent>
                    </Card>
                </div>
            )}

            {/* Footer */}
            <div className="flex items-start gap-2.5 p-4 rounded-xl bg-slate-800/40 border border-slate-700/40 text-xs text-slate-400">
                <Hash className="h-4 w-4 text-slate-500 shrink-0 mt-0.5" />
                <p>
                    All findings in this report are derived exclusively from the file's embedded metadata.
                    No content analysis, external database lookups, or speculation beyond the available evidence is included.
                    Report ID: <code className="font-mono text-violet-300">{report.meta.report_id}</code>
                </p>
            </div>
        </div>
    );
}
