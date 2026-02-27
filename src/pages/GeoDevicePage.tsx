import { useMemo, useState } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { normalizeMetadata } from '@/lib/metadata-normalizer';
import { analyzeGeoDevice, GeoDeviceReport } from '@/lib/geo-device-analyzer';
import {
    MapPin, Smartphone, Monitor, Globe2, Languages, AlertTriangle,
    CheckCircle2, Info, ChevronDown, ChevronUp, Cpu, Compass,
    Navigation, Radio, ExternalLink, ShieldAlert, Radar
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { useNavigate } from 'react-router-dom';

// ── Helpers ──────────────────────────────────────────────────────────────────

function confidenceBadge(c: string) {
    const map: Record<string, string> = {
        exact: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
        high: 'bg-sky-500/20 text-sky-400 border-sky-500/30',
        moderate: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
        low: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
        unknown: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
        none: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
        definitive: 'bg-violet-500/20 text-violet-400 border-violet-500/30',
    };
    return map[c] ?? map.unknown;
}

function methodLabel(m: string) {
    const labels: Record<string, string> = {
        gps_exact: 'GPS Coordinates',
        timezone: 'Timezone Analysis',
        device_make: 'Device Make',
        language: 'Language Fingerprint',
        software_locale: 'Software Locale',
        combined: 'Multi-Signal Fusion',
        none: 'Insufficient Data',
    };
    return labels[m] ?? m;
}

function osEcosystemIcon(os: string | null) {
    if (!os) return '❓';
    const lower = os.toLowerCase();
    if (lower.includes('ios') || lower.includes('ipad')) return '📱';
    if (lower.includes('macos')) return '💻';
    if (lower.includes('android')) return '🤖';
    if (lower.includes('windows')) return '🪟';
    if (lower.includes('linux')) return '🐧';
    if (lower.includes('chromeos')) return '🌐';
    return '💾';
}

function deviceCategoryIcon(cat: string) {
    if (cat === 'smartphone') return '📱';
    if (cat === 'tablet') return '📟';
    if (cat === 'dslr_mirrorless') return '📷';
    if (cat === 'laptop_desktop') return '🖥️';
    return '📦';
}

// ── Info Row ─────────────────────────────────────────────────────────────────

function InfoRow({ label, value, mono = false, badge, accent }: {
    label: string;
    value: React.ReactNode;
    mono?: boolean;
    badge?: string;
    accent?: string;
}) {
    return (
        <div className="flex items-start justify-between py-2.5 border-b border-white/5 last:border-0 gap-4">
            <span className="text-xs text-slate-400 shrink-0 pt-0.5 w-44">{label}</span>
            <div className="flex items-center gap-2 flex-1 justify-end flex-wrap">
                {badge && (
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold uppercase tracking-wider ${confidenceBadge(badge)}`}>
                        {badge}
                    </span>
                )}
                <span className={`text-sm text-right ${mono ? 'font-mono text-xs text-emerald-300' : 'text-slate-200'} ${accent ?? ''}`}>
                    {value}
                </span>
            </div>
        </div>
    );
}

// ── Section Card ─────────────────────────────────────────────────────────────

function SectionCard({ icon: Icon, title, subtitle, children, accentColor = 'text-violet-400', iconBg = 'bg-violet-500/10' }: {
    icon: React.ElementType;
    title: string;
    subtitle?: string;
    children: React.ReactNode;
    accentColor?: string;
    iconBg?: string;
}) {
    return (
        <Card className="bg-slate-800/50 border-slate-700/50 backdrop-blur-sm">
            <CardHeader className="pb-3">
                <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${iconBg}`}>
                        <Icon className={`h-4 w-4 ${accentColor}`} />
                    </div>
                    <div>
                        <CardTitle className="text-sm font-semibold text-slate-100">{title}</CardTitle>
                        {subtitle && <CardDescription className="text-xs text-slate-400 mt-0.5">{subtitle}</CardDescription>}
                    </div>
                </div>
            </CardHeader>
            <CardContent>{children}</CardContent>
        </Card>
    );
}

// ── Origin Reasoning Panel ────────────────────────────────────────────────────

function OriginReasoningPanel({ report }: { report: GeoDeviceReport }) {
    const [expanded, setExpanded] = useState(true);
    const origin = report.originEstimate;

    return (
        <Card className={`border-2 ${origin.confidence === 'exact' ? 'border-emerald-500/40 bg-emerald-950/20' :
            origin.confidence === 'high' ? 'border-sky-500/40 bg-sky-950/20' :
                origin.confidence === 'moderate' ? 'border-amber-500/40 bg-amber-950/20' :
                    origin.confidence === 'low' ? 'border-orange-500/40 bg-orange-950/20' :
                        'border-slate-600/40 bg-slate-900/30'
            } backdrop-blur-sm`}>
            <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-white/5">
                            <span className="text-2xl leading-none">{origin.regionEmoji}</span>
                        </div>
                        <div>
                            <p className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-1">Estimated Origin Region</p>
                            <h2 className="text-xl font-bold text-white leading-tight">{origin.region}</h2>
                            {origin.subRegion && (
                                <p className="text-sm text-slate-300 mt-0.5">{origin.subRegion}</p>
                            )}
                        </div>
                    </div>
                    <div className="text-right">
                        <span className={`text-xs px-3 py-1.5 rounded-full border font-bold uppercase tracking-widest ${confidenceBadge(origin.confidence)}`}>
                            {origin.confidence}
                        </span>
                        <p className="text-[10px] text-slate-500 mt-1.5">{methodLabel(origin.inferenceMethod)}</p>
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <button
                    onClick={() => setExpanded(v => !v)}
                    className="w-full flex items-center justify-between text-xs text-slate-400 hover:text-slate-200 transition-colors mb-3 group"
                >
                    <span className="flex items-center gap-1.5">
                        <Radar className="h-3.5 w-3.5" />
                        Inference Reasoning Chain ({origin.reasoning.length} steps)
                    </span>
                    {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                </button>

                {expanded && (
                    <div className="space-y-2">
                        {origin.reasoning.map((r, i) => (
                            <div key={i} className="flex gap-2.5 items-start">
                                <div className="flex-shrink-0 w-5 h-5 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mt-0.5">
                                    <span className="text-[9px] font-bold text-slate-400">{i + 1}</span>
                                </div>
                                <p className="text-xs text-slate-300 leading-relaxed">{r}</p>
                            </div>
                        ))}
                    </div>
                )}

                {origin.caveats.length > 0 && (
                    <div className="mt-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 space-y-1.5">
                        <div className="flex items-center gap-1.5 mb-2">
                            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                            <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Caveats</span>
                        </div>
                        {origin.caveats.map((c, i) => (
                            <p key={i} className="text-xs text-amber-200/80">{c}</p>
                        ))}
                    </div>
                )}
            </CardContent>
        </Card>
    );
}

// ── GPS Panel ────────────────────────────────────────────────────────────────

function GpsPanel({ report }: { report: GeoDeviceReport }) {
    const gps = report.gpsCoordinates;

    if (!gps) {
        return (
            <SectionCard icon={MapPin} title="GPS Coordinates" subtitle="No GPS data embedded" accentColor="text-slate-400" iconBg="bg-slate-500/10">
                <div className="flex flex-col items-center py-6 text-center gap-3">
                    <div className="p-4 rounded-full bg-slate-700/30">
                        <Navigation className="h-8 w-8 text-slate-500" />
                    </div>
                    <div>
                        <p className="text-sm text-slate-400">No GPS coordinates found in file metadata</p>
                        <p className="text-xs text-slate-500 mt-1">GPS is typically embedded by smartphones and cameras with location services enabled</p>
                    </div>
                </div>
            </SectionCard>
        );
    }

    return (
        <SectionCard
            icon={MapPin}
            title="GPS Coordinates"
            subtitle="Precise location data embedded by device"
            accentColor="text-emerald-400"
            iconBg="bg-emerald-500/10"
        >
            {gps.suspicion !== 'none' && (
                <div className="mb-3 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
                    <p className="text-xs text-amber-300">
                        Suspicious coordinates detected: <strong>{gps.suspicion.replace('_', ' ')}</strong>
                    </p>
                </div>
            )}

            <div className="grid grid-cols-2 gap-3 mb-4">
                <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-center">
                    <p className="text-[10px] text-emerald-400/70 uppercase tracking-widest mb-1">Latitude</p>
                    <p className="text-lg font-mono font-bold text-emerald-300">{gps.latitude.toFixed(6)}°</p>
                    <p className="text-[10px] text-emerald-400/50">{gps.latitude >= 0 ? 'N' : 'S'}</p>
                </div>
                <div className="p-3 rounded-lg bg-sky-500/10 border border-sky-500/20 text-center">
                    <p className="text-[10px] text-sky-400/70 uppercase tracking-widest mb-1">Longitude</p>
                    <p className="text-lg font-mono font-bold text-sky-300">{gps.longitude.toFixed(6)}°</p>
                    <p className="text-[10px] text-sky-400/50">{gps.longitude >= 0 ? 'E' : 'W'}</p>
                </div>
            </div>

            <InfoRow label="Altitude" value={gps.altitudeMetres !== null ? `${gps.altitudeMetres} m` : 'Not recorded'} />
            <InfoRow label="Precision Estimate" value={gps.precision} />
            <InfoRow label="Suspicion Flag" value={gps.suspicion === 'none' ? 'None — coordinates appear valid' : gps.suspicion} />

            <a
                href={gps.googleMapsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-4 flex items-center justify-center gap-2 w-full py-2.5 rounded-lg bg-emerald-500/15 border border-emerald-500/25 text-emerald-300 text-sm hover:bg-emerald-500/25 transition-colors"
            >
                <ExternalLink className="h-4 w-4" />
                Open in Google Maps
            </a>
        </SectionCard>
    );
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function GeoDevicePage() {
    const { analyses, currentAnalysis } = useForensic();
    const navigate = useNavigate();
    const latest = currentAnalysis ?? analyses[0] ?? null;

    const report: GeoDeviceReport | null = useMemo(() => {
        if (!latest) return null;
        const norm = normalizeMetadata(latest);
        return analyzeGeoDevice(norm);
    }, [latest]);

    if (!latest || !report) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4 p-8">
                <div className="p-5 rounded-2xl bg-violet-500/10 border border-violet-500/20">
                    <Globe2 className="h-10 w-10 text-violet-400" />
                </div>
                <div className="text-center">
                    <h2 className="text-xl font-bold text-white mb-2">No File Analyzed Yet</h2>
                    <p className="text-slate-400 text-sm max-w-md">
                        Upload and analyze a file first to see geographic and device indicators.
                    </p>
                </div>
                <Button onClick={() => navigate('/upload')} className="bg-violet-600 hover:bg-violet-700 text-white">
                    Upload a File
                </Button>
            </div>
        );
    }

    const { deviceProfile, osEcosystem, osConfidence, osEvidenceSources, regionalProfile, languageFingerprint, originEstimate, osintLeads } = report;

    return (
        <div className="max-w-6xl mx-auto px-4 py-6 space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <Globe2 className="h-5 w-5 text-violet-400" />
                        <h1 className="text-xl font-bold text-white">Geographic & Device Indicators</h1>
                    </div>
                    <p className="text-slate-400 text-sm">
                        GPS extraction · Device fingerprinting · OS ecosystem · Regional settings · Language fingerprint · Origin estimation
                    </p>
                    <p className="text-xs text-slate-500 mt-1 font-mono">
                        Analyzing: <span className="text-violet-300">{report.fileName}</span>
                    </p>
                </div>
                <div className="flex flex-col items-end gap-1.5">
                    <span className={`text-xs px-3 py-1.5 rounded-full border font-bold uppercase tracking-widest ${report.gpsAvailable ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-slate-500/20 text-slate-400 border-slate-500/30'
                        }`}>
                        {report.gpsAvailable ? '📍 GPS Available' : '📍 GPS Inferred'}
                    </span>
                    <p className="text-[10px] text-slate-500">
                        Analyzed {new Date(report.analyzedAt).toLocaleTimeString()}
                    </p>
                </div>
            </div>

            {/* Origin Estimate — Primary Panel */}
            <OriginReasoningPanel report={report} />

            {/* 2-column grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* GPS */}
                <GpsPanel report={report} />

                {/* Device Profile */}
                <SectionCard
                    icon={Smartphone}
                    title="Device Profile"
                    subtitle="Camera / device model fingerprint"
                    accentColor="text-sky-400"
                    iconBg="bg-sky-500/10"
                >
                    {deviceProfile.fullDeviceString ? (
                        <>
                            <div className="p-3 mb-4 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center gap-3">
                                <span className="text-3xl">{deviceCategoryIcon(deviceProfile.category)}</span>
                                <div>
                                    <p className="text-sm font-bold text-sky-200">{deviceProfile.fullDeviceString}</p>
                                    <p className="text-xs text-sky-400/70 capitalize mt-0.5">{deviceProfile.category.replace('_', ' ')}</p>
                                </div>
                            </div>
                            <InfoRow label="Make" value={deviceProfile.make ?? '—'} />
                            <InfoRow label="Model" value={deviceProfile.model ?? '—'} />
                            <InfoRow label="Brand" value={deviceProfile.brand ?? '—'} />
                            <InfoRow label="Category" value={deviceProfile.category.replace(/_/g, ' ')} />
                        </>
                    ) : (
                        <div className="flex flex-col items-center py-6 text-center gap-2">
                            <Cpu className="h-8 w-8 text-slate-500" />
                            <p className="text-sm text-slate-400">No device model found in metadata</p>
                            <p className="text-xs text-slate-500">Device info is typically embedded by cameras and smartphones</p>
                        </div>
                    )}
                </SectionCard>

                {/* OS Ecosystem */}
                <SectionCard
                    icon={Monitor}
                    title="OS Ecosystem"
                    subtitle="Inferred operating system / platform"
                    accentColor="text-purple-400"
                    iconBg="bg-purple-500/10"
                >
                    <div className="flex items-center gap-4 p-4 rounded-lg bg-purple-500/10 border border-purple-500/20 mb-4">
                        <span className="text-4xl">{osEcosystemIcon(osEcosystem)}</span>
                        <div>
                            <p className="text-base font-bold text-purple-200">{osEcosystem ?? 'Unknown'}</p>
                            <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold uppercase tracking-wider mt-1 inline-block ${confidenceBadge(osConfidence)}`}>
                                {osConfidence} confidence
                            </span>
                        </div>
                    </div>
                    <div className="space-y-2">
                        {osEvidenceSources.length > 0 ? (
                            <>
                                <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2">Evidence Sources</p>
                                {osEvidenceSources.map((s, i) => (
                                    <div key={i} className="flex items-start gap-2">
                                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 mt-0.5 shrink-0" />
                                        <p className="text-xs text-slate-300">{s}</p>
                                    </div>
                                ))}
                            </>
                        ) : (
                            <p className="text-xs text-slate-500 italic">No OS evidence sources detected</p>
                        )}
                    </div>
                </SectionCard>

                {/* Regional Settings */}
                <SectionCard
                    icon={Compass}
                    title="Regional Settings"
                    subtitle="Timezone, locale, date format hints"
                    accentColor="text-amber-400"
                    iconBg="bg-amber-500/10"
                >
                    {regionalProfile.detectedTimezone || regionalProfile.timezoneUtcOffset ? (
                        <>
                            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 mb-4">
                                <p className="text-xs text-amber-400/70 uppercase tracking-widest mb-1">Timezone</p>
                                <p className="text-sm font-mono font-bold text-amber-200">
                                    {regionalProfile.detectedTimezone ?? regionalProfile.timezoneUtcOffset}
                                </p>
                                {regionalProfile.timezoneUtcOffset && (
                                    <p className="text-xs text-amber-300/60 mt-0.5">{regionalProfile.timezoneUtcOffset}</p>
                                )}
                            </div>
                            <InfoRow label="Region (from TZ)" value={regionalProfile.likelyRegionFromTimezone ?? 'Could not map'} />
                            <InfoRow label="Date Format Hint" value={
                                regionalProfile.dateFormatHint === 'MDY' ? 'Month/Day/Year (US)' :
                                    regionalProfile.dateFormatHint === 'DMY' ? 'Day/Month/Year (EU)' :
                                        regionalProfile.dateFormatHint === 'YMD' ? 'Year-Month-Day (ISO/Asia)' :
                                            'Unknown'
                            } />
                            <InfoRow label="Embedded Locale" value={regionalProfile.embeddedLocale ?? 'Not detected'} />
                        </>
                    ) : (
                        <div className="flex flex-col items-center py-6 text-center gap-2">
                            <Compass className="h-8 w-8 text-slate-500" />
                            <p className="text-sm text-slate-400">No timezone or locale data embedded</p>
                            <p className="text-xs text-slate-500">Timezone info is embedded by some cameras and mobile devices</p>
                        </div>
                    )}
                </SectionCard>

                {/* Language Fingerprint */}
                <SectionCard
                    icon={Languages}
                    title="Language Fingerprints"
                    subtitle="Detected languages, scripts, locale clues"
                    accentColor="text-rose-400"
                    iconBg="bg-rose-500/10"
                >
                    {languageFingerprint.primaryLanguage || languageFingerprint.scriptDetected ? (
                        <>
                            <div className="flex flex-wrap gap-2 mb-4">
                                {languageFingerprint.detectedLanguages.map(l => (
                                    <span key={l} className="text-xs px-2.5 py-1 rounded-full bg-rose-500/15 border border-rose-500/25 text-rose-300 font-mono">
                                        {l}
                                    </span>
                                ))}
                                {languageFingerprint.scriptDetected && (
                                    <span className="text-xs px-2.5 py-1 rounded-full bg-violet-500/15 border border-violet-500/25 text-violet-300">
                                        Script: {languageFingerprint.scriptDetected}
                                    </span>
                                )}
                                {languageFingerprint.rtlScript && (
                                    <span className="text-xs px-2.5 py-1 rounded-full bg-amber-500/15 border border-amber-500/25 text-amber-300">
                                        RTL Layout
                                    </span>
                                )}
                            </div>

                            <InfoRow label="Primary Language" value={languageFingerprint.primaryLanguage ?? '—'} />

                            {languageFingerprint.languageSource.length > 0 && (
                                <div className="mt-3 space-y-1.5">
                                    <p className="text-[10px] text-slate-500 uppercase tracking-widest">Detection Sources</p>
                                    {languageFingerprint.languageSource.map((s, i) => (
                                        <div key={i} className="flex items-start gap-2">
                                            <Info className="h-3 w-3 text-rose-400 mt-0.5 shrink-0" />
                                            <p className="text-xs text-slate-400">{s}</p>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {languageFingerprint.languageClues.length > 0 && (
                                <div className="mt-3 space-y-1.5">
                                    <p className="text-[10px] text-slate-500 uppercase tracking-widest">Cultural Clues</p>
                                    {languageFingerprint.languageClues.map((c, i) => (
                                        <div key={i} className="flex items-start gap-2">
                                            <Radio className="h-3 w-3 text-amber-400 mt-0.5 shrink-0" />
                                            <p className="text-xs text-slate-300">{c}</p>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    ) : (
                        <div className="flex flex-col items-center py-6 text-center gap-2">
                            <Languages className="h-8 w-8 text-slate-500" />
                            <p className="text-sm text-slate-400">No language fingerprints detected</p>
                            <p className="text-xs text-slate-500">Language clues may appear in author names, software strings, or locale codes</p>
                        </div>
                    )}
                </SectionCard>

                {/* OSINT Leads */}
                <SectionCard
                    icon={Radar}
                    title="OSINT Investigation Leads"
                    subtitle="Geo-specific investigation entry points"
                    accentColor="text-cyan-400"
                    iconBg="bg-cyan-500/10"
                >
                    {osintLeads.length > 0 ? (
                        <div className="space-y-2.5">
                            {osintLeads.map((lead, i) => (
                                <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-cyan-500/5 border border-cyan-500/15 hover:border-cyan-500/30 transition-colors">
                                    <div className="flex-shrink-0 w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center mt-0.5">
                                        <span className="text-[9px] font-bold text-cyan-400">{i + 1}</span>
                                    </div>
                                    <p className="text-xs text-slate-300 leading-relaxed">{lead}</p>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="flex flex-col items-center py-6 text-center gap-2">
                            <Radar className="h-8 w-8 text-slate-500" />
                            <p className="text-sm text-slate-400">No OSINT leads generated</p>
                        </div>
                    )}
                </SectionCard>
            </div>

            {/* Disclaimer */}
            <div className="flex items-start gap-2.5 p-4 rounded-xl bg-slate-800/40 border border-slate-700/40 text-xs text-slate-400">
                <Info className="h-4 w-4 text-slate-500 shrink-0 mt-0.5" />
                <p>
                    Geographic estimation uses metadata signals (GPS, timezone, language codes, device make, software locale) to infer origin region.
                    Without embedded GPS coordinates, estimates are probabilistic — not definitive. Always cross-reference with corroborating
                    evidence from other forensic engines before drawing conclusions.
                </p>
            </div>
        </div>
    );
}
