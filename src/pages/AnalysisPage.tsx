import { useState } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { exportReport } from '@/lib/pdf-export';
import {
  Shield, AlertTriangle, CheckCircle, XCircle, Download,
  User, Network, Cpu, Clock, MapPin, EyeOff, BarChart3,
  Mail, Globe, Server, Hash, Monitor, Calendar,
  FileText, Fingerprint, ChevronDown, ChevronUp, Zap, Code2, LayoutList
} from 'lucide-react';

// ── Helpers ────────────────────────────────────────────────────────────────
const riskColors: Record<string, string> = {
  low: '#22c55e', medium: '#eab308', high: '#ef4444',
};
const statusConfig = {
  authentic: { icon: CheckCircle, label: 'Authentic', className: 'text-emerald-400 border-emerald-500/25 bg-emerald-500/5' },
  suspicious: { icon: AlertTriangle, label: 'Suspicious', className: 'text-yellow-400 border-yellow-500/25 bg-yellow-400/5' },
  tampered: { icon: XCircle, label: 'Tampered', className: 'text-red-400   border-red-500/25   bg-red-500/5' },
};
const confidenceColor: Record<string, string> = {
  high: 'text-red-400', medium: 'text-yellow-400', low: 'text-blue-400', none: 'text-muted-foreground'
};

function RiskGauge({ score, level }: { score: number; level: string }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const color = riskColors[level];
  return (
    <div className="relative flex items-center justify-center w-32 h-32">
      <svg className="absolute inset-0 -rotate-90" width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r={r} fill="none" stroke="hsl(222,30%,14%)" strokeWidth="9" />
        <circle cx="64" cy="64" r={r} fill="none" stroke={color} strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * circ} ${circ}`}
          style={{ filter: `drop-shadow(0 0 5px ${color})`, transition: 'stroke-dasharray 1s ease' }}
        />
      </svg>
      <div className="text-center z-10">
        <p className="text-2xl font-black font-mono tabular-nums" style={{ color }}>{score}</p>
        <p className="text-[10px] text-muted-foreground uppercase tracking-widest">/100</p>
      </div>
    </div>
  );
}

function Section({ icon: Icon, title, color, children, defaultOpen = true }: {
  icon: React.ComponentType<{ className?: string }>;
  title: string; color: string; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Card className="overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-5 py-3 border-b border-border/50 hover:bg-accent/20 transition-colors text-left"
        onClick={() => setOpen(o => !o)}
      >
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-sm font-semibold flex-1">{title}</span>
        {open ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
      </button>
      {open && <CardContent className="p-4">{children}</CardContent>}
    </Card>
  );
}

function Field({ label, value, mono, badge, badgeVariant }: {
  label: string; value?: string | null; mono?: boolean;
  badge?: boolean; badgeVariant?: 'default' | 'secondary' | 'destructive' | 'outline';
}) {
  if (!value) return null;
  return (
    <div className="flex items-start gap-2 py-1.5 border-b border-border/30 last:border-0">
      <span className="text-xs text-muted-foreground shrink-0 w-36">{label}</span>
      {badge
        ? <Badge variant={badgeVariant || 'secondary'} className="text-xs">{value}</Badge>
        : <span className={`text-xs text-foreground break-all ${mono ? 'font-mono' : 'font-medium'}`}>{value}</span>
      }
    </div>
  );
}

function TagList({ items, color = 'text-foreground', emptyMsg = 'None detected' }: { items: string[]; color?: string; emptyMsg?: string }) {
  if (items.length === 0) return <p className="text-xs text-muted-foreground italic">{emptyMsg}</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((v, i) => (
        <span key={i} className={`text-xs font-mono px-2 py-0.5 rounded bg-muted border border-border/50 ${color}`}>{v}</span>
      ))}
    </div>
  );
}

function FlagList({ items, emptyMsg = 'No indicators found', icon: Icon = AlertTriangle }: { items: string[]; emptyMsg?: string; icon?: React.ComponentType<{ className?: string }> }) {
  if (items.length === 0) return (
    <div className="flex items-center gap-2 text-emerald-400 text-xs">
      <CheckCircle className="h-3.5 w-3.5" /> <span>{emptyMsg}</span>
    </div>
  );
  return (
    <div className="space-y-1.5">
      {items.map((v, i) => (
        <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-muted/50 border border-border/30">
          <Icon className="h-3.5 w-3.5 text-yellow-400 mt-0.5 shrink-0" />
          <span className="text-xs text-foreground">{v}</span>
        </div>
      ))}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function AnalysisPage() {
  const { currentAnalysis } = useForensic();
  const [viewMode, setViewMode] = useState<'report' | 'json'>('report');

  if (!currentAnalysis) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] gap-4 text-center">
        <div className="p-5 rounded-2xl bg-muted"><Shield className="h-12 w-12 text-muted-foreground/30" /></div>
        <div>
          <p className="font-medium text-foreground">No analysis loaded</p>
          <p className="text-sm text-muted-foreground mt-1">Upload a file on the Upload page to begin.</p>
        </div>
      </div>
    );
  }

  const r = currentAnalysis;
  const m = r.metadata;
  const net = r.networkIndicators;
  const art = r.hiddenArtifacts;
  const fa = r.forensicAssessment;
  const sc = statusConfig[r.integrityStatus];
  const ScIcon = sc.icon;

  const highCount = r.anomalies.filter(a => a.severity === 'high').length;
  const medCount = r.anomalies.filter(a => a.severity === 'medium').length;
  const lowCount = r.anomalies.filter(a => a.severity === 'low').length;

  // ── Download JSON helper ──
  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(r.rawForensicJSON, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic_report_${m.fileName.replace(/[^a-z0-9]/gi, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-5xl mx-auto space-y-4">

      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest mb-1">Deep Forensic Report · {r.analyzedAt.toLocaleString()}</p>
          <h1 className="text-xl font-bold text-foreground truncate max-w-xl">{m.fileName}</h1>
          <p className="text-[11px] text-muted-foreground mt-0.5 font-mono">SHA-256: {m.sha256Hash}</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* View mode tabs */}
          <div className="flex rounded-lg border border-border overflow-hidden">
            <button
              onClick={() => setViewMode('report')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${viewMode === 'report' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent/40'
                }`}
            >
              <LayoutList className="h-3 w-3" /> Forensic Report
            </button>
            <button
              onClick={() => setViewMode('json')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${viewMode === 'json' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent/40'
                }`}
            >
              <Code2 className="h-3 w-3" /> Raw JSON
            </button>
          </div>
          <Button onClick={() => exportReport(r)} variant="outline" size="sm" className="gap-2">
            <Download className="h-3.5 w-3.5" /> Export PDF
          </Button>
          {viewMode === 'json' && (
            <Button onClick={downloadJSON} size="sm" className="gap-2">
              <Download className="h-3.5 w-3.5" /> Download JSON
            </Button>
          )}
        </div>
      </div>

      {/* ── Risk summary bar ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* Integrity */}
        <Card className={`border ${sc.className}`}>
          <CardContent className="p-3 flex items-center gap-2">
            <ScIcon className="h-5 w-5 shrink-0" />
            <div>
              <p className="text-[10px] opacity-60 uppercase tracking-wider">Status</p>
              <p className="text-sm font-bold">{sc.label}</p>
            </div>
          </CardContent>
        </Card>
        {/* Gauge */}
        <Card className="flex items-center justify-center">
          <CardContent className="p-3 flex items-center gap-3">
            <RiskGauge score={r.riskScore} level={r.riskLevel} />
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Risk</p>
              <Badge variant={r.riskLevel === 'low' ? 'secondary' : r.riskLevel === 'medium' ? 'outline' : 'destructive'}>
                {r.riskLevel.toUpperCase()}
              </Badge>
            </div>
          </CardContent>
        </Card>
        {/* Attribution */}
        <Card>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Attribution</p>
            <p className={`text-sm font-bold ${confidenceColor[fa.attributionConfidence]}`}>
              {fa.attributionConfidence.toUpperCase()}
            </p>
            <p className="text-[10px] text-muted-foreground">confidence</p>
          </CardContent>
        </Card>
        {/* Integrity score */}
        <Card>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Evidence Integrity</p>
            <p className="text-sm font-bold font-mono" style={{ color: fa.evidenceIntegrityScore >= 70 ? '#22c55e' : fa.evidenceIntegrityScore >= 40 ? '#eab308' : '#ef4444' }}>
              {fa.evidenceIntegrityScore}/100
            </p>
            <div className="h-1 rounded-full bg-muted mt-1 overflow-hidden">
              <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${fa.evidenceIntegrityScore}%` }} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── 1. Author & Ownership ── */}
      <Section icon={User} title="1 · Author & Ownership Information" color="text-blue-400">
        <div className="space-y-0">
          <Field label="Document Author" value={m.author} />
          <Field label="Creator Name" value={m.creator || m.author} />
          <Field label="Last Modified By" value={m.lastModifiedBy} />
          <Field label="Organization" value={m.organization} />
          <Field label="Device Owner" value={m.deviceOwner} />
          {!m.author && !m.creator && !m.lastModifiedBy &&
            <p className="text-xs text-muted-foreground italic py-2">No author/ownership metadata found in this file.</p>
          }
        </div>
      </Section>

      {/* ── 2. Network & Source Indicators ── */}
      <Section icon={Network} title="2 · Network & Source Indicators" color="text-cyan-400">
        <div className="space-y-4">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1"><Mail className="h-3 w-3" /> Email Addresses</p>
            <TagList items={net.emails} color="text-cyan-400" emptyMsg="No email addresses found" />
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1"><Server className="h-3 w-3" /> Embedded IP Addresses</p>
            <TagList items={net.ips} color="text-yellow-400" emptyMsg="No IP addresses found" />
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1"><Globe className="h-3 w-3" /> URLs & External References</p>
            <TagList items={net.urls.slice(0, 10)} color="text-violet-400" emptyMsg="No external URLs found" />
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1"><Server className="h-3 w-3" /> Internal Network Paths (UNC)</p>
            <TagList items={net.uncPaths} color="text-red-400" emptyMsg="No UNC paths found" />
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1"><Globe className="h-3 w-3" /> Hostnames</p>
            <TagList items={net.hostnames.slice(0, 8)} emptyMsg="No hostnames found" />
          </div>
        </div>
      </Section>

      {/* ── 3. Device & Software Fingerprinting ── */}
      <Section icon={Cpu} title="3 · Device & Software Fingerprinting" color="text-violet-400">
        <div className="space-y-0">
          <Field label="Software" value={m.software} />
          <Field label="App Version" value={m.appVersion || m.softwareVersion} />
          <Field label="Operating System" value={m.operatingSystem} />
          <Field label="Device / Camera" value={m.device} />
          <Field label="Color Space" value={m.colorSpace} />
          <Field label="Image Dimensions" value={m.dimensions ? `${m.dimensions.width} × ${m.dimensions.height} px` : undefined} />
          <Field label="DPI" value={m.dpi ? `${m.dpi} dpi` : undefined} />
          {!m.software && !m.device && !m.operatingSystem &&
            <p className="text-xs text-muted-foreground italic py-2">No software/device fingerprint detected.</p>
          }
        </div>
      </Section>

      {/* ── 4. Timeline Analysis ── */}
      <Section icon={Clock} title="4 · Timeline Analysis" color="text-emerald-400">
        <div className="space-y-0">
          <Field label="Creation Timestamp" value={m.creationDate?.toLocaleString()} />
          <Field label="Modification Timestamp" value={m.modificationDate?.toLocaleString()} />
          <Field label="File System Last Modified" value={m.lastModified.toLocaleString()} />
          <Field label="Upload Timestamp" value={m.uploadTimestamp.toLocaleString()} />
          <Field label="Access Time" value={m.accessDate?.toLocaleString()} />
          <Field label="Timezone" value={m.timezone} />
        </div>
        {/* Anomalies from timeline */}
        {r.anomalies.filter(a => a.type === 'date_mismatch').length > 0 && (
          <div className="mt-3 pt-3 border-t border-border/50">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">⚠ Metadata Inconsistencies</p>
            <FlagList items={r.anomalies.filter(a => a.type === 'date_mismatch').map(a => a.title)} />
          </div>
        )}
      </Section>

      {/* ── 5. Location Intelligence ── */}
      <Section icon={MapPin} title="5 · Location Intelligence" color="text-orange-400">
        {m.gpsLatitude !== undefined ? (
          <div className="space-y-3">
            <div className="space-y-0">
              <Field label="GPS Latitude" value={`${m.gpsLatitude.toFixed(7)}°`} mono />
              <Field label="GPS Longitude" value={`${m.gpsLongitude?.toFixed(7)}°`} mono />
              <Field label="GPS Altitude" value={m.gpsAltitude ? `${m.gpsAltitude} m` : undefined} />
              <Field label="GPS Timestamp" value={m.gpsTimestamp} />
            </div>
            <a
              href={`https://www.google.com/maps?q=${m.gpsLatitude},${m.gpsLongitude}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-primary underline hover:opacity-80 transition"
            >
              <MapPin className="h-3 w-3" /> View on Google Maps ↗
            </a>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground italic">No GPS coordinates found in this file.</p>
        )}
        {m.locationReference && <Field label="Location Reference" value={m.locationReference} />}
      </Section>

      {/* ── 6. Hidden / Suspicious Artifacts ── */}
      <Section icon={EyeOff} title="6 · Hidden & Suspicious Artifacts" color="text-red-400">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mb-4">
          {[
            { label: 'VBA Macros', value: art.hasMacros },
            { label: 'Embedded Scripts', value: art.hasEmbeddedScripts },
            { label: 'Embedded Files', value: art.hasEmbeddedFiles },
            { label: 'Hidden Text', value: art.hasHiddenText },
            { label: 'Deleted Content', value: art.deletedContent },
            { label: `Revisions (${art.revisionCount})`, value: art.revisionCount > 0 },
          ].map(({ label, value }) => (
            <div key={label} className={`p-2.5 rounded-lg border text-xs font-medium flex items-center gap-1.5
              ${value ? 'border-red-500/30 bg-red-500/5 text-red-400' : 'border-border/50 bg-muted/30 text-muted-foreground'}`}>
              {value ? <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> : <CheckCircle className="h-3.5 w-3.5 shrink-0" />}
              {label}
            </div>
          ))}
        </div>
        {art.suspiciousStreams.length > 0 && (
          <div className="mb-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Suspicious Streams Detected</p>
            <FlagList items={art.suspiciousStreams} />
          </div>
        )}
        {art.embeddedObjectTypes.length > 0 && (
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Embedded Object Types</p>
            <TagList items={art.embeddedObjectTypes} color="text-orange-400" />
          </div>
        )}
      </Section>

      {/* ── 7. Forensic Risk Assessment ── */}
      <Section icon={BarChart3} title="7 · Forensic Risk Assessment" color="text-yellow-400">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Identity leakage */}
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1">
              <Fingerprint className="h-3 w-3" /> Possible Identity Leakage
            </p>
            <FlagList items={fa.identityLeakageRisks} emptyMsg="No identity leakage detected" />
          </div>
          {/* OSINT potential */}
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1">
              <Zap className="h-3 w-3" /> OSINT Investigation Potential
            </p>
            <FlagList items={fa.osintPotential} emptyMsg="No OSINT leads found" icon={Zap} />
          </div>
        </div>

        {/* Risk explanation */}
        <div className="mt-4 pt-4 border-t border-border/50 space-y-2">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">AI Forensic Summary</p>
          <p className="text-sm text-muted-foreground leading-relaxed">{r.riskExplanation}</p>
        </div>

        {/* Anomaly timeline */}
        {r.anomalies.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border/50">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" /> All Anomalies ({r.anomalies.length})
            </p>
            <div className="space-y-2">
              {r.anomalies.map(a => (
                <div key={a.id} className={`p-2.5 rounded-lg border text-xs ${a.severity === 'high' ? 'border-red-500/25 bg-red-500/5' :
                  a.severity === 'medium' ? 'border-yellow-500/25 bg-yellow-400/5' :
                    'border-border bg-muted/20'
                  }`}>
                  <div className="flex items-center gap-2 mb-0.5">
                    <Badge variant={a.severity === 'high' ? 'destructive' : a.severity === 'medium' ? 'outline' : 'secondary'}
                      className="text-[10px] px-1.5 py-0">{a.severity.toUpperCase()}</Badge>
                    <span className="font-semibold">{a.title}</span>
                  </div>
                  <p className="text-muted-foreground text-[11px] leading-relaxed">{a.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* ── Image preview ── */}
      {r.filePreviewUrl && (
        <Section icon={FileText} title="Evidence Preview" color="text-muted-foreground">
          <div className="flex justify-center">
            <img src={r.filePreviewUrl} alt="Preview" className="max-h-80 rounded-xl border border-border/50 object-contain shadow-lg" />
          </div>
        </Section>
      )}

      {/* ── JSON View ── */}
      {viewMode === 'json' && (
        <Card>
          <CardHeader className="pb-2 flex flex-row items-center gap-2">
            <Code2 className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm">Complete Raw Forensic JSON</CardTitle>
            <Badge variant="secondary" className="ml-auto font-mono text-xs">
              {JSON.stringify(r.rawForensicJSON).length.toLocaleString()} chars
            </Badge>
          </CardHeader>
          <CardContent className="p-0">
            <pre className="text-[11px] font-mono leading-relaxed text-emerald-300 bg-[hsl(222,47%,5%)] p-4 rounded-b-xl overflow-auto max-h-[70vh] whitespace-pre-wrap break-all">
              {JSON.stringify(r.rawForensicJSON, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}

    </div>
  );
}
