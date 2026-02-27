import { useForensic } from '@/context/ForensicContext';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { exportReport } from '@/lib/pdf-export';
import { Download, Eye, FileText, TrendingUp, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

const riskVariant = {
  low: { badge: 'secondary' as const, icon: ShieldCheck, dot: 'bg-emerald-500', glow: 'hover:border-emerald-500/30' },
  medium: { badge: 'outline' as const, icon: AlertTriangle, dot: 'bg-yellow-500', glow: 'hover:border-yellow-500/30' },
  high: { badge: 'destructive' as const, icon: ShieldAlert, dot: 'bg-red-500', glow: 'hover:border-red-500/30' },
};

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function ReportsPage() {
  const { analyses, selectAnalysis } = useForensic();
  const navigate = useNavigate();

  const viewAnalysis = (id: string) => {
    selectAnalysis(id);
    navigate('/analysis');
  };

  const totalHigh = analyses.filter(a => a.riskLevel === 'high').length;
  const totalMedium = analyses.filter(a => a.riskLevel === 'medium').length;
  const totalLow = analyses.filter(a => a.riskLevel === 'low').length;
  const avgScore = analyses.length > 0
    ? Math.round(analyses.reduce((s, a) => s + a.riskScore, 0) / analyses.length)
    : 0;

  return (
    <div className="max-w-5xl mx-auto space-y-6">

      {/* ── Header ───────────────────────────────────────────────────── */}
      <div>
        <p className="text-xs text-muted-foreground font-mono tracking-widest uppercase mb-1">Case History</p>
        <h1 className="text-2xl font-bold text-foreground">Analysis Reports</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {analyses.length === 0
            ? 'No analyses yet — upload a file to get started'
            : `${analyses.length} file${analyses.length > 1 ? 's' : ''} analysed`}
        </p>
      </div>

      {/* ── Summary stats (only when there's data) ───────────────────── */}
      {analyses.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Total Files', value: analyses.length, icon: FileText, color: 'text-primary', bg: 'bg-primary/10' },
            { label: 'Avg Risk Score', value: `${avgScore}/100`, icon: TrendingUp, color: 'text-yellow-400', bg: 'bg-yellow-400/10' },
            { label: 'High Risk', value: totalHigh, icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-400/10' },
            { label: 'Authentic', value: totalLow, icon: ShieldCheck, color: 'text-emerald-400', bg: 'bg-emerald-400/10' },
          ].map(({ label, value, icon: Icon, color, bg }) => (
            <div key={label} className="rounded-xl border border-border/50 bg-card/60 p-4 flex items-center gap-3">
              <div className={`p-2 rounded-lg ${bg}`}>
                <Icon className={`h-4 w-4 ${color}`} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className={`text-lg font-bold font-mono ${color}`}>{value}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Report cards / empty state ────────────────────────────────── */}
      {analyses.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-20 gap-4">
            <div className="p-5 rounded-2xl bg-muted">
              <FileText className="h-10 w-10 text-muted-foreground/40" />
            </div>
            <div className="text-center">
              <p className="font-medium text-foreground">No analyses yet</p>
              <p className="text-sm text-muted-foreground mt-1">Upload a file on the Upload page to begin forensic analysis</p>
            </div>
            <Button variant="outline" onClick={() => navigate('/')}>Go to Upload</Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {analyses.map((a, idx) => {
            const cfg = riskVariant[a.riskLevel];
            const RiskIcon = cfg.icon;
            return (
              <div
                key={a.id}
                className={`group rounded-xl border border-border/60 bg-card/60 hover:bg-card transition-all duration-200 hover:shadow-md ${cfg.glow} cursor-pointer`}
                onClick={() => viewAnalysis(a.id)}
              >
                <div className="p-4 flex items-center gap-4">
                  {/* Index */}
                  <span className="text-xs font-mono text-muted-foreground/50 w-5 shrink-0">
                    {String(idx + 1).padStart(2, '0')}
                  </span>

                  {/* Risk dot */}
                  <div className={`h-2.5 w-2.5 rounded-full shrink-0 ${cfg.dot} shadow-lg`} />

                  {/* File info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-semibold text-foreground truncate max-w-xs">
                        {a.metadata.fileName}
                      </p>
                      <Badge variant="secondary" className="text-[10px] font-mono shrink-0">
                        {a.metadata.fileType}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap gap-3 mt-1">
                      <span className="text-xs text-muted-foreground">{formatSize(a.metadata.fileSize)}</span>
                      <span className="text-xs text-muted-foreground">·</span>
                      <span className="text-xs text-muted-foreground">{a.analyzedAt.toLocaleString()}</span>
                      <span className="text-xs text-muted-foreground">·</span>
                      <span className="text-xs text-muted-foreground">{a.anomalies.length} anomal{a.anomalies.length === 1 ? 'y' : 'ies'}</span>
                    </div>
                  </div>

                  {/* Risk score */}
                  <div className="shrink-0 text-right hidden sm:block">
                    <p className="text-xs text-muted-foreground mb-1">Risk Score</p>
                    <p className="text-lg font-black font-mono" style={{ color: a.riskLevel === 'high' ? '#ef4444' : a.riskLevel === 'medium' ? '#eab308' : '#22c55e' }}>
                      {a.riskScore}
                      <span className="text-xs text-muted-foreground font-normal">/100</span>
                    </p>
                  </div>

                  {/* Badge */}
                  <div className="shrink-0">
                    <Badge variant={cfg.badge} className="gap-1">
                      <RiskIcon className="h-3 w-3" />
                      {a.riskLevel.toUpperCase()}
                    </Badge>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7"
                      onClick={(e) => { e.stopPropagation(); viewAnalysis(a.id); }}
                      title="View analysis"
                    >
                      <Eye className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7"
                      onClick={(e) => { e.stopPropagation(); exportReport(a); }}
                      title="Export PDF"
                    >
                      <Download className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                {/* Bottom risk bar */}
                <div className="px-4 pb-3">
                  <div className="h-0.5 rounded-full bg-muted overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${cfg.dot}`}
                      style={{ width: `${a.riskScore}%` }}
                    />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
