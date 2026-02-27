import { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileImage, FileText, Film, File, ShieldCheck, Zap, Lock } from 'lucide-react';
import { Progress } from '@/components/ui/progress';
import { useForensic } from '@/context/ForensicContext';

const ACCEPTED_EXT = '.pdf,.docx,.jpg,.jpeg,.png,.mp4';

const FILE_TYPES = [
  { ext: 'JPG/PNG', icon: FileImage, color: 'text-cyan-400', bg: 'bg-cyan-400/10' },
  { ext: 'PDF', icon: FileText, color: 'text-violet-400', bg: 'bg-violet-400/10' },
  { ext: 'DOCX', icon: FileText, color: 'text-blue-400', bg: 'bg-blue-400/10' },
  { ext: 'MP4', icon: Film, color: 'text-emerald-400', bg: 'bg-emerald-400/10' },
];

const STEPS = [
  { label: 'Hashing file', icon: Lock },
  { label: 'Extracting metadata', icon: FileText },
  { label: 'Detecting anomalies', icon: Zap },
  { label: 'Scoring risk', icon: ShieldCheck },
];

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function getFileIcon(type: string) {
  if (type.startsWith('image/')) return FileImage;
  if (type.startsWith('video/')) return Film;
  if (type.includes('pdf') || type.includes('word')) return FileText;
  return File;
}

export default function UploadPage() {
  const { processFile, isAnalyzing, progress } = useForensic();
  const navigate = useNavigate();
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleFile = useCallback(async (file: File) => {
    setSelectedFile(file);
    await processFile(file);
    navigate('/analysis');
  }, [processFile, navigate]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const onFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const currentStep = Math.floor((progress / 100) * STEPS.length);
  const FileIcon = selectedFile ? getFileIcon(selectedFile.type) : Upload;

  return (
    <div className="min-h-[calc(100vh-3rem)] flex flex-col items-center justify-center p-6 relative overflow-hidden">

      {/* Background glow effect */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[400px] rounded-full bg-primary/5 blur-[120px]" />
      </div>

      <div className="w-full max-w-2xl space-y-6 relative z-10">

        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-mono tracking-widest uppercase mb-2">
            <ShieldCheck className="h-3 w-3" />
            Forensic Analysis Engine
          </div>
          <h1 className="text-3xl font-bold text-foreground tracking-tight">
            Upload Evidence File
          </h1>
          <p className="text-sm text-muted-foreground">
            Drop any document or image to begin deep metadata forensic analysis
          </p>
        </div>

        {/* Drop Zone */}
        <div
          className={`relative rounded-2xl border-2 border-dashed transition-all duration-300 cursor-pointer overflow-hidden
            ${dragOver
              ? 'border-primary bg-primary/5 shadow-[0_0_40px_rgba(6,182,212,0.15)]'
              : 'border-border hover:border-primary/50 hover:bg-accent/20 hover:shadow-[0_0_30px_rgba(6,182,212,0.08)]'
            }`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => !isAnalyzing && document.getElementById('file-input')?.click()}
        >
          {/* Scanning animation overlay on drag */}
          {dragOver && (
            <div className="absolute inset-0 pointer-events-none">
              <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-primary to-transparent animate-[scan_1.5s_ease-in-out_infinite]" style={{ top: '40%' }} />
            </div>
          )}

          <div className="flex flex-col items-center justify-center py-20 gap-5 px-6">
            {/* Icon */}
            <div className={`relative p-5 rounded-2xl transition-all duration-300 ${dragOver ? 'bg-primary/20 scale-110' : 'bg-muted'}`}>
              {dragOver
                ? <div className="absolute inset-0 rounded-2xl border border-primary/50 animate-ping opacity-30" />
                : null}
              <Upload className={`h-10 w-10 transition-colors duration-300 ${dragOver ? 'text-primary' : 'text-muted-foreground'}`} />
            </div>

            <div className="text-center space-y-1">
              <p className="text-foreground font-semibold text-lg">
                {dragOver ? '✦ Release to scan' : 'Drag & drop your file here'}
              </p>
              <p className="text-xs text-muted-foreground">
                or <span className="text-primary underline cursor-pointer">browse files</span> · max 50MB
              </p>
            </div>

            {/* Accepted types */}
            <div className="flex flex-wrap items-center justify-center gap-2 mt-2">
              {FILE_TYPES.map(({ ext, icon: Icon, color, bg }) => (
                <span key={ext} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-medium ${bg} ${color}`}>
                  <Icon className="h-3 w-3" />
                  {ext}
                </span>
              ))}
            </div>

            <input
              id="file-input"
              type="file"
              accept={ACCEPTED_EXT}
              className="hidden"
              onChange={onFileSelect}
            />
          </div>
        </div>

        {/* Analysis progress card */}
        {isAnalyzing && selectedFile && (
          <div className="rounded-2xl border border-border bg-card/80 backdrop-blur-sm p-5 space-y-4 shadow-xl animate-in fade-in slide-in-from-bottom-2 duration-300">

            {/* File info */}
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-primary/10">
                <FileIcon className="h-5 w-5 text-primary" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-foreground truncate">{selectedFile.name}</p>
                <p className="text-xs text-muted-foreground">{formatSize(selectedFile.size)} · {selectedFile.type || 'Unknown type'}</p>
              </div>
              <span className="text-xs font-mono text-primary font-bold tabular-nums">{Math.round(progress)}%</span>
            </div>

            {/* Progress bar */}
            <Progress value={progress} className="h-1.5 bg-muted" />

            {/* Step indicators */}
            <div className="grid grid-cols-4 gap-2">
              {STEPS.map(({ label, icon: Icon }, i) => (
                <div key={i} className={`flex flex-col items-center gap-1.5 p-2 rounded-lg transition-all duration-300 ${i < currentStep
                    ? 'bg-primary/10 text-primary'
                    : i === currentStep
                      ? 'bg-primary/5 text-primary animate-pulse'
                      : 'text-muted-foreground/40'
                  }`}>
                  <Icon className="h-4 w-4" />
                  <span className="text-[10px] text-center leading-tight font-medium">{label}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Feature highlights */}
        {!isAnalyzing && (
          <div className="grid grid-cols-3 gap-3">
            {[
              { icon: Lock, title: 'SHA-256 Hashing', desc: 'Cryptographic integrity verification' },
              { icon: Zap, title: '10 Anomaly Checks', desc: 'Timestamp, GPS, software analysis' },
              { icon: ShieldCheck, title: 'Risk Scoring', desc: 'Composite forensic risk score 0-100' },
            ].map(({ icon: Icon, title, desc }) => (
              <div key={title} className="p-3 rounded-xl border border-border/50 bg-card/40 text-center space-y-1.5 hover:border-primary/30 hover:bg-primary/5 transition-all duration-200">
                <Icon className="h-4 w-4 text-primary mx-auto" />
                <p className="text-xs font-semibold text-foreground">{title}</p>
                <p className="text-[10px] text-muted-foreground leading-tight">{desc}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
