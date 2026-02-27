import { useState, useMemo, useRef, useEffect } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { useNavigate } from 'react-router-dom';
import { normalizeMetadata } from '@/lib/metadata-normalizer';
import { analyzeAttribution } from '@/lib/attribution-analyst';
import { reconstructLifecycle } from '@/lib/lifecycle-analyzer';
import { analyzeNetworkOrigin } from '@/lib/network-origin-analyzer';
import { analyzeGeoDevice } from '@/lib/geo-device-analyzer';
import { analyzePrivacyRisk } from '@/lib/privacy-risk-analyzer';
import {
    ChatMessage,
    buildFileContext,
    sendForensicChat,
    FORENSIC_PRESETS,
} from '@/lib/llama-analyst';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
    Bot, User, Send, Loader2, AlertTriangle, BookOpen,
    Sparkles, RotateCcw, Copy, Check, ChevronRight, Zap,
    Shield, Key, ExternalLink,
} from 'lucide-react';

// ── Message bubble ────────────────────────────────────────────────────────────

function MessageBubble({ msg, isStreaming }: { msg: ChatMessage; isStreaming?: boolean }) {
    const isUser = msg.role === 'user';
    const [copied, setCopied] = useState(false);

    const handleCopy = () => {
        navigator.clipboard.writeText(msg.content);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
    };

    return (
        <div className={`flex gap-3 ${isUser ? 'flex-row-reverse' : ''}`}>
            {/* Avatar */}
            <div className={`h-8 w-8 rounded-xl flex items-center justify-center shrink-0 mt-0.5 ${isUser
                    ? 'bg-violet-600/20 border border-violet-500/30'
                    : 'bg-emerald-600/20 border border-emerald-500/30'
                }`}>
                {isUser
                    ? <User className="h-4 w-4 text-violet-400" />
                    : <Bot className="h-4 w-4 text-emerald-400" />
                }
            </div>

            {/* Bubble */}
            <div className={`flex-1 max-w-[85%] group ${isUser ? 'items-end flex flex-col' : ''}`}>
                <div className={`rounded-2xl px-4 py-3 text-sm leading-relaxed relative ${isUser
                        ? 'bg-violet-600/20 border border-violet-500/20 text-slate-100 rounded-tr-sm'
                        : 'bg-slate-800/60 border border-slate-700/50 text-slate-200 rounded-tl-sm'
                    }`}>
                    {/* Streaming cursor */}
                    {isStreaming && !isUser && (
                        <span className="inline-block w-2 h-4 bg-emerald-400 animate-pulse rounded-sm ml-0.5 align-middle" />
                    )}
                    {/* Message content with basic markdown-like formatting */}
                    <div className="whitespace-pre-wrap break-words">
                        {msg.content.split('\n').map((line, i) => {
                            if (line.startsWith('### ')) return <p key={i} className="font-bold text-slate-100 mt-2 mb-1 text-sm">{line.slice(4)}</p>;
                            if (line.startsWith('## ')) return <p key={i} className="font-bold text-slate-100 mt-3 mb-1">{line.slice(3)}</p>;
                            if (line.startsWith('**') && line.endsWith('**')) return <p key={i} className="font-semibold text-slate-100">{line.slice(2, -2)}</p>;
                            if (line.startsWith('- ') || line.startsWith('• ')) return <p key={i} className="flex gap-2 text-slate-300"><span className="text-emerald-400 shrink-0">›</span>{line.slice(2)}</p>;
                            if (line.trim() === '') return <div key={i} className="h-2" />;
                            return <p key={i} className="text-slate-200">{line}</p>;
                        })}
                    </div>
                </div>
                {/* Copy button - shows on hover */}
                {!isStreaming && (
                    <button
                        onClick={handleCopy}
                        className={`mt-1 flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition-colors opacity-0 group-hover:opacity-100 ${isUser ? 'mr-1' : 'ml-1'}`}
                    >
                        {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        {copied ? 'Copied' : 'Copy'}
                    </button>
                )}
            </div>
        </div>
    );
}

// ── API key setup banner ──────────────────────────────────────────────────────

function APIKeyBanner() {
    return (
        <div className="flex flex-col items-center justify-center h-full gap-6 p-8 text-center max-w-lg mx-auto">
            <div className="relative">
                <div className="h-20 w-20 rounded-2xl bg-amber-950/30 border border-amber-500/30 flex items-center justify-center">
                    <Key className="h-10 w-10 text-amber-400" />
                </div>
                <div className="absolute -top-1 -right-1 h-6 w-6 rounded-full bg-violet-600/30 border border-violet-500/30 flex items-center justify-center">
                    <Zap className="h-3 w-3 text-violet-400" />
                </div>
            </div>
            <div>
                <h2 className="text-xl font-bold text-white mb-2">Connect Llama AI</h2>
                <p className="text-slate-400 text-sm leading-relaxed">
                    Add your free Groq API key to activate the AI Forensic Analyst powered by <span className="text-violet-400 font-semibold">Llama 3.3 70B</span>.
                    Groq is free — no credit card required.
                </p>
            </div>

            <div className="w-full space-y-3 text-left">
                {[
                    { step: '1', text: 'Go to console.groq.com and sign up (free)', link: 'https://console.groq.com/keys' },
                    { step: '2', text: 'Create an API key (starts with gsk_...)' },
                    { step: '3', text: 'Open the .env file in your project root' },
                    { step: '4', text: 'Replace "your_groq_api_key_here" with your key' },
                    { step: '5', text: 'Save and the app hot-reloads instantly' },
                ].map(({ step, text, link }) => (
                    <div key={step} className="flex items-start gap-3 p-3 rounded-xl bg-slate-800/40 border border-slate-700/40">
                        <span className="h-6 w-6 rounded-full bg-violet-600/20 border border-violet-500/30 text-[11px] font-black text-violet-400 flex items-center justify-center shrink-0">{step}</span>
                        <p className="text-sm text-slate-300 flex-1">{text}</p>
                        {link && (
                            <a href={link} target="_blank" rel="noopener noreferrer" className="shrink-0">
                                <ExternalLink className="h-3.5 w-3.5 text-slate-500 hover:text-violet-400 transition-colors" />
                            </a>
                        )}
                    </div>
                ))}
            </div>

            <div className="flex items-center gap-2 p-3 rounded-xl bg-slate-800/40 border border-slate-700/40 w-full">
                <code className="text-xs font-mono text-emerald-400 flex-1 break-all">VITE_GROQ_API_KEY=gsk_your_key_here</code>
            </div>

            <p className="text-[11px] text-slate-500">
                After adding the key, refresh this page. Groq free tier: 14,400 requests/day.
            </p>
        </div>
    );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function LlamaAnalystPage() {
    const { analyses, currentAnalysis } = useForensic();
    const navigate = useNavigate();
    const latest = currentAnalysis ?? analyses[0] ?? null;

    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [input, setInput] = useState('');
    const [streaming, setStreaming] = useState(false);
    const [streamingText, setStreamingText] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [apiKeyMissing, setApiKeyMissing] = useState(false);
    const bottomRef = useRef<HTMLDivElement>(null);
    const textareaRef = useRef<HTMLTextAreaElement>(null);

    // Build context once from all engines
    const fileContext = useMemo(() => {
        if (!latest) return '';
        try {
            const n = normalizeMetadata(latest);
            const attribution = analyzeAttribution(n);
            const lifecycle = reconstructLifecycle(latest);
            const network = analyzeNetworkOrigin(latest);
            const geo = analyzeGeoDevice(n);
            const privacy = analyzePrivacyRisk(latest, n);
            return buildFileContext(latest, n, attribution, lifecycle, network, geo, privacy);
        } catch {
            return buildFileContext(latest);
        }
    }, [latest]);

    // Scroll to bottom on new messages
    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages, streamingText]);

    // Welcome message
    useEffect(() => {
        if (latest && messages.length === 0) {
            setMessages([{
                role: 'assistant',
                content: `I've loaded the forensic analysis for **"${latest.metadata.fileName}"** (${latest.metadata.fileType}, ${(latest.metadata.fileSize / 1024).toFixed(1)} KB).\n\nIntegrity status: **${latest.integrityStatus.toUpperCase()}** · Risk: **${latest.riskLevel.toUpperCase()} (${latest.riskScore}/100)**\n\nI have access to all analysis engine outputs — identity, timeline, geographic, network, device, and privacy. Ask me anything about this file, or use one of the quick prompts below.`,
            }]);
        }
    }, [latest]);

    const send = async (text: string) => {
        if (!text.trim() || streaming || !latest) return;
        setError(null);

        const userMsg: ChatMessage = { role: 'user', content: text };
        const newMessages: ChatMessage[] = [...messages, userMsg];
        setMessages(newMessages);
        setInput('');
        setStreaming(true);
        setStreamingText('');

        try {
            let full = '';
            await sendForensicChat(
                newMessages.filter(m => m.role !== 'system'),
                fileContext,
                (chunk) => {
                    full += chunk;
                    setStreamingText(full);
                }
            );
            setMessages(prev => [...prev, { role: 'assistant', content: full }]);
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            if (msg === 'GROQ_API_KEY_MISSING') {
                setApiKeyMissing(true);
            } else {
                setError(`AI error: ${msg}`);
            }
        } finally {
            setStreaming(false);
            setStreamingText('');
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            send(input);
        }
    };

    const reset = () => {
        setMessages([]);
        setError(null);
        setTimeout(() => {
            if (latest) {
                setMessages([{
                    role: 'assistant',
                    content: `Conversation reset. I still have the full forensic context for **"${latest.metadata.fileName}"** loaded. What would you like to investigate?`,
                }]);
            }
        }, 100);
    };

    // Check API key on mount
    useEffect(() => {
        const key = import.meta.env.VITE_GROQ_API_KEY;
        if (!key || key === 'your_groq_api_key_here') {
            setApiKeyMissing(true);
        }
    }, []);

    if (!latest) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4 p-8 text-center">
                <div className="p-5 rounded-2xl bg-violet-500/10 border border-violet-500/20">
                    <Bot className="h-10 w-10 text-violet-400" />
                </div>
                <div>
                    <h2 className="text-xl font-bold text-white mb-2">No File Analyzed Yet</h2>
                    <p className="text-slate-400 text-sm max-w-md">Upload and analyze a file first, then return here to chat with the AI Forensic Analyst about its findings.</p>
                </div>
                <Button onClick={() => navigate('/upload')} className="bg-violet-600 hover:bg-violet-700 text-white">
                    Upload a File
                </Button>
            </div>
        );
    }

    if (apiKeyMissing) {
        return (
            <div className="max-w-2xl mx-auto px-4 py-6">
                <div className="flex items-center gap-2 mb-6">
                    <div className="p-1.5 rounded-lg bg-violet-500/10 border border-violet-500/20">
                        <Bot className="h-4 w-4 text-violet-400" />
                    </div>
                    <h1 className="text-xl font-bold text-white">AI Forensic Analyst</h1>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 font-bold ml-1">SETUP REQUIRED</span>
                </div>
                <Card className="bg-slate-900/60 border-slate-700/50 min-h-[60vh] flex flex-col">
                    <CardContent className="flex-1 flex">
                        <APIKeyBanner />
                    </CardContent>
                </Card>
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto px-4 py-6 flex flex-col h-[calc(100vh-5rem)] gap-4">

            {/* ── Header ── */}
            <div className="flex items-start justify-between gap-4 flex-wrap shrink-0">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <div className="p-1.5 rounded-lg bg-violet-500/10 border border-violet-500/20">
                            <Bot className="h-4 w-4 text-violet-400" />
                        </div>
                        <h1 className="text-xl font-bold text-white">AI Forensic Analyst</h1>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold">
                            Llama 3.3 70B
                        </span>
                    </div>
                    <p className="text-slate-400 text-xs">
                        Powered by Meta Llama via Groq · Analyzing: <span className="text-slate-300 font-mono">{latest.metadata.fileName}</span>
                    </p>
                </div>
                <div className="flex gap-2">
                    <Button onClick={reset} variant="outline" size="sm" className="gap-1.5 text-xs border-slate-700 text-slate-400 hover:text-white">
                        <RotateCcw className="h-3.5 w-3.5" /> Reset
                    </Button>
                    <Button onClick={() => navigate('/forensic-report')} variant="outline" size="sm" className="gap-1.5 text-xs border-slate-700 text-slate-400 hover:text-white">
                        <BookOpen className="h-3.5 w-3.5" /> Full Report
                    </Button>
                </div>
            </div>

            {/* ── File status pill ── */}
            <div className="flex gap-2 flex-wrap shrink-0">
                {[
                    { label: latest.integrityStatus.toUpperCase(), color: latest.integrityStatus === 'authentic' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25' : latest.integrityStatus === 'tampered' ? 'text-red-400 bg-red-500/10 border-red-500/25' : 'text-amber-400 bg-amber-500/10 border-amber-500/25', icon: Shield },
                    { label: `Risk: ${latest.riskScore}/100`, color: 'text-slate-400 bg-slate-700/30 border-slate-600/40', icon: Zap },
                ].map(({ label, color, icon: Icon }) => (
                    <span key={label} className={`flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-full border font-semibold ${color}`}>
                        <Icon className="h-3 w-3" />{label}
                    </span>
                ))}
            </div>

            {/* ── Chat window ── */}
            <Card className="flex-1 bg-slate-900/60 border-slate-700/50 flex flex-col overflow-hidden min-h-0">
                {/* Messages */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                    {messages.map((msg, i) => (
                        <MessageBubble key={i} msg={msg} />
                    ))}
                    {/* Streaming message */}
                    {streaming && streamingText && (
                        <MessageBubble
                            msg={{ role: 'assistant', content: streamingText }}
                            isStreaming
                        />
                    )}
                    {/* Thinking indicator */}
                    {streaming && !streamingText && (
                        <div className="flex gap-3">
                            <div className="h-8 w-8 rounded-xl bg-emerald-600/20 border border-emerald-500/30 flex items-center justify-center shrink-0">
                                <Bot className="h-4 w-4 text-emerald-400" />
                            </div>
                            <div className="rounded-2xl rounded-tl-sm px-4 py-3 bg-slate-800/60 border border-slate-700/50 flex items-center gap-2">
                                <Loader2 className="h-3.5 w-3.5 text-emerald-400 animate-spin" />
                                <span className="text-xs text-slate-400">Llama is analyzing…</span>
                            </div>
                        </div>
                    )}
                    {/* Error */}
                    {error && (
                        <div className="flex items-start gap-2 p-3 rounded-xl bg-red-950/20 border border-red-500/25">
                            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                            <p className="text-sm text-red-300">{error}</p>
                        </div>
                    )}
                    <div ref={bottomRef} />
                </div>

                {/* ── Quick presets ── */}
                {messages.length <= 1 && !streaming && (
                    <div className="px-4 pb-3 border-t border-slate-700/40 pt-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-1">
                            <Sparkles className="h-3 w-3" /> Quick Analysis Prompts
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                            {FORENSIC_PRESETS.map(preset => (
                                <button
                                    key={preset.label}
                                    onClick={() => send(preset.prompt)}
                                    disabled={streaming}
                                    className="flex items-center gap-1 text-[11px] px-2.5 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700/50 text-slate-300 hover:bg-slate-700/60 hover:text-white hover:border-violet-500/40 transition-all disabled:opacity-40"
                                >
                                    {preset.label}
                                    <ChevronRight className="h-3 w-3 text-slate-500" />
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {/* ── Input bar ── */}
                <div className="border-t border-slate-700/50 p-3 shrink-0">
                    <div className="flex gap-2 items-end">
                        <textarea
                            ref={textareaRef}
                            value={input}
                            onChange={e => setInput(e.target.value)}
                            onKeyDown={handleKeyDown}
                            placeholder="Ask anything about this file's metadata, authorship, integrity, or privacy exposure…"
                            rows={2}
                            disabled={streaming}
                            className="flex-1 resize-none bg-slate-800/60 border border-slate-700/50 rounded-xl px-3 py-2.5 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all disabled:opacity-50"
                        />
                        <Button
                            onClick={() => send(input)}
                            disabled={!input.trim() || streaming}
                            className="h-10 w-10 p-0 bg-violet-600 hover:bg-violet-700 text-white shrink-0 rounded-xl disabled:opacity-40"
                        >
                            {streaming
                                ? <Loader2 className="h-4 w-4 animate-spin" />
                                : <Send className="h-4 w-4" />
                            }
                        </Button>
                    </div>
                    <p className="text-[10px] text-slate-600 mt-1.5 ml-1">Enter to send · Shift+Enter for new line</p>
                </div>
            </Card>
        </div>
    );
}
