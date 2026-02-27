/**
 * Llama AI Forensic Analyst Service
 * ──────────────────────────────────
 * Uses Meta's Llama 3.3 70B via Groq (free tier) to provide
 * AI-powered forensic analysis insights from file metadata.
 *
 * Groq free tier: https://console.groq.com
 * Model: llama-3.3-70b-versatile
 */

import Groq from 'groq-sdk';
import { AnalysisResult } from './types';
import { NormalizedMetadata } from './metadata-normalizer';
import { AttributionReport } from './attribution-analyst';
import { ChronologyReport } from './lifecycle-analyzer';
import { NetworkOriginReport } from './network-origin-analyzer';
import { GeoDeviceReport } from './geo-device-analyzer';
import { PrivacyRiskReport } from './privacy-risk-analyzer';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ChatMessage {
    role: 'user' | 'assistant' | 'system';
    content: string;
}

export interface LlamaAnalystSession {
    messages: ChatMessage[];
    fileContext: string;
}

// ── Client singleton ─────────────────────────────────────────────────────────

let _groq: Groq | null = null;

function getClient(): Groq {
    if (_groq) return _groq;
    const apiKey = import.meta.env.VITE_GROQ_API_KEY;
    if (!apiKey || apiKey === 'your_groq_api_key_here') {
        throw new Error('GROQ_API_KEY_MISSING');
    }
    _groq = new Groq({
        apiKey,
        dangerouslyAllowBrowser: true, // safe for demo/hackathon — use a backend proxy in production
    });
    return _groq;
}

// ── Context builder ──────────────────────────────────────────────────────────

/**
 * Builds a compact forensic context summary to inject into the system prompt.
 * Keeps token usage reasonable while giving Llama everything it needs.
 */
export function buildFileContext(
    result: AnalysisResult,
    n?: NormalizedMetadata | null,
    attribution?: AttributionReport | null,
    lifecycle?: ChronologyReport | null,
    network?: NetworkOriginReport | null,
    geo?: GeoDeviceReport | null,
    privacy?: PrivacyRiskReport | null,
): string {
    const m = result.metadata;
    const lines: string[] = [
        `=== SUBJECT FILE ===`,
        `Name: ${m.fileName}`,
        `Type: ${m.fileType} (${m.mimeType})`,
        `Size: ${(m.fileSize / 1024).toFixed(1)} KB`,
        `SHA-256: ${m.sha256Hash}`,
        `Analyzed: ${result.analyzedAt.toISOString()}`,
        `Risk level: ${result.riskLevel.toUpperCase()} (score: ${result.riskScore}/100)`,
        `Integrity status: ${result.integrityStatus.toUpperCase()}`,
        ``,
        `=== IDENTITY METADATA ===`,
        `Author: ${m.author ?? 'not present'}`,
        `Last modified by: ${m.lastModifiedBy ?? 'not present'}`,
        `Creator: ${m.creator ?? 'not present'}`,
        `Organization: ${m.organization ?? 'not present'}`,
        `Device owner: ${m.deviceOwner ?? 'not present'}`,
        `Software: ${m.software ?? 'not present'}`,
        `Operating system: ${m.operatingSystem ?? 'not present'}`,
        `Device: ${m.device ?? 'not present'}`,
        ``,
        `=== TIMESTAMPS ===`,
        `Creation date: ${m.creationDate ? m.creationDate.toISOString() : 'not present'}`,
        `Modification date: ${m.modificationDate ? m.modificationDate.toISOString() : 'not present'}`,
        `Last modified (filesystem): ${m.lastModified.toISOString()}`,
        `Timezone: ${m.timezone ?? 'not present'}`,
        `GPS timestamp: ${m.gpsTimestamp ?? 'not present'}`,
    ];

    if (m.gpsLatitude !== undefined) {
        lines.push(``, `=== GPS LOCATION ===`);
        lines.push(`Latitude: ${m.gpsLatitude}`);
        lines.push(`Longitude: ${m.gpsLongitude}`);
        lines.push(`Altitude: ${m.gpsAltitude ?? 'not present'} m`);
    }

    lines.push(``, `=== NETWORK ARTIFACTS ===`);
    lines.push(`Embedded IPs: ${result.networkIndicators.ips.join(', ') || 'none'}`);
    lines.push(`Embedded emails: ${result.networkIndicators.emails.join(', ') || 'none'}`);
    lines.push(`UNC paths: ${result.networkIndicators.uncPaths.join(', ') || 'none'}`);
    lines.push(`URLs: ${result.networkIndicators.urls.slice(0, 5).join(', ') || 'none'}`);

    lines.push(``, `=== HIDDEN ARTIFACTS ===`);
    lines.push(`Has macros: ${result.hiddenArtifacts.hasMacros}`);
    lines.push(`Has embedded scripts: ${result.hiddenArtifacts.hasEmbeddedScripts}`);
    lines.push(`Has hidden text: ${result.hiddenArtifacts.hasHiddenText}`);
    lines.push(`Revision count: ${result.hiddenArtifacts.revisionCount}`);
    lines.push(`Deleted content: ${result.hiddenArtifacts.deletedContent}`);

    if (result.anomalies.length > 0) {
        lines.push(``, `=== DETECTED ANOMALIES ===`);
        result.anomalies.slice(0, 10).forEach(a => {
            lines.push(`[${a.severity.toUpperCase()}] ${a.title}: ${a.description}`);
        });
    }

    if (lifecycle) {
        lines.push(``, `=== LIFECYCLE ANALYSIS ===`);
        lines.push(`Verdict: ${lifecycle.verdict.toUpperCase()}`);
        lines.push(`Integrity score: ${lifecycle.integrity_score}/100`);
        lines.push(`Verdict explanation: ${lifecycle.verdict_explanation}`);
        if (lifecycle.tampering_events.length > 0) {
            lines.push(`Tampering events (${lifecycle.tampering_events.length}):`);
            lifecycle.tampering_events.slice(0, 5).forEach(t => {
                lines.push(`  - [${t.severity.toUpperCase()}] ${t.title}: ${t.description}`);
            });
        }
    }

    if (attribution) {
        lines.push(``, `=== ATTRIBUTION ANALYSIS ===`);
        lines.push(`Overall confidence: ${attribution.overall_confidence_tier} (${attribution.overall_confidence_score}/100)`);
        lines.push(`Probable author: ${attribution.author.probable_name ?? 'unknown'}`);
        lines.push(`Probable email: ${attribution.author.probable_email ?? 'none'}`);
        lines.push(`Probable organization: ${attribution.organization.probable_organization ?? 'unknown'}`);
        lines.push(`Device owner: ${attribution.device_ownership.probable_owner ?? 'unknown'}`);
        lines.push(`System username: ${attribution.device_ownership.username_on_device ?? 'none'}`);
        lines.push(`Canonical username: ${attribution.username_analysis.canonical_username ?? 'none'}`);
        if (attribution.possible_identity_conflicts.length > 0) {
            lines.push(`Identity conflicts: ${attribution.possible_identity_conflicts.map(c => c.description).slice(0, 3).join(' | ')}`);
        }
        if (attribution.osint_leads.length > 0) {
            lines.push(`OSINT leads: ${attribution.osint_leads.slice(0, 5).join('; ')}`);
        }
    }

    if (geo) {
        lines.push(``, `=== GEOGRAPHIC & DEVICE ANALYSIS ===`);
        lines.push(`GPS available: ${geo.gpsAvailable}`);
        if (geo.gpsCoordinates) {
            lines.push(`Coordinates: ${geo.gpsCoordinates.latitude}, ${geo.gpsCoordinates.longitude}`);
        }
        lines.push(`Device: ${geo.deviceProfile.fullDeviceString ?? 'not detected'}`);
        lines.push(`Device category: ${geo.deviceProfile.category ?? 'unknown'}`);
        lines.push(`OS ecosystem: ${geo.osEcosystem ?? 'unknown'} (${geo.osConfidence} confidence)`);
        if (!geo.gpsAvailable) {
            lines.push(`Estimated origin: ${geo.originEstimate.region} (${geo.originEstimate.confidence} confidence)`);
            lines.push(`Reasoning: ${geo.originEstimate.reasoning.join('; ')}`);
        }
    }

    if (privacy) {
        lines.push(``, `=== PRIVACY RISK ===`);
        lines.push(`Risk level: ${privacy.risk_level.toUpperCase()} (score: ${privacy.overall_risk_score}/100)`);
        lines.push(`Identity leakage: ${privacy.identity_leakage.score}/100`);
        lines.push(`Location exposure: ${privacy.location_exposure.score}/100`);
        lines.push(`Device traceability: ${privacy.device_traceability.score}/100`);
        lines.push(`Key leak sources: ${privacy.key_leak_sources.slice(0, 5).map(l => `${l.field}="${l.value}"`).join(', ')}`);
    }

    if (network && network.summary.total_artifacts > 0) {
        lines.push(``, `=== NETWORK ORIGIN ===`);
        lines.push(`Total artifacts: ${network.summary.total_artifacts}`);
        lines.push(`Network risk score: ${network.summary.network_risk_score}/100`);
        lines.push(`Verdict: ${network.summary.verdict}`);
    }

    return lines.join('\n');
}

// ── System prompt ────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are an expert digital forensic analyst with deep expertise in metadata analysis, file forensics, OSINT, and cybersecurity investigations. You are assisting a forensic examiner who has just analyzed a file using the Metadata Forensic Suite.

Your role:
- Analyze the forensic metadata provided and give expert, precise, actionable insights
- Answer questions about the file's origin, integrity, authorship, and privacy exposure
- Explain technical findings in clear language when asked
- Suggest next investigation steps based on what the metadata reveals
- Stay strictly within what the metadata evidence supports — no speculation beyond the data
- When something is uncertain or missing, say so explicitly

Important constraints:
- Base ALL conclusions only on the metadata context provided
- Never fabricate details not present in the metadata
- Use proper forensic language and maintain professional tone
- If asked about capabilities you don't have (live WHOIS, court orders, etc.), explain the limitation clearly

You have access to the complete forensic analysis of the submitted file shown in the context below.`;

// ── Core chat function ────────────────────────────────────────────────────────

export async function sendForensicChat(
    messages: ChatMessage[],
    fileContext: string,
    onChunk?: (text: string) => void,
): Promise<string> {
    const client = getClient();

    const systemMessage: ChatMessage = {
        role: 'system',
        content: `${SYSTEM_PROMPT}\n\n${fileContext}`,
    };

    const completion = await client.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [systemMessage, ...messages],
        temperature: 0.3,   // low temp for factual forensic analysis
        max_tokens: 1024,
        stream: true,
    });

    let fullText = '';
    for await (const chunk of completion) {
        const delta = chunk.choices[0]?.delta?.content ?? '';
        fullText += delta;
        if (onChunk) onChunk(delta);
    }
    return fullText;
}

// ── Preset forensic questions ────────────────────────────────────────────────

export const FORENSIC_PRESETS = [
    { label: '🔍 Executive Summary', prompt: 'Give me a concise executive summary of the most important forensic findings from this file analysis. What are the top 3 things an investigator should know?' },
    { label: '👤 Author Attribution', prompt: 'Based on all available metadata signals, who is the most likely author or creator of this file? What is the attribution confidence and what evidence supports it?' },
    { label: '⏱ Timeline Integrity', prompt: 'Analyze the timestamp chain for this file. Are the timestamps internally consistent? Are there any indicators of timestamp manipulation or tampering?' },
    { label: '📍 Location Analysis', prompt: 'What can you determine about where this file was created? Include GPS data if available, or estimate from indirect signals like timezone and device manufacturer.' },
    { label: '🌐 Network Exposure', prompt: 'What network artifacts are embedded in this file and what do they reveal? What attribution or investigation pivots do they provide?' },
    { label: '🔒 Privacy Risk', prompt: 'How much identifying information does this file expose? What would a threat actor learn from this file\'s metadata if it were shared publicly?' },
    { label: '⚠️ Red Flags', prompt: 'What are the most suspicious or anomalous findings in this analysis? List every red flag with its severity and explain why it matters forensically.' },
    { label: '🛡 Integrity Verdict', prompt: 'What is your assessment of this file\'s integrity? Has it been tampered with? What is the confidence level and what evidence supports the verdict?' },
    { label: '📋 Next Steps', prompt: 'Based on these forensic findings, what are the recommended next investigation steps? What additional data sources would be most valuable to pursue?' },
];
