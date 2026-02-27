/**
 * Content Scanner — scans raw file bytes for:
 *  - Embedded emails, IPs, URLs, UNC paths
 *  - Hidden artifacts (macros, scripts, embedded files)
 */
import { NetworkIndicators, HiddenArtifacts } from './types';

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const URL_RE = /https?:\/\/[^\s"'<>(){}\[\]\\,;]+/g;
const UNC_RE = /\\\\[A-Za-z0-9_\-\.]+\\[^\s"'<>]+/g;
const HOSTNAME_RE = /\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:com|net|org|io|gov|edu|local|internal|corp|lan)\b/g;

// Deduplicate + filter noise
function dedup(arr: string[]): string[] {
    return [...new Set(arr)].filter(Boolean);
}

function filterPrivateIPs(ips: string[]): string[] {
    // Keep only non-RFC1918 IPs (public) for OSINT relevance; flag all
    return ips;
}

export async function scanFileContent(file: File): Promise<{
    network: NetworkIndicators;
    artifacts: HiddenArtifacts;
}> {
    const ext = file.name.split('.').pop()?.toLowerCase() || '';
    const bytes = new Uint8Array(await file.arrayBuffer());

    // Decode as latin-1 to preserve byte values (safe for binary scanning)
    const text = new TextDecoder('latin1').decode(bytes);

    // ── Network Indicators ──────────────────────────────────────────────────
    const rawEmails = text.match(EMAIL_RE) || [];
    const rawIPs = text.match(IP_RE) || [];
    const rawURLs = text.match(URL_RE) || [];
    const rawUNC = text.match(UNC_RE) || [];
    const rawHostnames = text.match(HOSTNAME_RE) || [];
    const rawExternal: string[] = [];

    // Filter noise from URLs (Microsoft/Adobe CDN etc are expected in DOCX/PDF)
    const noiseDomains = ['schemas.openxmlformats.org', 'schemas.microsoft.com', 'www.w3.org',
        'purl.org', 'ns.adobe.com', 'xmlsoap.org', 'dublincore.org'];
    const filteredURLs = rawURLs.filter(u => !noiseDomains.some(n => u.includes(n)));

    // External references = any URL not localhost/schema
    filteredURLs.forEach(u => {
        if (!u.includes('localhost') && !u.includes('127.0.0.1')) rawExternal.push(u);
    });

    // Filter system/fake IPs
    const filteredIPs = filterPrivateIPs(
        dedup(rawIPs).filter(ip =>
            !ip.startsWith('0.') && !ip.startsWith('255.') && ip !== '0.0.0.0'
        )
    );

    // Filter schemas from hostnames
    const filteredHostnames = dedup(rawHostnames).filter(h => !noiseDomains.some(n => h.includes(n)));

    const network: NetworkIndicators = {
        emails: dedup(rawEmails.map(e => e.toLowerCase())),
        ips: filteredIPs,
        urls: dedup(filteredURLs),
        uncPaths: dedup(rawUNC),
        hostnames: filteredHostnames,
        externalRefs: dedup(rawExternal),
    };

    // ── Hidden Artifacts ────────────────────────────────────────────────────

    // DOCX / XLSX / PPTX (Office Open XML = ZIP)
    let hasMacros = false;
    let hasEmbeddedFiles = false;
    let hasHiddenText = false;
    let deletedContent = false;
    let revisionCount = 0;
    const suspiciousStreams: string[] = [];
    const embeddedObjectTypes: string[] = [];

    // Check ZIP directory for known macro/embed files
    if (['docx', 'xlsx', 'pptx', 'docm', 'xlsm'].includes(ext)) {
        if (text.includes('vbaProject.bin') || text.includes('xl/vbaProject') || ext === 'docm' || ext === 'xlsm') {
            hasMacros = true;
            suspiciousStreams.push('VBA Macro Project (vbaProject.bin)');
        }
        if (text.includes('embeddings/') || text.includes('oleObject')) {
            hasEmbeddedFiles = true;
            embeddedObjectTypes.push('OLE Object');
        }
        if (text.includes('word/embeddings')) {
            hasEmbeddedFiles = true;
            embeddedObjectTypes.push('Embedded Document');
        }
        if (text.includes('<w:rPrChange') || text.includes('<w:ins ') || text.includes('<w:del ')) {
            deletedContent = true;
            suspiciousStreams.push('Track Changes / Revision Markup');
        }
        if (text.includes('<w:vanish/>') || text.includes('<w:vanish />')) {
            hasHiddenText = true;
            suspiciousStreams.push('Hidden Text Elements (w:vanish)');
        }
        // Revision count
        const revMatch = text.match(/cp:revision[^>]*>(\d+)<\/cp:revision/);
        revisionCount = revMatch ? parseInt(revMatch[1]) : 0;
    }

    // PDF artifacts
    let hasEmbeddedScripts = false;
    if (ext === 'pdf') {
        if (text.includes('/JavaScript') || text.includes('/JS ')) {
            hasEmbeddedScripts = true;
            suspiciousStreams.push('Embedded JavaScript (/JavaScript stream)');
        }
        if (text.includes('/EmbeddedFile')) {
            hasEmbeddedFiles = true;
            embeddedObjectTypes.push('Embedded File Attachment');
        }
        if (text.includes('/Launch') || text.includes('/SubmitForm') || text.includes('/ImportData')) {
            suspiciousStreams.push('PDF Action: Launch/SubmitForm/ImportData (potentially malicious)');
        }
        if (text.includes('/AA ') || text.includes('/OpenAction')) {
            suspiciousStreams.push('Auto-Action on open (/OpenAction or /AA)');
        }
        if (text.includes('/XObject')) {
            embeddedObjectTypes.push('XObject (Image/Form embedded object)');
        }
        if (text.includes('/AcroForm')) {
            embeddedObjectTypes.push('AcroForm (Interactive PDF Form)');
        }
        // PDF revisions (appended %PDF sections = re-saves/tampering)
        const pdfHeaders = (text.match(/%PDF-/g) || []).length;
        revisionCount = Math.max(0, pdfHeaders - 1);
        if (revisionCount > 0) {
            suspiciousStreams.push(`PDF Incremental Update detected (${revisionCount} re-save revision${revisionCount > 1 ? 's' : ''})`);
            deletedContent = true;
        }
    }

    const artifacts: HiddenArtifacts = {
        hasMacros,
        hasEmbeddedScripts,
        hasEmbeddedFiles,
        hasHiddenText,
        revisionCount,
        deletedContent,
        suspiciousStreams,
        embeddedObjectTypes,
    };

    return { network, artifacts };
}
