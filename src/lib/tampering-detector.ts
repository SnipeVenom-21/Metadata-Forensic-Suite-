import { FileMetadata, Anomaly, RiskLevel, AnalysisResult, NetworkIndicators, HiddenArtifacts } from './types';
import { v4fallback } from './id-utils';

function generateId(): string {
  return v4fallback();
}

export function detectAnomalies(metadata: FileMetadata): Anomaly[] {
  const anomalies: Anomaly[] = [];

  // ── 1. Date mismatch: creation after modification ─────────────────────────
  if (metadata.creationDate && metadata.modificationDate) {
    if (metadata.creationDate > metadata.modificationDate) {
      anomalies.push({
        id: generateId(),
        type: 'date_mismatch',
        severity: 'high',
        title: 'Creation Date After Modification Date',
        description: `File claims to have been created on ${metadata.creationDate.toLocaleString()} but was modified on ${metadata.modificationDate.toLocaleString()}. This logical impossibility is a strong indicator of metadata tampering.`,
      });
    }
  }

  // ── 2. Future-dated timestamps ────────────────────────────────────────────
  const now = new Date();
  if (metadata.creationDate && metadata.creationDate > now) {
    anomalies.push({
      id: generateId(),
      type: 'date_mismatch',
      severity: 'high',
      title: 'Future Creation Date Detected',
      description: `Creation date (${metadata.creationDate.toLocaleString()}) is set in the future. This strongly suggests manual timestamp manipulation.`,
    });
  }
  if (metadata.modificationDate && metadata.modificationDate > now) {
    anomalies.push({
      id: generateId(),
      type: 'date_mismatch',
      severity: 'high',
      title: 'Future Modification Date Detected',
      description: `Modification date (${metadata.modificationDate.toLocaleString()}) is set in the future, which is physically impossible and indicates tampering.`,
    });
  }

  // ── 3. lastModified vs metadata modification date mismatch ────────────────
  if (metadata.modificationDate && metadata.lastModified) {
    const diffMs = Math.abs(metadata.modificationDate.getTime() - metadata.lastModified.getTime());
    const diffDays = diffMs / (1000 * 60 * 60 * 24);
    if (diffDays > 30) {
      anomalies.push({
        id: generateId(),
        type: 'date_mismatch',
        severity: 'medium',
        title: 'File System Date vs Metadata Date Discrepancy',
        description: `The embedded modification date (${metadata.modificationDate.toLocaleDateString()}) differs from the filesystem last-modified date (${metadata.lastModified.toLocaleDateString()}) by ${Math.round(diffDays)} days. This may indicate the file was re-exported or stamped with a false date.`,
      });
    }
  }

  // ── 4. Suspicious timestamp precision (exactly 00:00:00) ──────────────────
  const checkMidnight = (d: Date | undefined, label: string) => {
    if (!d) return;
    if (d.getHours() === 0 && d.getMinutes() === 0 && d.getSeconds() === 0) {
      anomalies.push({
        id: generateId(),
        type: 'date_mismatch',
        severity: 'low',
        title: `Suspiciously Rounded ${label}`,
        description: `The ${label.toLowerCase()} is exactly midnight (00:00:00). Legitimate camera/application timestamps rarely hit exactly midnight and may have been manually set.`,
      });
    }
  };
  checkMidnight(metadata.creationDate, 'Creation Date');
  checkMidnight(metadata.modificationDate, 'Modification Date');

  // ── 5. Missing critical metadata fields ───────────────────────────────────
  const criticalFields = ['author', 'creationDate', 'software'] as const;
  const missingFields = criticalFields.filter(f => !metadata[f]);
  if (missingFields.length >= 3) {
    anomalies.push({
      id: generateId(),
      type: 'metadata_wiped',
      severity: 'high',
      title: 'Critical Metadata Completely Stripped',
      description: `All key identifying fields are missing: ${missingFields.join(', ')}. Complete metadata removal is a strong indicator of deliberate evidence tampering or anti-forensics.`,
    });
  } else if (missingFields.length === 2) {
    anomalies.push({
      id: generateId(),
      type: 'metadata_wiped',
      severity: 'medium',
      title: 'Multiple Metadata Fields Missing',
      description: `Key metadata fields are absent: ${missingFields.join(', ')}. This pattern may indicate intentional metadata stripping using tools like ExifTool or metadata cleaners.`,
    });
  } else if (missingFields.length === 1) {
    anomalies.push({
      id: generateId(),
      type: 'missing_metadata',
      severity: 'low',
      title: `Missing Metadata: ${missingFields[0]}`,
      description: `The "${missingFields[0]}" field is absent. While this may be benign, it reduces the traceability of the file's origin.`,
    });
  }

  // ── 6. Editing software forensics ─────────────────────────────────────────
  if (metadata.software) {
    const sw = metadata.software.toLowerCase();

    // Known image editors (tampering tools)
    const imageEditors = ['photoshop', 'gimp', 'lightroom', 'affinity', 'pixelmator', 'paint.net', 'canva'];
    const videoEditors = ['ffmpeg', 'handbrake', 'premiere', 'after effects', 'davinci', 'final cut', 'avisynth'];
    const docEditors = ['libreoffice', 'openoffice', 'google docs', 'wps office'];

    const detectedImg = imageEditors.filter(e => sw.includes(e));
    const detectedVid = videoEditors.filter(e => sw.includes(e));

    // Multiple editing tools in one software string
    if (detectedImg.length > 1) {
      anomalies.push({
        id: generateId(),
        type: 'multiple_software',
        severity: 'high',
        title: 'Multiple Image Editing Tools Detected',
        description: `Evidence of multiple editing applications: ${detectedImg.join(', ')}. The file appears to have been processed through multiple editing pipelines, which is unusual for authentic files.`,
      });
    }

    // Video re-encoding tools
    if (detectedVid.length > 0 && metadata.fileType === 'MP4') {
      anomalies.push({
        id: generateId(),
        type: 'multiple_software',
        severity: 'medium',
        title: 'Video Re-encoding Tool Detected',
        description: `Software "${metadata.software}" indicates the video was re-encoded using ${detectedVid.join(', ')}. Re-encoding can strip original camera metadata and introduce artificial quality degradation.`,
      });
    }

    // Non-standard software for document type
    if (metadata.fileType === 'DOCX' && docEditors.some(e => sw.includes(e))) {
      anomalies.push({
        id: generateId(),
        type: 'multiple_software',
        severity: 'low',
        title: 'Alternative Office Suite Detected',
        description: `Document was last edited in "${metadata.software}" (not Microsoft Word). This may indicate the document was converted/re-saved, potentially altering its original metadata.`,
      });
    }
  }

  // ── 7. GPS coordinate anomaly checks ─────────────────────────────────────
  if (metadata.gpsLatitude !== undefined && metadata.gpsLongitude !== undefined) {
    const lat = metadata.gpsLatitude;
    const lon = metadata.gpsLongitude;

    // Null-island check (0,0 is suspicious for most photos)
    if (Math.abs(lat) < 0.001 && Math.abs(lon) < 0.001) {
      anomalies.push({
        id: generateId(),
        type: 'date_mismatch',
        severity: 'high',
        title: 'GPS Coordinates at Null Island (0°, 0°)',
        description: 'GPS coordinates are exactly 0°N, 0°E (offshore West Africa — "Null Island"). This is a common artifact of GPS data being zeroed out or fabricated.',
      });
    }

    // Suspiciously precise coordinates (more than 6 decimal places = likely fabricated)
    const latStr = lat.toString();
    const lonStr = lon.toString();
    const latDecimals = (latStr.split('.')[1] || '').length;
    const lonDecimals = (lonStr.split('.')[1] || '').length;
    if (latDecimals > 6 || lonDecimals > 6) {
      anomalies.push({
        id: generateId(),
        type: 'timezone_inconsistency',
        severity: 'low',
        title: 'Unusually Precise GPS Coordinates',
        description: `GPS precision of ${Math.max(latDecimals, lonDecimals)} decimal places exceeds typical hardware accuracy. Consumer GPS is accurate to ~5 decimal places; higher precision may indicate synthetic or tampered coordinates.`,
      });
    }
  }

  // ── 8. File size anomaly for images ───────────────────────────────────────
  if (metadata.dimensions && metadata.fileType === 'JPG' || metadata.fileType === 'JPEG') {
    const { width, height } = metadata.dimensions || { width: 0, height: 0 };
    if (width > 0 && height > 0) {
      const pixelCount = width * height;
      const bytesPerPixel = metadata.fileSize / pixelCount;
      // JPEG should typically be 0.1 – 2.0 bytes/pixel compressed
      if (bytesPerPixel > 5) {
        anomalies.push({
          id: generateId(),
          type: 'missing_metadata',
          severity: 'low',
          title: 'Unusual File Size to Dimension Ratio',
          description: `File size (${(metadata.fileSize / 1024).toFixed(1)} KB) is unusually large for a ${width}×${height} JPEG. This may indicate the image was embedded with hidden data or re-saved at very low compression.`,
        });
      }
    }
  }

  // ── 9. Very old or implausible creation dates ─────────────────────────────
  if (metadata.creationDate) {
    const year = metadata.creationDate.getFullYear();
    if (year < 1990) {
      anomalies.push({
        id: generateId(),
        type: 'date_mismatch',
        severity: 'medium',
        title: 'Implausibly Old Creation Date',
        description: `Creation date of ${year} predates consumer digital file formats. This is almost certainly a fabricated timestamp used to make a recent file appear historically old.`,
      });
    }
  }

  // ── 10. Upload time vs claimed creation time ──────────────────────────────
  if (metadata.creationDate && metadata.uploadTimestamp) {
    const uploadYear = metadata.uploadTimestamp.getFullYear();
    const createYear = metadata.creationDate.getFullYear();
    if (createYear > uploadYear) {
      anomalies.push({
        id: generateId(),
        type: 'date_mismatch',
        severity: 'high',
        title: 'Creation Date After Upload Time',
        description: `File claims a creation date in ${createYear} but was uploaded in ${uploadYear}. A file cannot be created after it is uploaded — this timestamp is impossible and likely fabricated.`,
      });
    }
  }

  return anomalies;
}

export function calculateRiskScore(anomalies: Anomaly[]): number {
  let score = 0;
  for (const a of anomalies) {
    switch (a.severity) {
      case 'high': score += 30; break;
      case 'medium': score += 15; break;
      case 'low': score += 7; break;
    }
  }
  return Math.min(100, score);
}

export function getRiskLevel(score: number): RiskLevel {
  if (score >= 60) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

export function getIntegrityStatus(riskLevel: RiskLevel): 'authentic' | 'suspicious' | 'tampered' {
  switch (riskLevel) {
    case 'low': return 'authentic';
    case 'medium': return 'suspicious';
    case 'high': return 'tampered';
  }
}

export function generateRiskExplanation(
  metadata: FileMetadata,
  anomalies: Anomaly[],
  riskScore: number,
  riskLevel: RiskLevel
): string {
  if (anomalies.length === 0) {
    return `"${metadata.fileName}" passed all forensic integrity checks with a risk score of ${riskScore}/100. No anomalies were detected in the metadata, timestamps, or file structure. The file appears authentic and unmodified. Chain-of-custody appears intact based on available metadata.`;
  }

  const highAnoms = anomalies.filter(a => a.severity === 'high');
  const medAnoms = anomalies.filter(a => a.severity === 'medium');
  const lowAnoms = anomalies.filter(a => a.severity === 'low');

  let explanation = `Forensic analysis of "${metadata.fileName}" detected ${anomalies.length} anomal${anomalies.length === 1 ? 'y' : 'ies'} with a composite risk score of ${riskScore}/100. `;

  if (riskLevel === 'high') {
    explanation += `The HIGH risk classification indicates strong forensic evidence of metadata tampering or file manipulation. `;
    if (highAnoms.length > 0) {
      explanation += `Critical issues detected: ${highAnoms.map(a => a.title).join('; ')}. `;
    }
    explanation += `This file should NOT be considered a reliable piece of evidence without independent corroboration.`;
  } else if (riskLevel === 'medium') {
    explanation += `The MEDIUM risk classification indicates suspicious characteristics that warrant further investigation. `;
    if (medAnoms.length > 0) {
      explanation += `Moderate concerns: ${medAnoms.map(a => a.title).join('; ')}. `;
    }
    explanation += `Recommend cross-referencing with additional evidence sources before accepting this file as authentic.`;
  } else {
    explanation += `The LOW risk classification indicates minor concerns that are likely benign. `;
    if (lowAnoms.length > 0) {
      explanation += `Minor observations: ${lowAnoms.map(a => a.title).join('; ')}. `;
    }
    explanation += `The file is likely authentic, but standard chain-of-custody verification is still recommended.`;
  }

  return explanation;
}

export function analyzeFile(
  file: File,
  metadata: FileMetadata,
  network?: NetworkIndicators,
  artifacts?: HiddenArtifacts,
): Omit<AnalysisResult, 'id' | 'file' | 'filePreviewUrl' | 'networkIndicators' | 'hiddenArtifacts' | 'forensicAssessment'> {
  const anomalies = detectAnomalies(metadata);

  // Extra anomalies from network scan
  if (network) {
    if (network.ips.length > 0) {
      anomalies.push({
        id: v4fallback(),
        type: 'network_artifact',
        severity: 'medium',
        title: `${network.ips.length} Embedded IP Address${network.ips.length > 1 ? 'es' : ''} Detected`,
        description: `IP address(es) found embedded in file content: ${network.ips.slice(0, 5).join(', ')}. May indicate network origin, server references, or tracking pixels.`,
      });
    }
    if (network.uncPaths.length > 0) {
      anomalies.push({
        id: v4fallback(),
        type: 'network_artifact',
        severity: 'high',
        title: 'Internal Network Path Exposed',
        description: `UNC/network path(s) found in file: ${network.uncPaths.slice(0, 3).join(', ')}. This reveals internal infrastructure and author's network topology — a major OSINT/identity leakage.`,
      });
    }
    if (network.emails.length > 0) {
      anomalies.push({
        id: v4fallback(),
        type: 'identity_leakage',
        severity: 'medium',
        title: `${network.emails.length} Email Address${network.emails.length > 1 ? 'es' : ''} Found`,
        description: `Email(s) embedded in file body: ${network.emails.slice(0, 3).join(', ')}. These can be used for attribution and OSINT correlation.`,
      });
    }
  }

  // Extra anomalies from artifact scan
  if (artifacts) {
    if (artifacts.hasMacros) {
      anomalies.push({
        id: v4fallback(),
        type: 'hidden_artifact',
        severity: 'high',
        title: 'VBA Macros Detected',
        description: 'The file contains VBA macro code. Macros can execute arbitrary code upon opening and are a common vector for malware delivery and credential theft.',
      });
    }
    if (artifacts.hasEmbeddedScripts) {
      anomalies.push({
        id: v4fallback(),
        type: 'hidden_artifact',
        severity: 'high',
        title: 'Embedded JavaScript Detected',
        description: 'JavaScript code is embedded in this PDF. This can execute silently when the file is opened and may perform malicious actions including phishing and data exfiltration.',
      });
    }
    if (artifacts.hasHiddenText) {
      anomalies.push({
        id: v4fallback(),
        type: 'hidden_artifact',
        severity: 'medium',
        title: 'Hidden Text Elements Found',
        description: 'Document contains text marked as hidden (w:vanish). Hidden content may include sensitive information, watermarks, or data intentionally concealed from readers.',
      });
    }
    if (artifacts.deletedContent) {
      anomalies.push({
        id: v4fallback(),
        type: 'hidden_artifact',
        severity: 'medium',
        title: 'Deleted / Revised Content Residue',
        description: 'Track changes, revision markup, or incremental PDF updates found. Previously deleted or modified content may be recoverable through forensic tools.',
      });
    }
    if (artifacts.revisionCount > 10) {
      anomalies.push({
        id: v4fallback(),
        type: 'hidden_artifact',
        severity: 'low',
        title: `High Revision Count (${artifacts.revisionCount})`,
        description: `Document has been revised ${artifacts.revisionCount} times. Heavy edit history increases the likelihood of embedded personal data and recoverable deleted content.`,
      });
    }
  }

  const riskScore = calculateRiskScore(anomalies);
  const riskLevel = getRiskLevel(riskScore);
  const integrityStatus = getIntegrityStatus(riskLevel);
  const riskExplanation = generateRiskExplanation(metadata, anomalies, riskScore, riskLevel);

  return {
    metadata,
    anomalies,
    riskScore,
    riskLevel,
    integrityStatus,
    riskExplanation,
    analyzedAt: new Date(),
  };
}
