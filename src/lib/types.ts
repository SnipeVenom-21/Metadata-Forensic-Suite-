// ── Core Metadata ──────────────────────────────────────────────────────────
export interface FileMetadata {
  fileName: string;
  fileSize: number;
  fileType: string;
  mimeType: string;
  lastModified: Date;
  uploadTimestamp: Date;
  sha256Hash: string;

  // Author & Ownership
  author?: string;
  creator?: string;
  lastModifiedBy?: string;
  organization?: string;
  deviceOwner?: string;

  // Device & Software
  software?: string;
  softwareVersion?: string;
  operatingSystem?: string;
  device?: string;
  appVersion?: string;

  // Timeline
  creationDate?: Date;
  modificationDate?: Date;
  accessDate?: Date;
  timezone?: string;

  // Location
  gpsLatitude?: number;
  gpsLongitude?: number;
  gpsAltitude?: number;
  gpsTimestamp?: string;
  locationReference?: string;

  // Image-specific
  colorSpace?: string;
  dimensions?: { width: number; height: number };
  dpi?: number;

  // Raw tag dump
  exifData?: Record<string, unknown>;
}

// ── Network & Source Indicators ────────────────────────────────────────────
export interface NetworkIndicators {
  emails: string[];
  ips: string[];
  urls: string[];
  uncPaths: string[];     // \\server\share paths
  hostnames: string[];
  externalRefs: string[];
}

// ── Hidden / Suspicious Artifacts ─────────────────────────────────────────
export interface HiddenArtifacts {
  hasMacros: boolean;
  hasEmbeddedScripts: boolean;
  hasEmbeddedFiles: boolean;
  hasHiddenText: boolean;
  revisionCount: number;
  deletedContent: boolean;
  suspiciousStreams: string[];
  embeddedObjectTypes: string[];
}

// ── Forensic Risk Assessment ───────────────────────────────────────────────
export interface ForensicRiskAssessment {
  attributionConfidence: 'high' | 'medium' | 'low' | 'none';
  identityLeakageRisks: string[];
  evidenceIntegrityScore: number;    // 0-100
  suspiciousIndicators: string[];
  osintPotential: string[];
}

// ── Anomaly ────────────────────────────────────────────────────────────────
export interface Anomaly {
  id: string;
  type: 'date_mismatch' | 'missing_metadata' | 'multiple_software' | 'timezone_inconsistency' | 'metadata_wiped' | 'network_artifact' | 'hidden_artifact' | 'identity_leakage';
  severity: 'low' | 'medium' | 'high';
  title: string;
  description: string;
}

export type RiskLevel = 'low' | 'medium' | 'high';

// ── Full Analysis Result ───────────────────────────────────────────────────
export interface AnalysisResult {
  id: string;
  file: File;
  filePreviewUrl?: string;
  metadata: FileMetadata;
  networkIndicators: NetworkIndicators;
  hiddenArtifacts: HiddenArtifacts;
  forensicAssessment: ForensicRiskAssessment;
  anomalies: Anomaly[];
  riskScore: number;
  riskLevel: RiskLevel;
  integrityStatus: 'authentic' | 'suspicious' | 'tampered';
  riskExplanation: string;
  analyzedAt: Date;
  /** Complete structured raw JSON — all tags including nulls */
  rawForensicJSON: Record<string, unknown>;
}

