import React, { createContext, useContext, useState, useCallback } from 'react';
import { AnalysisResult, ForensicRiskAssessment, NetworkIndicators, HiddenArtifacts } from '@/lib/types';
import { extractMetadata } from '@/lib/metadata-extractor';
import { analyzeFile } from '@/lib/tampering-detector';
import { scanFileContent } from '@/lib/content-scanner';
import { buildRawForensicJSON } from '@/lib/forensic-json-builder';
import { v4fallback } from '@/lib/id-utils';
import { saveAnalysisToFirestore } from '@/lib/firestore-service';
import { uploadEvidenceFile } from '@/lib/storage-service';
import { useAuth } from '@/context/AuthContext';

interface ForensicContextType {
  analyses: AnalysisResult[];
  currentAnalysis: AnalysisResult | null;
  isAnalyzing: boolean;
  progress: number;
  processFile: (file: File) => Promise<void>;
  selectAnalysis: (id: string) => void;
  clearCurrent: () => void;
}

const ForensicContext = createContext<ForensicContextType | null>(null);

function buildForensicAssessment(
  metadata: ReturnType<typeof Object.assign>,
  network: NetworkIndicators,
  artifacts: HiddenArtifacts,
  riskScore: number,
): ForensicRiskAssessment {
  const identityLeakageRisks: string[] = [];
  const suspiciousIndicators: string[] = [];
  const osintPotential: string[] = [];

  // Identity leakage
  if (metadata.author) identityLeakageRisks.push(`Author name exposed: "${metadata.author}"`);
  if (metadata.lastModifiedBy) identityLeakageRisks.push(`Last editor name exposed: "${metadata.lastModifiedBy}"`);
  if (metadata.deviceOwner) identityLeakageRisks.push(`Device owner exposed: "${metadata.deviceOwner}"`);
  if (network.emails.length > 0) identityLeakageRisks.push(`${network.emails.length} email address(es) found in file body`);
  if (network.uncPaths.length > 0) identityLeakageRisks.push(`Internal network paths exposed: ${network.uncPaths.join(', ')}`);
  if (metadata.device) identityLeakageRisks.push(`Camera/device fingerprint: "${metadata.device}"`);
  if (metadata.gpsLatitude !== undefined) identityLeakageRisks.push(`GPS location embedded: ${metadata.gpsLatitude?.toFixed(5)}°, ${metadata.gpsLongitude?.toFixed(5)}°`);
  if (metadata.operatingSystem) identityLeakageRisks.push(`OS fingerprint: "${metadata.operatingSystem}"`);

  // OSINT potential
  if (metadata.author) osintPotential.push(`Search "${metadata.author}" on LinkedIn, GitHub, social media`);
  if (network.emails.length > 0) osintPotential.push(`Enumerate emails for account recovery / breach exposure`);
  if (metadata.gpsLatitude !== undefined) osintPotential.push(`Reverse geocode GPS: ${metadata.gpsLatitude?.toFixed(5)}, ${metadata.gpsLongitude?.toFixed(5)}`);
  if (network.ips.length > 0) osintPotential.push(`WHOIS / geolookup on IPs: ${network.ips.join(', ')}`);
  if (metadata.device) osintPotential.push(`Match device "${metadata.device}" to known owner`);
  if (network.uncPaths.length > 0) osintPotential.push(`UNC paths reveal internal network structure`);

  // Suspicious indicators
  if (artifacts.hasMacros) suspiciousIndicators.push('VBA macros present — potential code execution risk');
  if (artifacts.hasEmbeddedScripts) suspiciousIndicators.push('JavaScript embedded in document — risk of script injection');
  if (artifacts.hasHiddenText) suspiciousIndicators.push('Hidden text found — content may be concealed');
  if (artifacts.deletedContent) suspiciousIndicators.push('Deleted/revised content may be recoverable');
  if (artifacts.suspiciousStreams.length > 0) suspiciousIndicators.push(...artifacts.suspiciousStreams);
  if (network.ips.length > 0) suspiciousIndicators.push(`${network.ips.length} IP address(es) embedded in file`);

  // Attribution confidence
  let attribution: ForensicRiskAssessment['attributionConfidence'] = 'none';
  const attributionScore = [
    metadata.author, metadata.lastModifiedBy, metadata.deviceOwner,
    network.emails.length > 0, metadata.device, metadata.gpsLatitude !== undefined,
    metadata.operatingSystem,
  ].filter(Boolean).length;

  if (attributionScore >= 5) attribution = 'high';
  else if (attributionScore >= 3) attribution = 'medium';
  else if (attributionScore >= 1) attribution = 'low';

  // Evidence integrity: inverse of risk score
  const integrityScore = Math.max(0, 100 - riskScore);

  return {
    attributionConfidence: attribution,
    identityLeakageRisks,
    evidenceIntegrityScore: integrityScore,
    suspiciousIndicators,
    osintPotential,
  };
}

export function ForensicProvider({ children }: { children: React.ReactNode }) {
  const [analyses, setAnalyses] = useState<AnalysisResult[]>([]);
  const [currentAnalysis, setCurrentAnalysis] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const { user } = useAuth();

  const processFile = useCallback(async (file: File) => {
    setIsAnalyzing(true);
    setProgress(0);

    const progressInterval = setInterval(() => {
      setProgress(p => Math.min(p + Math.random() * 12, 70));
    }, 180);

    try {
      // Step 1: Extract metadata (EXIF, PDF binary, DOCX XML)
      const metadata = await extractMetadata(file);
      setProgress(75);

      // Step 2: Content scan (network indicators + hidden artifacts)
      const { network, artifacts } = await scanFileContent(file);
      setProgress(82);

      // Step 3: Tampering anomaly detection
      const analysisData = analyzeFile(file, metadata, network, artifacts);
      setProgress(88);

      // Step 4: Build full forensic assessment
      const forensicAssessment = buildForensicAssessment(
        metadata, network, artifacts, analysisData.riskScore
      );
      setProgress(92);

      // Step 5: Image preview
      let filePreviewUrl: string | undefined;
      if (file.type.startsWith('image/')) {
        filePreviewUrl = URL.createObjectURL(file);
      }

      const result: AnalysisResult = {
        id: v4fallback(),
        file,
        filePreviewUrl,
        networkIndicators: network,
        hiddenArtifacts: artifacts,
        forensicAssessment,
        rawForensicJSON: {},   // placeholder — will be replaced below
        ...analysisData,
      };

      // Build the complete raw forensic JSON (pass full result)
      result.rawForensicJSON = buildRawForensicJSON(result);

      // Step 6: Firebase (if authenticated)
      if (user) {
        try {
          setProgress(95);
          const fileUrl = await uploadEvidenceFile(user.uid, file, metadata.sha256Hash);
          const firestoreId = await saveAnalysisToFirestore(user.uid, result, fileUrl);
          console.log(`[Firebase] Saved: ${firestoreId}`);
        } catch (err) {
          console.warn('[Firebase] Save failed (non-critical):', err);
        }
      }

      setProgress(100);
      setAnalyses(prev => [result, ...prev]);
      setCurrentAnalysis(result);
    } finally {
      clearInterval(progressInterval);
      setTimeout(() => { setIsAnalyzing(false); setProgress(0); }, 600);
    }
  }, [user]);

  const selectAnalysis = useCallback((id: string) => {
    const found = analyses.find(a => a.id === id);
    if (found) setCurrentAnalysis(found);
  }, [analyses]);

  const clearCurrent = useCallback(() => setCurrentAnalysis(null), []);

  return (
    <ForensicContext.Provider value={{ analyses, currentAnalysis, isAnalyzing, progress, processFile, selectAnalysis, clearCurrent }}>
      {children}
    </ForensicContext.Provider>
  );
}

export function useForensic() {
  const ctx = useContext(ForensicContext);
  if (!ctx) throw new Error('useForensic must be used within ForensicProvider');
  return ctx;
}
