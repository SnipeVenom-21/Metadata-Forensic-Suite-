// Firestore service — saves and reads analysis reports
// Collection: analysis_reports
import {
    collection,
    addDoc,
    getDocs,
    query,
    where,
    orderBy,
    serverTimestamp,
    Timestamp,
    doc,
    getDoc,
} from 'firebase/firestore';
import { db } from '@/lib/firebase';
import { AnalysisResult } from '@/lib/types';

export interface FirestoreAnalysis {
    id: string;
    userId: string;
    fileName: string;
    fileType: string;
    fileSize: number;
    sha256Hash: string;
    mimeType: string;
    riskScore: number;
    riskLevel: string;
    integrityStatus: string;
    riskExplanation: string;
    anomaliesCount: number;
    anomalies: Array<{
        id: string;
        type: string;
        severity: string;
        title: string;
        description: string;
    }>;
    metadata: {
        author?: string;
        software?: string;
        device?: string;
        creationDate?: string;
        modificationDate?: string;
        lastModified: string;
        uploadTimestamp: string;
        gpsLatitude?: number;
        gpsLongitude?: number;
        colorSpace?: string;
        dimensions?: { width: number; height: number };
    };
    fileUrl?: string;
    analyzedAt: Timestamp;
    createdAt: Timestamp;
}

/**
 * Save a completed analysis result to Firestore
 */
export async function saveAnalysisToFirestore(
    userId: string,
    result: AnalysisResult,
    fileUrl?: string
): Promise<string> {
    const m = result.metadata;

    const doc_data = {
        userId,
        fileName: m.fileName,
        fileType: m.fileType,
        fileSize: m.fileSize,
        sha256Hash: m.sha256Hash,
        mimeType: m.mimeType,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        integrityStatus: result.integrityStatus,
        riskExplanation: result.riskExplanation,
        anomaliesCount: result.anomalies.length,
        anomalies: result.anomalies.map((a) => ({
            id: a.id,
            type: a.type,
            severity: a.severity,
            title: a.title,
            description: a.description,
        })),
        metadata: {
            ...(m.author && { author: m.author }),
            ...(m.software && { software: m.software }),
            ...(m.device && { device: m.device }),
            ...(m.creationDate && { creationDate: m.creationDate.toISOString() }),
            ...(m.modificationDate && { modificationDate: m.modificationDate.toISOString() }),
            lastModified: m.lastModified.toISOString(),
            uploadTimestamp: m.uploadTimestamp.toISOString(),
            ...(m.gpsLatitude !== undefined && { gpsLatitude: m.gpsLatitude }),
            ...(m.gpsLongitude !== undefined && { gpsLongitude: m.gpsLongitude }),
            ...(m.colorSpace && { colorSpace: m.colorSpace }),
            ...(m.dimensions && { dimensions: m.dimensions }),
        },
        ...(fileUrl && { fileUrl }),
        analyzedAt: serverTimestamp(),
        createdAt: serverTimestamp(),
    };

    const docRef = await addDoc(collection(db, 'analysis_reports'), doc_data);
    return docRef.id;
}

/**
 * Fetch all analyses for a specific user (ordered by newest first)
 */
export async function getUserAnalyses(userId: string): Promise<FirestoreAnalysis[]> {
    const q = query(
        collection(db, 'analysis_reports'),
        where('userId', '==', userId),
        orderBy('createdAt', 'desc')
    );

    const snapshot = await getDocs(q);
    return snapshot.docs.map((d) => ({
        id: d.id,
        ...d.data(),
    })) as FirestoreAnalysis[];
}

/**
 * Fetch a single analysis by document ID
 */
export async function getAnalysisById(docId: string): Promise<FirestoreAnalysis | null> {
    const ref = doc(db, 'analysis_reports', docId);
    const snap = await getDoc(ref);
    if (!snap.exists()) return null;
    return { id: snap.id, ...snap.data() } as FirestoreAnalysis;
}

/**
 * Save user profile to Firestore 'users' collection
 */
export async function saveUserProfile(userId: string, email: string, displayName?: string) {
    const { setDoc } = await import('firebase/firestore');
    await setDoc(
        doc(db, 'users', userId),
        {
            userId,
            email,
            displayName: displayName || email.split('@')[0],
            role: 'investigator',
            createdAt: serverTimestamp(),
            lastLogin: serverTimestamp(),
        },
        { merge: true } // merge so we don't overwrite existing data on re-login
    );
}
