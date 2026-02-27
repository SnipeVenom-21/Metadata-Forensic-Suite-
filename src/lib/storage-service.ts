// Firebase Storage service — uploads evidence files
import { ref, uploadBytes, getDownloadURL } from 'firebase/storage';
import { storage } from '@/lib/firebase';

/**
 * Upload an evidence file to Firebase Storage
 * Path: evidence/{userId}/{uuid}_{filename}
 * Returns the public download URL
 */
export async function uploadEvidenceFile(
    userId: string,
    file: File,
    sha256Hash: string
): Promise<string> {
    const ext = file.name.split('.').pop() || '';
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const storagePath = `evidence/${userId}/${sha256Hash}_${safeName}`;

    const storageRef = ref(storage, storagePath);

    // Add custom metadata for chain-of-custody tracking
    const metadata = {
        customMetadata: {
            originalName: file.name,
            uploadedBy: userId,
            sha256: sha256Hash,
            uploadedAt: new Date().toISOString(),
            mimeType: file.type,
        },
    };

    const snapshot = await uploadBytes(storageRef, file, metadata);
    const downloadURL = await getDownloadURL(snapshot.ref);
    return downloadURL;
}
