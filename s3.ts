import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

// New dependency regardless (no S3 SDK was installed before this), so no
// reason to match the rest of the handler's aws-sdk v2 usage here — v3 is
// the current SDK generation.
const s3 = new S3Client({ region: process.env.AWS_REGION || 'us-east-1' });

const bucket = process.env.CHAT_MEDIA_BUCKET;
if (!bucket) throw new Error('CHAT_MEDIA_BUCKET env var is required');

const UPLOAD_URL_TTL_SECONDS = 10 * 60; // 10 min — plenty for a mobile client to start the PUT
const MEDIA_URL_TTL_SECONDS = 60 * 60; // 1 hr — long enough to view a chat without re-requesting constantly

export const getUploadUrl = (key: string, contentType: string): Promise<string> =>
  getSignedUrl(s3, new PutObjectCommand({ Bucket: bucket, Key: key, ContentType: contentType }), {
    expiresIn: UPLOAD_URL_TTL_SECONDS,
  });

export const getMediaUrl = (key: string): Promise<string> =>
  getSignedUrl(s3, new GetObjectCommand({ Bucket: bucket, Key: key }), { expiresIn: MEDIA_URL_TTL_SECONDS });

export const deleteMedia = async (key: string): Promise<void> => {
  await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
};
