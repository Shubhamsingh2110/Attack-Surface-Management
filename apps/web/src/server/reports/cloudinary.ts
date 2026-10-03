import "server-only";
import { v2 as cloudinary } from "cloudinary";
import { getReportEnv } from "@asm/config";

function configuredClient() {
  const { CLOUDINARY_URL } = getReportEnv();
  if (!CLOUDINARY_URL.startsWith("cloudinary://")) throw new Error("CLOUDINARY_URL must use the cloudinary:// format.");
  cloudinary.config({ secure: true });
  return cloudinary;
}

export async function uploadPrivateReport(publicId: string, buffer: Buffer) {
  const client = configuredClient();
  return new Promise<{ publicId: string; bytes: number }>((resolve, reject) => {
    const stream = client.uploader.upload_stream(
      { public_id: publicId, resource_type: "raw", type: "authenticated", overwrite: false },
      (error, result) => error || !result ? reject(error ?? new Error("Cloudinary upload failed.")) : resolve({ publicId: result.public_id, bytes: result.bytes }),
    );
    stream.end(buffer);
  });
}

export function signedReportUrl(publicId: string, format: string) {
  return configuredClient().utils.private_download_url(publicId, format, {
    resource_type: "raw", type: "authenticated", attachment: true, expires_at: Math.floor(Date.now() / 1_000) + 300,
  });
}

export async function deletePrivateReports(publicIds: string[]) {
  if (!publicIds.length) return;
  await configuredClient().api.delete_resources(publicIds, { resource_type: "raw", type: "authenticated" });
}
