import { getDriveClient } from "@/lib/oauth";
import { randomUUID } from "node:crypto";

const FILE_NAME = "secure-vault.v1.json";
const API = "https://www.googleapis.com/drive/v3";
const UPLOAD_API = "https://www.googleapis.com/upload/drive/v3";

type DriveFile = { id: string; name: string; version?: string; modifiedTime?: string; md5Checksum?: string };

export class DriveSyncError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DriveSyncError";
  }
}

export function mergeDriveHeaders(base: Headers, overrides?: HeadersInit): Headers {
  const headers = new Headers(base);
  new Headers(overrides).forEach((value, name) => headers.set(name, value));
  return headers;
}

export async function driveResponseError(response: Response, operation: string): Promise<DriveSyncError> {
  let status = "";
  let reason = "";
  let apiMessage = "";
  try {
    const payload: unknown = await response.clone().json();
    if (payload && typeof payload === "object" && "error" in payload) {
      const error = (payload as { error?: { status?: unknown; message?: unknown; errors?: Array<{ reason?: unknown }> } }).error;
      if (typeof error?.status === "string") status = error.status;
      if (typeof error?.message === "string") {
        apiMessage = error.message
          .replace(/[\r\n\t]+/g, " ")
          .replace(/\bya29\.[A-Za-z0-9._-]+/g, "[redacted]")
          .replace(/\b1\/\/[A-Za-z0-9._-]+/g, "[redacted]")
          .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted]")
          .slice(0, 180);
      }
      const firstReason = error?.errors?.find((item) => typeof item.reason === "string")?.reason;
      if (typeof firstReason === "string") reason = firstReason;
    }
  } catch {
    // The HTTP status remains enough to provide a safe, actionable message.
  }

  if (reason === "accessNotConfigured" || status === "SERVICE_DISABLED") {
    return new DriveSyncError("Google Drive API is not enabled for this Cloud project. Enable the Google Drive API in Google Cloud Console, wait for it to take effect, then retry.");
  }
  if (response.status === 401 || status === "UNAUTHENTICATED") {
    return new DriveSyncError("Google authorization expired or was revoked. Disconnect Google Drive in the app, reconnect, and approve access again.");
  }
  if (reason === "insufficientPermissions" || status === "PERMISSION_DENIED") {
    return new DriveSyncError("Google denied access to the app's Drive data. Reconnect Google Drive and approve the requested app-data permission.");
  }
  if (response.status === 429 || status === "RESOURCE_EXHAUSTED") {
    return new DriveSyncError("Google Drive quota was exceeded. Wait a while and retry.");
  }
  if (response.status === 400 && (reason || apiMessage)) {
    const details = [reason, apiMessage].filter(Boolean).join(": ");
    return new DriveSyncError(`Google Drive rejected the request to ${operation} (${details}). Check the Drive API request and retry.`);
  }
  return new DriveSyncError(`Google Drive could not ${operation} (HTTP ${response.status}). Check that the Drive API is enabled and retry.`);
}

async function request(url: string, init?: RequestInit) {
  const client = await getDriveClient();
  let headers: Awaited<ReturnType<typeof client.getRequestHeaders>>;
  try {
    headers = await client.getRequestHeaders();
  } catch {
    throw new DriveSyncError("Google authorization could not be refreshed. Disconnect Google Drive in the app, reconnect, and approve access again.");
  }
  return fetch(url, { ...init, headers: mergeDriveHeaders(headers, init?.headers) });
}

export async function findVault(): Promise<DriveFile[]> {
  const query = encodeURIComponent(`name='${FILE_NAME}' and 'appDataFolder' in parents and trashed=false`);
  const response = await request(`${API}/files?spaces=appDataFolder&q=${query}&fields=files(id,name,version,modifiedTime,md5Checksum)&pageSize=100`);
  if (!response.ok) throw await driveResponseError(response, "check Google Drive");
  const payload = await response.json() as { files?: DriveFile[] };
  return payload.files ?? [];
}

export async function downloadVault(fileId: string) {
  const response = await request(`${API}/files/${encodeURIComponent(fileId)}?alt=media`);
  if (!response.ok) throw await driveResponseError(response, "download the encrypted vault");
  return { content: await response.text(), etag: response.headers.get("etag") };
}

export async function uploadVault(content: string, expectedVersion?: string) {
  if (new TextEncoder().encode(content).byteLength > 1_500_000) throw new Error("Vault file is too large.");
  const existing = await findVault();
  if (existing.length > 1) throw new Error("Multiple vault files were found. Resolve duplicates before syncing.");
  if (existing.length === 0) {
    const boundary = `securevault_${randomUUID()}`;
    const metadata = JSON.stringify({ name: FILE_NAME, parents: ["appDataFolder"], mimeType: "application/json" });
    const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n${content}\r\n--${boundary}--`;
    const response = await request(`${UPLOAD_API}/files?uploadType=multipart&fields=id,name,version,modifiedTime,md5Checksum`, {
      method: "POST", headers: { "Content-Type": `multipart/related; boundary=${boundary}` }, body,
    });
    if (!response.ok) throw await driveResponseError(response, "create the encrypted vault");
    return await response.json() as DriveFile;
  }
  const file = existing[0];
  if (expectedVersion && expectedVersion !== file.version) throw new Error("Drive vault changed elsewhere. Download and resolve the newer version before uploading.");
  const etag = await request(`${API}/files/${encodeURIComponent(file.id)}?fields=id,version`).then((res) => {
    if (!res.ok) throw driveResponseError(res, "verify the current Drive revision");
    return res.headers.get("etag");
  });
  const response = await request(`${API}/upload/drive/v3/files/${encodeURIComponent(file.id)}?uploadType=media&fields=id,name,version,modifiedTime,md5Checksum`, {
    method: "PATCH", headers: { "Content-Type": "application/json", ...(etag ? { "If-Match": etag } : {}) }, body: content,
  });
  if (response.status === 412) throw new Error("Drive vault changed during upload. No local data was overwritten.");
  if (!response.ok) throw await driveResponseError(response, "update the encrypted vault");
  return await response.json() as DriveFile;
}

export async function syncVault(content?: string, version?: string) {
  const files = await findVault();
  if (files.length > 1) throw new Error("Multiple vault files were found. Resolve duplicates before syncing.");
  if (content !== undefined) {
    const saved = await uploadVault(content, version);
    const check = await downloadVault(saved.id);
    if (check.content !== content) throw new Error("Drive verification failed; the uploaded vault did not match.");
    return { action: "uploaded" as const, file: saved };
  }
  if (files.length === 0) return { action: "missing" as const };
  const downloaded = await downloadVault(files[0].id);
  return { action: "downloaded" as const, file: files[0], ...downloaded };
}