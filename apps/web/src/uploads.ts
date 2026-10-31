// Browser -> S3 resumable multipart upload using presigned part URLs from the API.
// Nothing large passes through the API; parts go straight to S3.

import { withCase } from "./api";

const PARTS_IN_FLIGHT = 4;

export type UploadResult = { source_id?: string; duplicate_of?: string };

async function sha256Hex(buf: ArrayBuffer) {
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Cheap content fingerprint (first MiB + last MiB + size) used to spot the same file
 *  uploaded twice, including two concurrent uploads. The full SHA-256 is computed during ingest. */
export async function quickFingerprint(file: File) {
  const mib = 1 << 20;
  const head = await file.slice(0, mib).arrayBuffer();
  const tail = await file.slice(Math.max(0, file.size - mib)).arrayBuffer();
  const size = new TextEncoder().encode(String(file.size));
  const all = new Uint8Array(head.byteLength + tail.byteLength + size.byteLength);
  all.set(new Uint8Array(head), 0);
  all.set(new Uint8Array(tail), head.byteLength);
  all.set(size, head.byteLength + tail.byteLength);
  return sha256Hex(all.buffer);
}

export async function uploadFile(file: File, onProgress: (fraction: number, note?: string) => void): Promise<UploadResult> {
  onProgress(0, "fingerprinting");
  const quick_fp = await quickFingerprint(file);
  const r = await fetch(withCase("/api/uploads"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filename: file.name, size: file.size, quick_fp }),
  });
  if (!r.ok) throw new Error(`could not start upload: ${r.status} ${await r.text()}`);
  const session = await r.json();
  if (session.duplicate_of) {
    onProgress(1, "already uploaded");
    return { duplicate_of: session.duplicate_of };
  }
  const { source_id, part_size, urls } = session as { source_id: string; part_size: number; urls: string[] };
  const parts: { PartNumber: number; ETag: string }[] = [];
  let next = 0;
  let sent = 0;
  const worker = async () => {
    while (next < urls.length) {
      const i = next++;
      const blob = file.slice(i * part_size, Math.min((i + 1) * part_size, file.size));
      for (let attempt = 1; ; attempt++) {
        try {
          const res = await fetch(urls[i], { method: "PUT", body: blob });
          if (!res.ok) throw new Error(`part ${i + 1}: HTTP ${res.status}`);
          const etag = res.headers.get("ETag");
          if (!etag) throw new Error("S3 did not expose the ETag header (check bucket CORS)");
          parts.push({ PartNumber: i + 1, ETag: etag });
          sent += blob.size;
          onProgress(sent / file.size, `${parts.length}/${urls.length} parts`);
          break;
        } catch (e) {
          if (attempt >= 4) {
            await fetch(withCase(`/api/uploads/${source_id}/abort`), { method: "POST" });
            throw e;
          }
          await new Promise((res) => setTimeout(res, 1000 * 2 ** attempt));
        }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARTS_IN_FLIGHT, urls.length) }, worker));
  const done = await fetch(withCase(`/api/uploads/${source_id}/complete`), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ parts }),
  });
  if (!done.ok) throw new Error(`could not finalize upload: ${done.status}`);
  onProgress(1, "uploaded");
  return { source_id };
}
