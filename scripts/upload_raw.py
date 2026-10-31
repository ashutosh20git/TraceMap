"""Stream a local log file to S3 as zstd while hashing the original bytes.

Nothing is staged on local disk. A JSON manifest with the SHA-256 and byte
count of the *uncompressed* source is written next to the object, because the
S3 ETag of a multipart upload is not a content hash.

    python scripts/upload_raw.py <local-file> <bucket> <key-prefix>
"""
import datetime as dt
import hashlib
import json
import os
import sys
import time

import boto3
import zstandard
from boto3.s3.transfer import TransferConfig


class HashingReader:
    def __init__(self, f, total):
        self.f, self.total, self.done = f, total, 0
        self.sha = hashlib.sha256()
        self.t0 = self.last = time.time()

    def read(self, n=-1):
        b = self.f.read(n)
        self.sha.update(b)
        self.done += len(b)
        now = time.time()
        if now - self.last > 30:
            self.last = now
            rate = self.done / (now - self.t0) / 1e6
            print(f"{self.done / 1e9:.2f}/{self.total / 1e9:.2f} GB read, {rate:.1f} MB/s", flush=True)
        return b


def main():
    path, bucket, prefix = sys.argv[1], sys.argv[2], sys.argv[3].strip("/")
    name = os.path.basename(path)
    key = f"{prefix}/{name}.zst"
    size = os.path.getsize(path)
    s3 = boto3.client("s3")
    with open(path, "rb") as f:
        src = HashingReader(f, size)
        reader = zstandard.ZstdCompressor(level=3, threads=-1, write_checksum=True).stream_reader(src)
        s3.upload_fileobj(
            reader, bucket, key,
            ExtraArgs={"ContentType": "application/zstd", "Metadata": {"source-name": name, "source-bytes": str(size)}},
            Config=TransferConfig(multipart_chunksize=64 << 20, max_concurrency=8),
        )
    head = s3.head_object(Bucket=bucket, Key=key)
    manifest = {
        "source_name": name,
        "source_bytes": src.done,
        "source_sha256": src.sha.hexdigest(),
        "hash_scope": "full uncompressed source file, streamed",
        "object_key": key,
        "object_version_id": head.get("VersionId"),
        "compressed_bytes": head["ContentLength"],
        "compression": "zstd level 3",
        "uploaded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    s3.put_object(Bucket=bucket, Key=f"{key}.manifest.json", Body=json.dumps(manifest, indent=2).encode(),
                  ContentType="application/json")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
