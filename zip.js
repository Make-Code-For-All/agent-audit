'use strict';
/* Agent Audit: reader for .zip archives chosen from the visitor's device.
   The archive is never loaded whole: the list of entries is read from the end of the file, and each
   entry is then read and unpacked on its own, so large archives are fine. Nothing in the archive is
   ever executed or written anywhere. Loaded before app.js.

   listZip(blob)                    -> [{ path, size, type, encrypted, ... }], type is 'file', 'dir' or 'link'
   readZipEntry(blob, entry, max)   -> Uint8Array with the entry's contents; refuses anything over max bytes */

const ZIP_MAX_DIRECTORY = 128 * 1024 * 1024; // the list of entries itself; real archives are far below this

async function listZip(blob){
  const bytes = async (start, end) => new Uint8Array(await blob.slice(start, end).arrayBuffer());
  const bad = () => new Error('It is not a zip archive, or it is damaged.');

  // The "end of central directory" record is at the very end, after an optional comment of up to 65,535 bytes.
  const tailStart = Math.max(0, blob.size - 65557);
  const tail = await bytes(tailStart, blob.size);
  const tv = new DataView(tail.buffer);
  let at = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (tv.getUint32(i, true) === 0x06054b50){ at = i; break; }
  if (at < 0) throw bad();
  let dirSize = tv.getUint32(at + 12, true), dirStart = tv.getUint32(at + 16, true);

  // Zip64: archives over 4 GB or with more than 65,535 entries keep the real numbers in a second record.
  if (tv.getUint16(at + 10, true) === 0xFFFF || dirSize === 0xFFFFFFFF || dirStart === 0xFFFFFFFF){
    const locAt = tailStart + at - 20;
    if (locAt >= 0){
      const loc = new DataView((await bytes(locAt, locAt + 20)).buffer);
      if (loc.getUint32(0, true) === 0x07064b50){
        const recAt = Number(loc.getBigUint64(8, true));
        const rec = new DataView((await bytes(recAt, recAt + 56)).buffer);
        if (rec.byteLength === 56 && rec.getUint32(0, true) === 0x06064b50){
          dirSize = Number(rec.getBigUint64(40, true));
          dirStart = Number(rec.getBigUint64(48, true));
        }
      }
    }
  }
  if (dirStart + dirSize > blob.size) throw bad();
  if (dirSize > ZIP_MAX_DIRECTORY) throw new Error('It lists too many entries to read.');

  const dir = await bytes(dirStart, dirStart + dirSize);
  const dv = new DataView(dir.buffer);
  const utf8 = new TextDecoder('utf-8');
  const entries = [];
  let p = 0;
  while (p + 46 <= dir.length && dv.getUint32(p, true) === 0x02014b50){
    const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true);
    let packed = dv.getUint32(p + 20, true), size = dv.getUint32(p + 24, true), offset = dv.getUint32(p + 42, true);
    const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true);
    const extraEnd = p + 46 + nameLen + extraLen;
    if (extraEnd > dir.length) break;
    const raw = utf8.decode(dir.subarray(p + 46, p + 46 + nameLen)).replace(/\\/g, '/');
    for (let q = p + 46 + nameLen; q + 4 <= extraEnd; ){
      const id = dv.getUint16(q, true), len = dv.getUint16(q + 2, true);
      if (id === 1){ // zip64 sizes, present only for the fields that overflowed
        let f = q + 4;
        if (size === 0xFFFFFFFF && f + 8 <= extraEnd){ size = Number(dv.getBigUint64(f, true)); f += 8; }
        if (packed === 0xFFFFFFFF && f + 8 <= extraEnd){ packed = Number(dv.getBigUint64(f, true)); f += 8; }
        if (offset === 0xFFFFFFFF && f + 8 <= extraEnd) offset = Number(dv.getBigUint64(f, true));
        break;
      }
      q += 4 + len;
    }
    const unixMode = dir[p + 5] === 3 ? dv.getUint32(p + 38, true) >>> 16 : 0;
    const type = raw.endsWith('/') ? 'dir' : (unixMode & 0xF000) === 0xA000 ? 'link' : 'file';
    const path = raw.replace(/^(?:\.?\/)+/, '').replace(/\/+$/, '');
    if (path) entries.push({ path, size, packed, offset, method, type, encrypted: (flags & 1) === 1 });
    p = extraEnd + commentLen;
  }
  return entries;
}

async function readZipEntry(blob, entry, maxBytes){
  if (entry.encrypted) throw new Error('password-protected');
  if (entry.method !== 0 && entry.method !== 8) throw new Error('unsupported compression');
  if (entry.size > maxBytes) throw new Error('too large');
  const head = new DataView(await blob.slice(entry.offset, entry.offset + 30).arrayBuffer());
  if (head.byteLength < 30 || head.getUint32(0, true) !== 0x04034b50) throw new Error('damaged entry');
  const start = entry.offset + 30 + head.getUint16(26, true) + head.getUint16(28, true);
  const packed = blob.slice(start, start + entry.packed);
  if (entry.method === 0){
    if (entry.packed > maxBytes) throw new Error('too large');
    return new Uint8Array(await packed.arrayBuffer());
  }
  // Unpack, stopping as soon as the entry grows past the size it declared (a "zip bomb" lies about this).
  const reader = packed.stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;){
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > entry.size) throw new Error('larger than its declared size');
      chunks.push(value);
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks){ out.set(c, at); at += c.length; }
  return out;
}

if (typeof module !== 'undefined') module.exports = { listZip, readZipEntry };
