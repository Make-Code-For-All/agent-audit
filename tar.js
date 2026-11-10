'use strict';
/* Agent Audit: streaming reader for .tar.gz archives (the format GitHub uses for repository downloads).
   The archive is unpacked piece by piece as it downloads, so a repository of any size can be read
   without holding all of it in memory. Nothing in the archive is ever executed. Loaded before app.js.

   readTarGz(stream, {
     entry(info)        called for every item; info = { path, size, type } where type is
                        'file', 'dir', 'link' or 'other'. Return true to receive the file's contents.
     file(path, bytes)  called with the contents (a Uint8Array) of each file that entry() accepted.
   })
   Paths have the archive's top-level folder (GitHub adds "repo-commit/") removed. */

async function readTarGz(stream, handlers){
  const reader = stream.pipeThrough(new DecompressionStream('gzip')).getReader();
  const utf8 = new TextDecoder('utf-8');
  let buf = new Uint8Array(0), pos = 0;

  // Read exactly n bytes. With keep=false the bytes are discarded without being copied.
  async function take(n, keep){
    const out = keep ? new Uint8Array(n) : null;
    let got = 0;
    while (got < n){
      if (pos >= buf.length){
        const { done, value } = await reader.read();
        if (done) throw new Error('The download ended before the archive was complete.');
        buf = value; pos = 0;
        continue;
      }
      const k = Math.min(n - got, buf.length - pos);
      if (out) out.set(buf.subarray(pos, pos + k), got);
      pos += k; got += k;
    }
    return out;
  }
  const str = (block, start, len) => {
    let end = start;
    while (end < start + len && block[end] !== 0) end++;
    return utf8.decode(block.subarray(start, end));
  };
  const num = (block, start, len) => {
    if (block[start] & 0x80){ // base-256, used for sizes of 8 GB and above
      let n = 0;
      for (let i = start + 1; i < start + len; i++) n = n * 256 + block[i];
      return n;
    }
    const n = parseInt(str(block, start, len).trim() || '0', 8);
    return Number.isFinite(n) ? n : 0;
  };
  // Extended headers: records of the form "<length> <key>=<value>\n".
  const parsePax = (bytes) => {
    const out = {};
    let i = 0;
    while (i < bytes.length){
      let sp = i;
      while (sp < bytes.length && bytes[sp] !== 0x20) sp++;
      const len = parseInt(utf8.decode(bytes.subarray(i, sp)), 10);
      if (!len || i + len > bytes.length) break;
      const rec = utf8.decode(bytes.subarray(sp + 1, i + len - 1));
      const eq = rec.indexOf('=');
      if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
      i += len;
    }
    return out;
  };
  const stripTop = (p) => { const i = p.indexOf('/'); return i < 0 ? '' : p.slice(i + 1); };

  let override = {};
  try {
    for (;;){
      const head = await take(512, true);
      if (head.every((b) => b === 0)) break; // end-of-archive marker
      const flag = head[156] === 0 ? '0' : String.fromCharCode(head[156]);
      let size = num(head, 124, 12);
      const pad = () => take((512 - (size % 512)) % 512, false);

      if (flag === 'x' || flag === 'L' || flag === 'K' || flag === 'g'){
        const data = await take(size, true);
        await pad();
        if (flag === 'x'){ const p = parsePax(data); if (p.path) override.path = p.path; if (p.size) override.size = parseInt(p.size, 10); }
        else if (flag === 'L') override.path = str(data, 0, data.length);
        continue; // 'g' (repository-wide comment) and 'K' (long link target) are not needed
      }

      let name = str(head, 0, 100);
      if (str(head, 257, 5) === 'ustar'){ const prefix = str(head, 345, 155); if (prefix) name = prefix + '/' + name; }
      if (override.path) name = override.path;
      if (Number.isFinite(override.size)) size = override.size;
      override = {};

      const type = (flag === '0' || flag === '7') ? 'file' : flag === '5' ? 'dir' : (flag === '1' || flag === '2') ? 'link' : 'other';
      const path = stripTop(name).replace(/\/+$/, '');
      const wanted = path ? handlers.entry({ path, size, type }) : false;
      if (type === 'file' && wanted){
        const bytes = await take(size, true);
        await pad();
        await handlers.file(path, bytes);
      } else {
        await take(size, false);
        await pad();
      }
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}

if (typeof module !== 'undefined') module.exports = { readTarGz };
