// Only non-sensitive status events are sent. Context is retrieved once via RPC,
// kept in Python memory, and never written to a diagnostic file.
let captured = null;
let options = null;
let park = null;
const dispatch = 0x983b36;
const callHandler = 0x987935;
const guest = ctx => ptr(ctx.ebp).add(12).readPointer().add(16);
const handled = nc => {
  nc.add(20).writeU32(0); // DR6
  nc.add(192).writeU32((nc.add(192).readU32() & ~0x100) | 0x10000);
};
Process.setExceptionHandler(d => {
  if (d.type !== 'single-step') return false;
  const pc = ptr(d.context.pc).toUInt32();
  const nc = ptr(d.nativeContext);
  if (pc === callHandler) {
    if (ptr(d.context.ebx).add(28).readU32() === 0x4ad1) {
      nc.add(4).writeU32(dispatch);
      nc.add(24).writeU32(1); // DR0 local execute breakpoint
    }
  } else if (pc === dispatch) {
    const index = ptr(d.context.esi).toUInt32();
    if (index === 0x486f) {
      const object = guest(d.context).readPointer();
      options = {
        hardware_component_enabled: object.add(1908).readU8() !== 0,
        registration_component_enabled: object.add(1802).readU8() !== 0
      };
    } else if (index === 0x489f && captured === null) {
      const g = guest(d.context);
      const descriptor = g.add(12).readPointer();
      const payload = g.add(24).readPointer();
      const descriptors = [];
      for (let i = 0; i < 64; i++) {
        const record = descriptor.add(i * 80);
        const sourceRVA = record.add(16).readU32();
        if (sourceRVA === 0) break;
        descriptors.push({
          flags: record.add(4).readU32(),
          payload_size: record.add(8).readU32(),
          source_rva: sourceRVA,
          key_prefix: Array.from(new Uint8Array(record.add(20).readByteArray(16))),
          expected_crc: record.add(60).readU32()
        });
      }
      captured = {
        ...options,
        descriptors,
        key_length: g.add(8).readU32(),
        ciphertext: Array.from(new Uint8Array(payload.readByteArray(256)))
      };
      // Park BEFORE KSA/PRGA: no serial/component value is read or patched.
      park = Memory.alloc(Process.pageSize);
      Memory.protect(park, Process.pageSize, 'rwx');
      const sleep = Module.getGlobalExportByName('Sleep').toUInt32();
      park.writeByteArray([
        0x6a,0x64,0xb8,sleep&255,(sleep>>>8)&255,(sleep>>>16)&255,(sleep>>>24)&255,
        0xff,0xd0,0xeb,0xf5
      ]);
      nc.add(24).writeU32(0);
      handled(nc);
      d.context.pc = park;
      send({event:'context_ready', descriptor_count:descriptors.length});
      return true;
    }
  } else {
    return false;
  }
  handled(nc);
  return true;
});
rpc.exports = {
  take() {
    const result = captured;
    captured = null;
    return result;
  }
};
