'use strict';

const kernel = Process.getModuleByName('kernel32.dll');
const getDriveType = kernel.getExportByName('GetDriveTypeA');
const virtualQuery = new NativeFunction(
  kernel.getExportByName('VirtualQuery'), 'uint32', ['pointer', 'pointer', 'uint32']
);
const readable = new Set([0x02, 0x04, 0x08, 0x20, 0x40, 0x80]);
let captured = false;
let capturedMain = false;

function snapshotExecutableSections(base, size, nt) {
  const sectionCount = nt.add(6).readU16();
  const optionalSize = nt.add(20).readU16();
  const headerSize = nt.add(0x54).readU32();
  const table = nt.add(24 + optionalSize);
  const tableEnd = table.sub(base).toUInt32() + sectionCount * 40;
  if (
    sectionCount === 0 || sectionCount > 96 || optionalSize < 0xe0 ||
    headerSize > size || tableEnd > headerSize || headerSize > 0x10000
  ) {
    throw new Error('invalid module headers');
  }
  const result = new Uint8Array(size);
  result.set(new Uint8Array(base.readByteArray(headerSize)), 0);
  const info = Memory.alloc(28);
  for (let index = 0; index < sectionCount; index++) {
    const section = table.add(index * 40);
    const virtualSize = section.add(8).readU32();
    const rva = section.add(12).readU32();
    const rawSize = section.add(16).readU32();
    const flags = section.add(36).readU32();
    if ((flags & 0x20000000) === 0) continue;
    const end = rva + Math.max(virtualSize, rawSize);
    if (rva < 0x1000 || end > size || end <= rva) {
      throw new Error('invalid executable section');
    }
    let position = rva;
    while (position < end) {
      const address = base.add(position);
      if (virtualQuery(address, info, 28) !== 28) {
        throw new Error('VirtualQuery failed');
      }
      const regionBase = info.readPointer().toUInt32();
      const allocationBase = info.add(4).readPointer();
      const regionSize = info.add(12).readU32();
      const state = info.add(16).readU32();
      const protect = info.add(20).readU32();
      const endAddress = Math.min(base.toUInt32() + end, regionBase + regionSize);
      const length = endAddress - address.toUInt32();
      if (length <= 0) throw new Error('invalid memory region');
      if (
        allocationBase.equals(base) && state === 0x1000 &&
        (protect & 0x100) === 0 && readable.has(protect & 0xff)
      ) {
        result.set(new Uint8Array(address.readByteArray(length)), position);
      }
      position += length;
    }
  }
  return result.buffer;
}

Interceptor.attach(getDriveType, {
  onEnter() {
    if (captured) return;
    try {
      const ret = this.returnAddress;
      const prefix = [0x90, 0x83, 0xf8, 0x05, 0x0f, 0x85];
      for (let index = 0; index < prefix.length; index++) {
        if (ret.add(index).readU8() !== prefix[index]) return;
      }
      const info = Memory.alloc(28);
      if (virtualQuery(ret, info, 28) !== 28) return;
      const base = info.add(4).readPointer();
      if (base.readU16() !== 0x5a4d) return;
      const ntOffset = base.add(0x3c).readU32();
      if (ntOffset < 0x40 || ntOffset > 0xf00) return;
      const nt = base.add(ntOffset);
      if (
        nt.readU32() !== 0x4550 || nt.add(4).readU16() !== 0x14c ||
        nt.add(24).readU16() !== 0x10b
      ) return;
      const size = nt.add(0x50).readU32();
      const caller = ret.sub(base).toUInt32();
      if (
        size < 0x1000 || size > 64 * 1024 * 1024 ||
        base.toUInt32() + size > 0x100000000 || caller >= size
      ) return;
      captured = true;
      const image = snapshotExecutableSections(base, size, nt);
      send({event: 'disc_evidence', base: base.toString(), caller_rva: caller}, image);
      recv('disc_patch', function (message) {
        const address = base.add(message.epilogue);
        Memory.patchCode(address, 3, function (code) {
          code.writeByteArray([0x33, 0xc0, 0x40]);
        });
        base.add(message.flag).writeU32(1);
      }).wait();
    } catch (error) {
      if (captured) send({event: 'disc_error', message: String(error)});
    }
  }
});
let messageHooked = false;
function containsDiscMarker(pointer) {
  let text = '';
  for (let index = 0; index < 256; index++) {
    const value = pointer.add(index).readU8();
    if (value === 0) break;
    text += String.fromCharCode(value).toLowerCase();
  }
  return text.indexOf('gamedisc') >= 0;
}
Process.attachModuleObserver({
  onAdded(module) {
    if (messageHooked || module.name.toLowerCase() !== 'user32.dll') return;
    messageHooked = true;
    const messageBoxA = module.getExportByName('MessageBoxA');
    Interceptor.attach(messageBoxA, {
      onEnter(args) {
        if (!captured || capturedMain) return;
        try {
          if (!containsDiscMarker(args[1])) return;
          const main = Process.mainModule;
          const base = main.base;
          const nt = base.add(base.add(0x3c).readU32());
          if (nt.readU32() !== 0x4550 || nt.add(24).readU16() !== 0x10b) return;
          const size = nt.add(0x50).readU32();
          if (size < 0x1000 || size > 64 * 1024 * 1024) return;
          const ret = this.returnAddress;
          if (ret.compare(base.add(6)) < 0 || ret.compare(base.add(size)) >= 0) return;
          const call = ret.sub(6);
          // The import may point through a protector thunk; this return
          // address is observed while the actual MessageBoxA hook is active.
          if (call.readU16() !== 0x15ff && ret.sub(2).readU16() !== 0xd3ff) return;
          capturedMain = true;
          const image = snapshotExecutableSections(base, size, nt);
          send({
            event: 'main_disc_evidence',
            base: base.toString(),
            return_rva: ret.sub(base).toUInt32()
          }, image);
          recv('finish', function () {}).wait();
        } catch (error) {
          if (capturedMain) send({event: 'disc_error', message: String(error)});
        }
      }
    });
  }
});
send({event: 'ready'});
