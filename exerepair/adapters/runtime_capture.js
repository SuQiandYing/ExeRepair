// Configuration contains offsets for an exact verified build, never file paths.
// Only non-sensitive status events are sent. The context is taken once via RPC.
const config = __CONFIG__;
const main = Process.mainModule;
if (Process.arch !== 'ia32') throw Error('capture requires an x86 target');
const engine = main.base.add(config.engineBaseDelta);
const dispatch = engine.add(config.dispatchRVA);
let armed = false, captured = null, options = null;

const selected = new NativeCallback((index, address) => {
  try {
    const g = ptr(address);
    if (index === config.optionsIndex) {
      const object = g.readPointer();
      options = {
        hardware_component_enabled: object.add(0x774).readU8() !== 0,
        registration_component_enabled: object.add(0x70a).readU8() !== 0
      };
    } else if (index === config.ksaIndex && captured === null) {
      if (options === null) throw Error('payload options were not observed');
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
      if (!descriptors.length || descriptors.length === 64)
        throw Error('invalid descriptor terminator');
      captured = {
        ...options, descriptors, key_length: g.add(8).readU32(),
        ciphertext: Array.from(new Uint8Array(payload.readByteArray(256)))
      };
      send({event: 'context_ready', descriptor_count: descriptors.length});
    }
  } catch (error) {
    send({event: 'capture_error', error: String(error)});
  }
}, 'void', ['uint', 'uint']);

// Park the target thread before KSA; the agent thread remains available for RPC.
// TinyCC's CModule parser does not accept __stdcall annotations.  The import
// is therefore a cdecl callback whose JS body calls Win32 Sleep explicitly
// with the stdcall ABI.
const sleepAddress = Module.getGlobalExportByName('Sleep');
const sleepNative = new NativeFunction(sleepAddress, 'void', ['uint'], 'stdcall');
const pauseMs = new NativeCallback(ms => sleepNative(ms), 'void', ['uint']);
const monitor = new CModule(`
#include <gum/guminterceptor.h>
extern void selected(unsigned int index, unsigned int guest);
extern void pause_ms(unsigned int ms);
void on_enter(GumInvocationContext *ic) {
  unsigned int index = ic->cpu_context->esi;
  if (index == ${config.optionsIndex} || index == ${config.ksaIndex}) {
    selected(index, *(unsigned int *)(ic->cpu_context->ebp + 12) + 16);
    if (index == ${config.ksaIndex}) {
      while (1) pause_ms(100);
    }
  }
}
`, {selected, pause_ms: pauseMs});

function tryHook() {
  if (armed) return;
  // Unmapped or partly initialized engine memory is normal during bootstrap.
  try {
    if (dispatch.readU8() !== 0xa1 ||
        !dispatch.add(1).readPointer().equals(engine.add(config.dispatchGlobalRVA)) ||
        !engine.add(config.dispatchGlobalRVA - 4).readPointer().equals(engine) ||
        !engine.add(config.dispatchGlobalRVA).readPointer().equals(engine.add(config.tableOffset)))
      return;
  } catch (_) { return; }
  try {
    const table = engine.add(config.tableOffset);
    for (const index of [config.predicateIndex, config.trueIndex]) {
      if (index < 0 || index >= config.tableCount ||
          table.add(index * 4).readU32() !== config.trueRecordOffset)
        throw Error('captured predicate table does not match the gate-only image');
    }
    for (const [index, operand] of [
      [config.ksaIndex, config.ksaOperand], [config.prgaIndex, config.prgaOperand]
    ]) {
      if (index < 0 || index >= config.tableCount) throw Error('VM call index out of range');
      const record = engine.add(table.add(index * 4).readU32());
      if (record.readU32() !== 0x60 || record.add(28).readU32() !== operand ||
          (config.nativeTargetType !== null && record.add(12).readU32() !== config.nativeTargetType))
        throw Error('captured native call guard failed');
    }
    Interceptor.attach(dispatch, {onEnter: monitor.on_enter});
    Interceptor.flush();
    armed = true;
  } catch (error) {
    armed = true;
    send({event: 'capture_error', error: String(error)});
  }
}

for (const [dll, names] of [
  ['kernel32.dll', ['VirtualProtect', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress']],
  ['ntdll.dll', ['NtProtectVirtualMemory']]
]) {
  for (const name of names) {
    Interceptor.attach(Process.getModuleByName(dll).getExportByName(name), {onLeave: tryHook});
  }
}
tryHook();
rpc.exports = {
  take() { const result = captured; captured = null; return result; }
};
