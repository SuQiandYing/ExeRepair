'use strict';

let configuredSections = [];
let hooked = new Set();
const main = Process.mainModule;

function readString(rva) {
  try {
    return main.base.add(rva).readUtf8String();
  } catch (_) {
    return null;
  }
}

function hexBytes(address, length) {
  const buffer = address.readByteArray(length);
  return Array.from(new Uint8Array(buffer))
    .map(value => value.toString(16).padStart(2, '0'))
    .join('');
}

function locateCandidates() {
  const pattern =
    '68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84 ?? ?? ?? ?? ' +
    '68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? ' +
    '68 ?? ?? ?? ?? ff d0 83 c4 04';
  const result = [];
  for (const section of configuredSections) {
    if ((section.characteristics & 0x20000000) === 0) {
      continue;
    }
    const start = main.base.add(section.rva);
    const hits = Memory.scanSync(start, section.size, pattern);
    for (const hit of hits) {
      const moduleRva = hit.address.add(1).readU32() - main.base.toUInt32();
      const nameRva = hit.address.add(22).readU32() - main.base.toUInt32();
      const moduleName = readString(moduleRva);
      const exportName = readString(nameRva);
      if (
        !moduleName ||
        moduleName.toLowerCase() !== 'plugin.dll' ||
        exportName !== 'executeAPI'
      ) {
        continue;
      }
      const signatureRva = hit.address.sub(main.base).toUInt32();
      const guardRva = signatureRva + 41;
      result.push({
        signature_rva: signatureRva,
        guard_rva: guardRva,
        call_rva: guardRva + 5,
        return_rva: guardRva + 7,
        guard_bytes: hexBytes(hit.address.add(41), 10),
        main_base: main.base.toString(),
        module_rva: moduleRva,
        name_rva: nameRva,
        module_name: moduleName,
        export: exportName
      });
    }
  }
  return result;
}

function hookExecuteAPI(module) {
  if (module.name.toLowerCase() !== 'plugin.dll' || hooked.has(module.base.toString())) {
    return;
  }
  let address = null;
  try {
    const exports = module.enumerateExports();
    const match = exports.find(item =>
      item.type === 'function' && item.name === 'executeAPI'
    );
    if (match) {
      address = match.address;
    }
  } catch (_) {
    address = null;
  }
  if (address === null) {
    return;
  }
  hooked.add(module.base.toString());
  send({
    event: 'executeAPI_hooked',
    module: module.name,
    address: address.toString()
  });
  Interceptor.attach(address, {
    onEnter() {
      const candidates = locateCandidates();
      const returnRva = this.returnAddress.sub(main.base).toUInt32();
      const matches = candidates.filter(candidate =>
        candidate.return_rva === returnRva
      );
      send({
        event: 'executeAPI_call',
        candidate_count: matches.length,
        return_rva: returnRva
      });
      if (matches.length === 1) {
        const evidence = Object.assign({}, matches[0], {
          candidate_count: matches.length
        });
        send({
          event: 'native_call_evidence',
          evidence: evidence
        });
      }
    }
  });
}

rpc.exports = {
  configure(sections) {
    configuredSections = sections;
    Process.enumerateModules().forEach(hookExecuteAPI);
    Process.attachModuleObserver({
      onAdded(module) {
        hookExecuteAPI(module);
      }
    });
    send({
      event: 'ready',
      arch: Process.arch,
      main: main.name
    });
  }
};
