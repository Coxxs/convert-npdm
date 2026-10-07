// NPDM -> JSON
//
// Anything in the binary that the JSON format cannot express is reported
// through `warnings`.

import { SYSCALL_NAMES } from "./syscalls.ts";
import type { FilesystemAccess, KernelCapability, NpdmJson } from "./types.ts";

const MAGIC_META = "META";
const MAGIC_ACID = "ACID";
const MAGIC_ACI0 = "ACI0";

function hex(value: number | bigint, digits: number): string {
  return "0x" + value.toString(16).padStart(digits, "0");
}

export interface ParseResult {
  json: NpdmJson;
  warnings: string[];
}


class Reader {
  private readonly view: DataView;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get length(): number {
    return this.bytes.byteLength;
  }

  private check(offset: number, size: number): void {
    if (offset < 0 || offset + size > this.bytes.byteLength) {
      throw new Error(
        `Read of ${size} bytes at ${hex(offset, 1)} is out of bounds (file size ${hex(this.bytes.byteLength, 1)})`,
      );
    }
  }

  u8(offset: number): number {
    this.check(offset, 1);
    return this.view.getUint8(offset);
  }

  u32(offset: number): number {
    this.check(offset, 4);
    return this.view.getUint32(offset, true);
  }

  u64(offset: number): bigint {
    this.check(offset, 8);
    return this.view.getBigUint64(offset, true);
  }

  slice(offset: number, size: number): Uint8Array {
    this.check(offset, size);
    return this.bytes.subarray(offset, offset + size);
  }

  ascii(offset: number, size: number): string {
    return String.fromCharCode(...this.slice(offset, size));
  }

  cstring(offset: number, size: number): string {
    const raw = this.slice(offset, size);
    const end = raw.indexOf(0);
    return new TextDecoder("utf-8").decode(end === -1 ? raw : raw.subarray(0, end));
  }
}

interface SectionHeader {
  offset: number;
  size: number;
}

function section(r: Reader, at: number): SectionHeader {
  return { offset: r.u32(at), size: r.u32(at + 4) };
}

interface SacEntry {
  name: string;
  isServer: boolean;
}

function parseSac(r: Reader, start: number, size: number): SacEntry[] {
  const entries: SacEntry[] = [];
  let pos = start;
  const end = start + size;
  while (pos < end) {
    const ctrl = r.u8(pos++);
    const len = (ctrl & 7) + 1;
    entries.push({ name: r.ascii(pos, len), isServer: (ctrl & 0x80) !== 0 });
    pos += len;
  }
  return entries;
}

function readWords(r: Reader, start: number, size: number): number[] {
  const words: number[] = [];
  for (let i = 0; i + 4 <= size; i += 4) words.push(r.u32(start + i));
  return words;
}

/** Number of trailing one bits; identifies the kernel capability type. */
function trailingOnes(word: number): number {
  let n = 0;
  while (n < 32 && (word >>> n) & 1) n++;
  return n;
}

function parseKernelCapabilities(words: number[], warnings: string[]): KernelCapability[] {
  const caps: KernelCapability[] = [];
  // All EnableSystemCalls descriptors are merged into a single "syscalls"
  // entry, placed where the first one appeared (buildNpdm splits them again).
  let syscalls: Record<string, string> | undefined;

  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    switch (trailingOnes(w)) {
      case 3: // ThreadInfo
        caps.push({
          type: "kernel_flags",
          value: {
            highest_thread_priority: (w >>> 10) & 0x3f,
            lowest_thread_priority: (w >>> 4) & 0x3f,
            lowest_cpu_id: (w >>> 16) & 0xff,
            highest_cpu_id: (w >>> 24) & 0xff,
          },
        });
        break;

      case 4: {
        // EnableSystemCalls
        if (!syscalls) {
          syscalls = {};
          caps.push({ type: "syscalls", value: syscalls });
        }
        const index = (w >>> 29) & 7;
        const mask = (w >>> 5) & 0xffffff;
        for (let bit = 0; bit < 24; bit++) {
          if (!((mask >>> bit) & 1)) continue;
          const id = index * 24 + bit;
          syscalls[SYSCALL_NAMES[id] ?? `svcUnknown${hex(id, 2)}`] = hex(id, 2);
        }
        break;
      }

      case 6: {
        // MemoryMap, stored as a pair of descriptors
        const next = words[i + 1];
        if (next === undefined || trailingOnes(next) !== 6) {
          warnings.push(`MemoryMap descriptor ${hex(w, 8)} is missing its second half; skipped`);
          break;
        }
        i++;
        const address =
          (BigInt((w >>> 7) & 0xffffff) << 12n) | (BigInt((next >>> 27) & 0xf) << 36n);
        const size = BigInt((next >>> 7) & 0xfffff) << 12n;
        caps.push({
          type: "map",
          value: {
            address: hex(address, 10),
            size: hex(size, 8),
            is_ro: (w >>> 31) !== 0,
            is_io: (next >>> 31) === 0,
          },
        });
        break;
      }

      case 7: // IoMemoryMap
        caps.push({ type: "map_page", value: hex(BigInt(w >>> 8) << 12n, 10) });
        break;

      case 10: {
        // MemoryRegionMap
        const regions: { region_type: number; is_ro: boolean }[] = [];
        for (let j = 0; j < 3; j++) {
          const field = (w >>> (11 + 7 * j)) & 0x7f;
          regions.push({ region_type: field & 0x3f, is_ro: (field & 0x40) !== 0 });
        }
        caps.push({ type: "map_region", value: regions });
        break;
      }

      case 11: {
        // EnableInterrupts; 0x3FF means "no interrupt"
        const irq = (v: number) => (v === 0x3ff ? null : v);
        caps.push({ type: "irq_pair", value: [irq((w >>> 12) & 0x3ff), irq((w >>> 22) & 0x3ff)] });
        break;
      }

      case 13: // MiscParams
        caps.push({ type: "application_type", value: (w >>> 14) & 7 });
        break;

      case 14: // KernelVersion
        caps.push({ type: "min_kernel_version", value: hex((w >>> 15) & 0xffff, 4) });
        break;

      case 15: // HandleTableSize
        caps.push({ type: "handle_table_size", value: (w >>> 16) & 0x3ff });
        break;

      case 16: // MiscFlags
        caps.push({
          type: "debug_flags",
          value: {
            allow_debug: ((w >>> 17) & 1) !== 0,
            force_debug: ((w >>> 19) & 1) !== 0,
            ...(((w >>> 18) & 1) !== 0 && { force_debug_prod: true }),
          },
        });
        break;

      case 32: // all ones: unused / padding
        break;

      default:
        warnings.push(`Unknown kernel capability descriptor ${hex(w, 8)}; skipped`);
    }
  }
  return caps;
}

function sameArray(a: ArrayLike<number>, b: ArrayLike<number>): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function parseNpdm(bytes: Uint8Array): ParseResult {
  const r = new Reader(bytes);
  const warnings: string[] = [];

  // ---- Meta ----
  if (r.ascii(0, 4) !== MAGIC_META) throw new Error("Not an NPDM file (missing META magic)");

  const signatureKeyGeneration = r.u32(0x4);
  const flags0 = r.u8(0xc);
  const flags1 = r.u8(0xd);
  const mainThreadPriority = r.u8(0xe);
  const mainThreadCoreNumber = r.u8(0xf);
  const systemResourceSize = r.u32(0x14);
  const version = r.u32(0x18);
  const mainThreadStackSize = r.u32(0x1c);
  const name = r.cstring(0x20, 0x10);
  const productCode = r.slice(0x30, 0x10);
  const aciHdr = section(r, 0x70);
  const acidHdr = section(r, 0x78);

  const addressSpaceType = (flags0 >>> 1) & 7;
  if (addressSpaceType > 3) {
    warnings.push(`address_space_type ${addressSpaceType} does not fit the JSON's 2-bit field`);
  }
  if (flags1 !== 0) warnings.push(`Meta Flags1 (${hex(flags1, 2)}) is not representable in the JSON`);
  if (signatureKeyGeneration > 0xff) {
    warnings.push(`signature_key_generation ${signatureKeyGeneration} is truncated to a u8 in the JSON`);
  }
  if (productCode.some((b) => b !== 0)) warnings.push("Non-empty ProductCode is not representable in the JSON");

  // ---- ACID ----
  const acid = acidHdr.offset;
  if (r.ascii(acid + 0x200, 4) !== MAGIC_ACID) throw new Error("Missing ACID magic");
  const acidFlags = r.u32(acid + 0x20c);
  const programIdMin = r.u64(acid + 0x210);
  const programIdMax = r.u64(acid + 0x218);
  const acidFac = section(r, acid + 0x220);
  const acidSac = section(r, acid + 0x228);
  const acidKc = section(r, acid + 0x230);

  const memoryRegion = (acidFlags >>> 2) & 0xf;
  if (memoryRegion > 3) warnings.push(`ACID memory region ${memoryRegion} does not fit the JSON's 2-bit field`);
  const lostAcidFlags = [
    [1, "UnqualifiedApproval"],
    [6, "bit 6"],
    [7, "LoadBrowserCoreDll"],
  ].filter(([bit]) => (acidFlags >>> (bit as number)) & 1).map(([, label]) => label);
  if (acidFlags >>> 8) lostAcidFlags.push(`bits 8-31 (${hex(acidFlags >>> 8, 6)})`);
  if (lostAcidFlags.length) {
    warnings.push(`ACID flags not representable in the JSON: ${lostAcidFlags.join(", ")}`);
  }

  // ---- ACI0 ----
  const aci = aciHdr.offset;
  if (r.ascii(aci, 4) !== MAGIC_ACI0) throw new Error("Missing ACI0 magic");
  const programId = r.u64(aci + 0x10);
  const aciFah = section(r, aci + 0x20);
  const aciSac = section(r, aci + 0x28);
  const aciKc = section(r, aci + 0x30);

  // ACI filesystem access header
  const fah = aci + aciFah.offset;
  const permissions = r.u64(fah + 0x4);
  const coiInfo = section(r, fah + 0xc);
  const sdoiInfo = section(r, fah + 0x14);

  const filesystemAccess: FilesystemAccess = { permissions: hex(permissions, 16) };

  if (coiInfo.size > 0) {
    const base = fah + coiInfo.offset;
    const count = r.u32(base);
    filesystemAccess.content_owner_ids = [];
    for (let i = 0; i < count; i++) filesystemAccess.content_owner_ids.push(hex(r.u64(base + 4 + i * 8), 16));
  }

  if (sdoiInfo.size > 0) {
    const base = fah + sdoiInfo.offset;
    const count = r.u32(base);
    const accessBase = base + 4;
    const idBase = accessBase + ((count + 3) & ~3);
    filesystemAccess.save_data_owner_ids = [];
    for (let i = 0; i < count; i++) {
      filesystemAccess.save_data_owner_ids.push({
        accessibility: r.u8(accessBase + i),
        id: hex(r.u64(idBase + i * 8), 16),
      });
    }
  }

  // ACID filesystem access control (only its permissions survive in the JSON)
  const fac = acid + acidFac.offset;
  const acidPermissions = r.u64(fac + 0x4);
  if (acidPermissions !== permissions) {
    warnings.push(
      `ACID FS permissions ${hex(acidPermissions, 16)} differ from ACI ${hex(permissions, 16)}; the JSON has one value for both`,
    );
  }
  const acidCoiCount = r.u8(fac + 0x1);
  const acidSdoiCount = r.u8(fac + 0x2);
  const acidRanges = [r.u64(fac + 0xc), r.u64(fac + 0x14), r.u64(fac + 0x1c), r.u64(fac + 0x24)];
  if (acidCoiCount || acidSdoiCount || acidRanges.some((v) => v !== 0n)) {
    warnings.push("ACID FS owner id ranges/lists are not representable in the JSON");
  }

  // ---- Services ----
  const services = parseSac(r, aci + aciSac.offset, aciSac.size);
  const acidServicesRaw = r.slice(acid + acidSac.offset, acidSac.size);
  const aciServicesRaw = r.slice(aci + aciSac.offset, aciSac.size);
  if (!sameArray(acidServicesRaw, aciServicesRaw)) {
    warnings.push("ACID service list differs from ACI; output uses ACI");
  }

  // ---- Kernel capabilities ----
  const aciWords = readWords(r, aci + aciKc.offset, aciKc.size);
  const acidWords = readWords(r, acid + acidKc.offset, acidKc.size);
  if (!sameArray(aciWords, acidWords)) {
    warnings.push(
      "ACID kernel capabilities differ from ACI; output uses ACI",
    );
  }
  const kernelCapabilities = parseKernelCapabilities(aciWords, warnings);

  // Key order follows the classic layout. Optional fields are only emitted
  // when they differ from their defaults.
  const flag = (bit: number) => ((flags0 >>> bit) & 1) !== 0;
  const json: NpdmJson = {
    name,
    program_id: hex(programId, 16),
    program_id_range_min: hex(programIdMin, 16),
    program_id_range_max: hex(programIdMax, 16),
    main_thread_stack_size: hex(mainThreadStackSize, 8),
    main_thread_priority: mainThreadPriority,
    default_cpu_id: mainThreadCoreNumber,
    version: hex(version, 8),
    ...(systemResourceSize !== 0 && { system_resource_size: hex(systemResourceSize, 8) }),
    ...(signatureKeyGeneration !== 0 && { signature_key_generation: signatureKeyGeneration }),
    is_retail: (acidFlags & 1) !== 0,
    pool_partition: memoryRegion,
    is_64_bit: flag(0),
    address_space_type: addressSpaceType,
    ...(flag(4) && { optimize_memory_allocation: true }),
    ...(flag(5) && { disable_device_address_space_merge: true }),
    ...(flag(6) && { enable_alias_region_extra_size: true }),
    ...(flag(7) && { prevent_code_reads: true }),
    filesystem_access: filesystemAccess,
    service_access: services.filter((s) => !s.isServer).map((s) => s.name),
    service_host: services.filter((s) => s.isServer).map((s) => s.name),
    kernel_capabilities: kernelCapabilities,
  };

  return { json, warnings };
}
