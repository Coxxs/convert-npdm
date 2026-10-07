// JSON -> NPDM

type Json = unknown;
type JsonObject = Record<string, Json>;

const META_SIZE = 0x80;
const ACID_HEADER_SIZE = 0x240;
const ACI0_HEADER_SIZE = 0x40;
const FAC_SIZE = 0x2c;
const FAH_SIZE = 0x1c;

export interface BuildResult {
  bytes: Uint8Array;
  warnings: string[];
}

const align16 = (n: number) => (n + 0xf) & ~0xf;

function isObject(v: Json): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Entries of an array, or [key, value] pairs of an object (cJSON_ArrayForEach semantics). */
function entries(v: Json): [string | undefined, Json][] {
  if (Array.isArray(v)) return v.map((x) => [undefined, x]);
  if (isObject(v)) return Object.entries(v);
  return [];
}

/** Parses a base-16 string like strtoull(..., 16): the 0x prefix is optional. */
function parseHex(v: Json, field: string, bits: 64 | 32 = 64): bigint {
  if (typeof v !== "string") throw new Error(`${field}: expected a hex string`);
  const m = /^\s*([+-]?)(?:0x)?([0-9a-f]+)/i.exec(v);
  if (!m) throw new Error(`${field}: "${v}" is not a base-16 string`);
  let value = BigInt("0x" + m[2]);
  if (m[1] === "-") value = (1n << 64n) - value; // strtoull negates modulo 2^64
  if (value >> BigInt(bits)) throw new Error(`${field}: "${v}" does not fit in ${bits} bits`);
  return value;
}

function num(obj: JsonObject, key: string, path: string): number {
  const v = obj[key];
  if (typeof v !== "number") throw new Error(`${path}${key}: expected a number`);
  return Math.trunc(v);
}

function bool(obj: JsonObject, key: string, path: string): boolean {
  const v = obj[key];
  if (typeof v !== "boolean") throw new Error(`${path}${key}: expected true or false`);
  return v;
}

function optBool(obj: JsonObject, key: string, path: string): boolean {
  return obj[key] === undefined ? false : bool(obj, key, path);
}

function hexField(obj: JsonObject, keys: string[], path: string, bits: 64 | 32 = 64): bigint {
  for (const key of keys) {
    if (obj[key] !== undefined) return parseHex(obj[key], path + key, bits);
  }
  throw new Error(`${path}${keys.join(" or ")}: field not present`);
}

function optHexField(obj: JsonObject, keys: string[], path: string, bits: 64 | 32 = 64): bigint {
  for (const key of keys) {
    if (obj[key] !== undefined) return parseHex(obj[key], path + key, bits);
  }
  return 0n;
}

function checkRange(value: number, max: number, field: string): number {
  if (value < 0 || value > max) throw new Error(`${field}: ${value} is out of range [0, ${max}]`);
  return value;
}

function encodeServices(json: JsonObject, warnings: string[]): Uint8Array {
  const out: number[] = [];
  const add = (name: string, isHost: boolean, field: string) => {
    const bytes = new TextEncoder().encode(name);
    if (bytes.length < 1 || bytes.length > 8) {
      throw new Error(`${field}: service name "${name}" must be 1-8 bytes long`);
    }
    out.push((bytes.length - 1) | (isHost ? 0x80 : 0), ...bytes);
  };

  const hosts = json.service_host;
  if (hosts !== undefined && !Array.isArray(hosts)) throw new Error("service_host: expected an array");
  for (const host of hosts ?? []) {
    if (typeof host !== "string") throw new Error("service_host: expected an array of strings");
    add(host, true, "service_host");
  }

  const access = json.service_access;
  if (access !== undefined && !Array.isArray(access) && !isObject(access)) {
    throw new Error("service_access: expected an array");
  }
  if (isObject(access)) {
    warnings.push("service_access uses the deprecated { name: is_host } object format");
    for (const [name, isHost] of Object.entries(access)) {
      if (typeof isHost !== "boolean") throw new Error(`service_access.${name}: expected true or false`);
      add(name, isHost, "service_access");
    }
  } else {
    for (const name of access ?? []) {
      if (typeof name !== "string") throw new Error("service_access: expected an array of strings");
      add(name, false, "service_access");
    }
  }
  return Uint8Array.from(out);
}

function encodeKernelCapabilities(json: JsonObject, warnings: string[]): number[] {
  const capabilities = json.kernel_capabilities;
  if (!Array.isArray(capabilities) && !isObject(capabilities)) {
    throw new Error("kernel_capabilities: expected an array");
  }
  const legacy = isObject(capabilities);
  if (legacy) warnings.push("kernel_capabilities uses the deprecated object format");

  const caps: number[] = [];
  entries(capabilities).forEach(([key, entry], i) => {
    let type: string;
    let value: Json;
    let path: string;
    if (legacy) {
      type = key!;
      value = entry;
      path = `kernel_capabilities.${type}`;
    } else {
      if (!isObject(entry) || typeof entry.type !== "string") {
        throw new Error(`kernel_capabilities[${i}]: expected { "type": string, "value": ... }`);
      }
      type = entry.type;
      value = entry.value;
      path = `kernel_capabilities[${i}] (${type})`;
    }

    switch (type) {
      case "kernel_flags": {
        if (!isObject(value)) throw new Error(`${path}: value must be an object`);
        const p = `${path}.`;
        const a = num(value, "highest_thread_priority", p) & 0xff;
        const b = num(value, "lowest_thread_priority", p) & 0xff;
        const highestCpu = num(value, "highest_cpu_id", p) & 0xff;
        const lowestCpu = num(value, "lowest_cpu_id", p) & 0xff;
        // The two priorities are sorted, so either order works.
        const hiPrio = Math.min(a, b) & 0x3f;
        const loPrio = Math.max(a, b) & 0x3f;
        const desc = (highestCpu << 24) | (lowestCpu << 16) | (hiPrio << 10) | (loPrio << 4);
        caps.push((desc | 0x7) >>> 0);
        break;
      }

      case "syscalls": {
        if (!isObject(value)) throw new Error(`${path}: value must be an object`);
        const masks = new Array<number>(8).fill(0);
        for (const [name, v] of Object.entries(value)) {
          const id = typeof v === "number" ? Math.trunc(v) : Number(parseHex(v, `${path}.${name}`));
          if (id < 0 || id >= 0xc0) throw new Error(`${path}.${name}: syscall id must be in [0, 0xBF]`);
          masks[Math.floor(id / 24)]! |= 1 << id % 24;
        }
        masks.forEach((mask, index) => {
          if (mask) caps.push((((index << 24) | mask) << 5 | 0xf) >>> 0);
        });
        break;
      }

      case "map": {
        if (!isObject(value)) throw new Error(`${path}: value must be an object`);
        const p = `${path}.`;
        const address = hexField(value, ["address"], p);
        const size = hexField(value, ["size"], p);
        const isRo = bool(value, "is_ro", p);
        const isIo = bool(value, "is_io", p);
        const first = Number((address >> 12n) & 0xffffffn) | (isRo ? 1 << 24 : 0);
        const second =
          Number((size >> 12n) & 0xfffffn) | (Number((address >> 36n) & 0xfn) << 20) | (isIo ? 0 : 1 << 24);
        caps.push(((first << 7) | 0x3f) >>> 0, ((second << 7) | 0x3f) >>> 0);
        break;
      }

      case "map_page": {
        const address = parseHex(value, path);
        caps.push(((Number((address >> 12n) & 0xffffffn) << 8) | 0x7f) >>> 0);
        break;
      }

      case "map_region": {
        if (!Array.isArray(value)) throw new Error(`${path}: value must be an array`);
        if (value.length > 3) throw new Error(`${path}: at most 3 region descriptors are allowed`);
        let desc = 0x3ff;
        value.forEach((region, j) => {
          if (!isObject(region)) throw new Error(`${path}[${j}]: region descriptor must be an object`);
          const p = `${path}[${j}].`;
          const type = num(region, "region_type", p) & 0x3f;
          const ro = bool(region, "is_ro", p) ? 0x40 : 0;
          desc |= (type | ro) << (11 + 7 * j);
        });
        caps.push(desc >>> 0);
        break;
      }

      case "irq_pair": {
        if (!Array.isArray(value) || value.length !== 2) throw new Error(`${path}: value must be a 2-element array`);
        let desc = 0;
        value.forEach((irq, j) => {
          if (irq === null) desc |= 0x3ff << (10 * j);
          else if (typeof irq === "number") desc |= (Math.trunc(irq) & 0x3ff) << (10 * j);
          else throw new Error(`${path}[${j}]: IRQ must be a number or null`);
        });
        caps.push(((desc << 12) | 0x7ff) >>> 0);
        break;
      }

      case "application_type": {
        if (typeof value !== "number") throw new Error(`${path}: value must be a number`);
        caps.push((((Math.trunc(value) & 7) << 14) | 0x1fff) >>> 0);
        break;
      }

      case "min_kernel_version": {
        const version = typeof value === "number" ? Math.trunc(value) : Number(parseHex(value, path) & 0xffffn);
        caps.push((((version & 0xffff) << 15) | 0x3fff) >>> 0);
        break;
      }

      case "handle_table_size": {
        if (typeof value !== "number") throw new Error(`${path}: value must be a number`);
        caps.push((((Math.trunc(value) & 0xffff) << 16) | 0x7fff) >>> 0);
        break;
      }

      case "debug_flags": {
        if (!isObject(value)) throw new Error(`${path}: value must be an object`);
        const p = `${path}.`;
        const allow = optBool(value, "allow_debug", p);
        const force = optBool(value, "force_debug", p);
        const forceProd = optBool(value, "force_debug_prod", p);
        if (Number(allow) + Number(force) + Number(forceProd) > 1) {
          throw new Error(`${path}: only one of allow_debug, force_debug, force_debug_prod may be set`);
        }
        const desc = (allow ? 1 : 0) | (forceProd ? 2 : 0) | (force ? 4 : 0);
        caps.push(((desc << 17) | 0xffff) >>> 0);
        break;
      }

      default:
        // Unknown capability types are skipped.
        warnings.push(`${path}: unknown capability type ignored`);
    }
  });
  return caps;
}

export function buildNpdm(input: Json): BuildResult {
  if (!isObject(input)) throw new Error("Top-level JSON value must be an object");
  const json = input;
  const warnings: string[] = [];

  // ---- Meta fields ----
  if (typeof json.name !== "string") throw new Error("name: field not present");
  const name = new TextEncoder().encode(json.name).subarray(0, 0xf);

  const stackSize = Number(hexField(json, ["main_thread_stack_size"], "", 32));
  const priority = num(json, "main_thread_priority", "") & 0xff;
  const cpuId = num(json, "default_cpu_id", "") & 0xff;
  const systemResourceSize = Number(optHexField(json, ["system_resource_size"], "", 32));
  const version = Number(optHexField(json, ["version", "process_category"], "", 32));
  const signatureKeyGeneration =
    json.signature_key_generation === undefined ? 0 : num(json, "signature_key_generation", "") & 0xff;

  const addressSpaceType = checkRange(num(json, "address_space_type", ""), 7, "address_space_type");
  const flags0 =
    (bool(json, "is_64_bit", "") ? 1 : 0) |
    (addressSpaceType << 1) |
    (optBool(json, "optimize_memory_allocation", "") ? 1 << 4 : 0) |
    (optBool(json, "disable_device_address_space_merge", "") ? 1 << 5 : 0) |
    (optBool(json, "enable_alias_region_extra_size", "") ? 1 << 6 : 0) |
    (optBool(json, "prevent_code_reads", "") ? 1 << 7 : 0);

  // ---- ACID fields ----
  const poolPartition = checkRange(num(json, "pool_partition", ""), 0xf, "pool_partition");
  const acidFlags = (bool(json, "is_retail", "") ? 1 : 0) | (poolPartition << 2);
  const programIdMin = hexField(json, ["program_id_range_min", "title_id_range_min"], "");
  const programIdMax = hexField(json, ["program_id_range_max", "title_id_range_max"], "");

  // ---- ACI0 fields ----
  const programId = hexField(json, ["program_id", "title_id"], "");

  const fs = json.filesystem_access;
  if (!isObject(fs)) throw new Error("filesystem_access: expected an object");
  const permissions = hexField(fs, ["permissions"], "filesystem_access.");

  const contentOwnerIds: bigint[] = [];
  if (Array.isArray(fs.content_owner_ids)) {
    fs.content_owner_ids.forEach((id, i) =>
      contentOwnerIds.push(parseHex(id, `filesystem_access.content_owner_ids[${i}]`)),
    );
  }

  const saveDataOwners: { accessibility: number; id: bigint }[] = [];
  if (Array.isArray(fs.save_data_owner_ids)) {
    fs.save_data_owner_ids.forEach((entry, i) => {
      const p = `filesystem_access.save_data_owner_ids[${i}].`;
      if (!isObject(entry)) throw new Error(`${p.slice(0, -1)}: expected an object`);
      saveDataOwners.push({ accessibility: num(entry, "accessibility", p) & 0xff, id: hexField(entry, ["id"], p) });
    });
  }

  const sac = encodeServices(json, warnings);
  const kc = encodeKernelCapabilities(json, warnings);

  // ---- Layout ----
  const coiSize = contentOwnerIds.length ? 4 + 8 * contentOwnerIds.length : 0;
  const sdoiCount = saveDataOwners.length;
  const sdoiSize = sdoiCount ? 4 + ((sdoiCount + 3) & ~3) + 8 * sdoiCount : 0;
  const fahSize = FAH_SIZE + coiSize + sdoiSize;
  const kcSize = kc.length * 4;

  const acidFacOffset = ACID_HEADER_SIZE;
  const acidSacOffset = align16(acidFacOffset + FAC_SIZE);
  const acidKcOffset = align16(acidSacOffset + sac.length);
  const acidSize = acidKcOffset + kcSize;

  const aciFahOffset = ACI0_HEADER_SIZE;
  const aciSacOffset = align16(aciFahOffset + fahSize);
  const aciKcOffset = align16(aciSacOffset + sac.length);
  const aciSize = aciKcOffset + kcSize;

  const acid = META_SIZE;
  const aci = align16(acid + acidSize);
  const out = new Uint8Array(aci + aciSize);
  const view = new DataView(out.buffer);
  const u8 = (o: number, v: number) => view.setUint8(o, v);
  const u32 = (o: number, v: number) => view.setUint32(o, v, true);
  const u64 = (o: number, v: bigint) => view.setBigUint64(o, v, true);
  const ascii = (o: number, s: string) => out.set(new TextEncoder().encode(s), o);
  const writeCaps = (o: number) => kc.forEach((w, i) => u32(o + i * 4, w));

  // Meta
  ascii(0x0, "META");
  u32(0x4, signatureKeyGeneration);
  u8(0xc, flags0);
  u8(0xe, priority);
  u8(0xf, cpuId);
  u32(0x14, systemResourceSize);
  u32(0x18, version);
  u32(0x1c, stackSize);
  out.set(name, 0x20);
  u32(0x70, aci);
  u32(0x74, aciSize);
  u32(0x78, acid);
  u32(0x7c, acidSize);

  // ACID (signature and modulus at 0x0-0x1FF stay zero)
  ascii(acid + 0x200, "ACID");
  u32(acid + 0x204, acidSize - 0x100);
  u32(acid + 0x20c, acidFlags);
  u64(acid + 0x210, programIdMin);
  u64(acid + 0x218, programIdMax);
  u32(acid + 0x220, acidFacOffset);
  u32(acid + 0x224, FAC_SIZE);
  u32(acid + 0x228, acidSacOffset);
  u32(acid + 0x22c, sac.length);
  u32(acid + 0x230, acidKcOffset);
  u32(acid + 0x234, kcSize);
  u8(acid + acidFacOffset, 1); // FAC version; owner id counts/ranges stay zero
  u64(acid + acidFacOffset + 0x4, permissions);
  out.set(sac, acid + acidSacOffset);
  writeCaps(acid + acidKcOffset);

  // ACI0
  ascii(aci, "ACI0");
  u64(aci + 0x10, programId);
  u32(aci + 0x20, aciFahOffset);
  u32(aci + 0x24, fahSize);
  u32(aci + 0x28, aciSacOffset);
  u32(aci + 0x2c, sac.length);
  u32(aci + 0x30, aciKcOffset);
  u32(aci + 0x34, kcSize);

  const fah = aci + aciFahOffset;
  u32(fah, 1); // FAH version
  u64(fah + 0x4, permissions);
  u32(fah + 0xc, FAH_SIZE);
  u32(fah + 0x10, coiSize);
  u32(fah + 0x14, FAH_SIZE + coiSize);
  u32(fah + 0x18, sdoiSize);
  if (coiSize) {
    const base = fah + FAH_SIZE;
    u32(base, contentOwnerIds.length);
    contentOwnerIds.forEach((id, i) => u64(base + 4 + i * 8, id));
  }
  if (sdoiSize) {
    const base = fah + FAH_SIZE + coiSize;
    u32(base, sdoiCount);
    const idBase = base + 4 + ((sdoiCount + 3) & ~3);
    saveDataOwners.forEach((o, i) => {
      u8(base + 4 + i, o.accessibility);
      u64(idBase + i * 8, o.id);
    });
  }
  out.set(sac, aci + aciSacOffset);
  writeCaps(aci + aciKcOffset);

  return { bytes: out, warnings };
}
