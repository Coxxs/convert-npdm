export interface SaveDataOwnerId {
  accessibility: number; // 1 = Read, 2 = Write, 3 = ReadWrite
  id: string;
}

export interface FilesystemAccess {
  permissions: string;
  content_owner_ids?: string[];
  save_data_owner_ids?: SaveDataOwnerId[];
}

export type KernelCapability =
  | {
      type: "kernel_flags";
      value: {
        highest_thread_priority: number;
        lowest_thread_priority: number;
        lowest_cpu_id: number;
        highest_cpu_id: number;
      };
    }
  | { type: "syscalls"; value: Record<string, string> }
  | { type: "map"; value: { address: string; size: string; is_ro: boolean; is_io: boolean } }
  | { type: "map_page"; value: string }
  | { type: "map_region"; value: { region_type: number; is_ro: boolean }[] }
  | { type: "irq_pair"; value: [number | null, number | null] }
  | { type: "application_type"; value: number }
  | { type: "min_kernel_version"; value: string }
  | { type: "handle_table_size"; value: number }
  | {
      type: "debug_flags";
      value: { allow_debug: boolean; force_debug: boolean; force_debug_prod?: boolean };
    };

export interface NpdmJson {
  name: string;
  program_id: string;
  program_id_range_min: string;
  program_id_range_max: string;
  main_thread_stack_size: string;
  main_thread_priority: number;
  default_cpu_id: number;
  version: string;
  system_resource_size?: string;
  signature_key_generation?: number;
  is_retail: boolean;
  pool_partition: number;
  is_64_bit: boolean;
  address_space_type: number;
  optimize_memory_allocation?: boolean;
  disable_device_address_space_merge?: boolean;
  enable_alias_region_extra_size?: boolean;
  prevent_code_reads?: boolean;
  filesystem_access: FilesystemAccess;
  service_access: string[];
  service_host: string[];
  kernel_capabilities: KernelCapability[];
}
