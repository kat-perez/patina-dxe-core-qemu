//! DXE Core Sample X64 Binary for QEMU Q35
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
#![cfg(all(target_os = "uefi", feature = "x64"))]
#![no_std]
#![no_main]

use core::{ffi::c_void, panic::PanicInfo};
use patina::{log::Format, serial::uart::Uart16550};
use patina::uefi_protocol::device_path::{DevicePathBuf, nodes::{Acpi, Pci, NvmExpress, HardDrive, FilePath}};
use patina_adv_logger::{component::AdvancedLoggerComponent, logger::AdvancedLogger};
use patina_boot::{component::BootOrchestrator, config::BootOptions};
use patina_dxe_core::*;
use patina_ffs_extractors::CompositeSectionExtractor;
use patina_stacktrace::StackTrace;
use qemu_resources::q35::component::service as q35_services;
extern crate alloc;
use alloc::vec;
use qemu_resources::q35::timer;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("{}", info);

    if let Err(err) = unsafe { StackTrace::dump() } {
        log::error!("StackTrace: {}", err);
    }

    if patina_debugger::enabled() {
        patina_debugger::breakpoint();
    }

    loop {}
}

/// Port address of the ACPI PM Timer.
/// Obtained from ACPI FADT `X_PM_TIMER_BLOCK`. It is always at 0x608 on Q35.
const PM_TIMER_PORT: u16 = 0x608;

static LOGGER: AdvancedLogger<Uart16550> = AdvancedLogger::new(
    Format::Standard,
    &[
        ("goblin", log::LevelFilter::Off),
        ("gcd_measure", log::LevelFilter::Off),
        ("allocations", log::LevelFilter::Off),
        ("efi_memory_map", log::LevelFilter::Off),
        ("mm_comm", log::LevelFilter::Off),
        ("sw_mmi", log::LevelFilter::Off),
        ("patina_performance", log::LevelFilter::Off),
    ],
    log::LevelFilter::Info,
    Uart16550::Io { base: 0x402 },
);

#[cfg(feature = "enable_debugger")]
const _ENABLE_DEBUGGER: bool = true;
#[cfg(not(feature = "enable_debugger"))]
const _ENABLE_DEBUGGER: bool = false;

#[cfg(feature = "build_debugger")]
static DEBUGGER: patina_debugger::PatinaDebugger<Uart16550> =
    patina_debugger::PatinaDebugger::new(Uart16550::Io { base: 0x3F8 })
        .with_force_enable(_ENABLE_DEBUGGER)
        .with_log_policy(patina_debugger::DebuggerLoggingPolicy::FullLogging);

struct Q35;

// Default `MemoryInfo` implementation is sufficient for Q35.
impl MemoryInfo for Q35 {}

// Q35 should use TSC frequency calibrated from ACPI PM Timer.
impl CpuInfo for Q35 {
    fn perf_timer_frequency() -> Option<u64> {
        // SAFETY: Reading from the PM Timer I/O port is safe as long as the port is valid.
        // On Q35, the PM Timer is always available at the specified port address.
        Some(unsafe { timer::calibrate_tsc_frequency(PM_TIMER_PORT) })
    }
}

/// Create a device path for primary boot target (NVMe).
///
/// On QEMU Q35, the NVMe controller is typically at PCI address 0:4.0.
/// The complete device path to the EFI boot application is:
///   Acpi(0x0A0341D0,0)/Pci(0x4,0x0)/NvmExpress(1,0)/HD(1,GPT,...)/\EFI\Boot\BOOTX64.efi
fn create_primary_boot_path() -> DevicePathBuf {
    // QEMU Q35 uses HID 0x0A0341D0 for the PCI root (not standard PNP0A03)
    let mut path = DevicePathBuf::from_device_path_node_iter(core::iter::once(Acpi { hid: 0x0A0341D0, uid: 0 }));

    // PCI device node for NVMe controller at slot 4
    let pci_path = DevicePathBuf::from_device_path_node_iter(core::iter::once(Pci { function: 0, device: 4 }));
    path.append_device_path(&pci_path);

    // NVMe namespace node (namespace 1, EUI64 = 0)
    let nvme_path = DevicePathBuf::from_device_path_node_iter(core::iter::once(NvmExpress::new(1, 0)));
    path.append_device_path(&nvme_path);

    // Hard drive partition node (GPT partition 1)
    // Partition GUID: 1BBEE91E-5177-4248-A08F-2F6000BFE3B6 (in UEFI little-endian format)
    let partition_guid: [u8; 16] = [
        0x1E, 0xE9, 0xBE, 0x1B, 0x77, 0x51, 0x48, 0x42,
        0xA0, 0x8F, 0x2F, 0x60, 0x00, 0xBF, 0xE3, 0xB6,
    ];
    let hd_path = DevicePathBuf::from_device_path_node_iter(core::iter::once(
        HardDrive::new_gpt(1, 34, 131005, partition_guid)
    ));
    path.append_device_path(&hd_path);

    // File path to EFI boot file
    let file_path = DevicePathBuf::from_device_path_node_iter(core::iter::once(FilePath::new("\\EFI\\Boot\\BOOTX64.efi")));
    path.append_device_path(&file_path);

    log::info!("Primary boot path: Acpi(0x0A0341D0,0)/Pci(0,4)/NvmExpress(1,0)/HD(1,GPT,...)/\\EFI\\Boot\\BOOTX64.efi");
    path
}

/// Create a device path for secondary/fallback boot target.
///
/// This points to a different PCI device as a fallback boot option.
/// On Q35, this could be a secondary virtio device or AHCI controller.
fn create_secondary_boot_path() -> DevicePathBuf {
    let mut path = DevicePathBuf::from_device_path_node_iter(core::iter::once(Acpi::new_pci_root(0)));
    let pci_path = DevicePathBuf::from_device_path_node_iter(core::iter::once(Pci { function: 0, device: 31 }));
    path.append_device_path(&pci_path);
    path
}

impl ComponentInfo for Q35 {
    fn configs(mut add: Add<Config>) {
        add.config(patina_mm::config::MmCommunicationConfiguration {
            acpi_base: patina_mm::config::AcpiBase::Mmio(0x0), // Actual ACPI base address will be set during boot
            cmd_port: patina_mm::config::MmiPort::Smi(0xB2),
            data_port: patina_mm::config::MmiPort::Smi(0xB3),
            enable_comm_buffer_updates: false,
            updatable_buffer_id: None,
            comm_buffers: vec![],
        });
        add.config(patina_performance::config::PerfConfig {
            enable_component: true,
            enabled_measurements: {
                patina::performance::Measurement::DriverBindingStart         // Adds driver binding start measurements.
               | patina::performance::Measurement::DriverBindingStop        // Adds driver binding stop measurements.
               | patina::performance::Measurement::DriverBindingSupport     // Adds driver binding support measurements.
               | patina::performance::Measurement::LoadImage                // Adds load image measurements.
               | patina::performance::Measurement::StartImage // Adds start image measurements.
            },
        });
        // Boot orchestration configuration
        add.config(
            BootOptions::new(create_primary_boot_path())
                .with_secondary(create_secondary_boot_path())
                .with_hotkey(0x86) // F12 scancode
                .with_failure_handler(|| {
                    log::error!("===========================================");
                    log::error!("BOOT FAILED: All boot options exhausted");
                    log::error!("===========================================");
                })
        );
    }

    fn components(mut add: Add<Component>) {
        add.component(AdvancedLoggerComponent::<Uart16550>::new(&LOGGER));
        add.component(q35_services::mm_config_provider::MmConfigurationProvider);
        add.component(q35_services::mm_control::QemuQ35PlatformMmControl::new());
        add.component(patina_mm::component::sw_mmi_manager::SwMmiManager::new());
        add.component(patina_mm::component::communicator::MmCommunicator::new());
        add.component(q35_services::mm_test::QemuQ35MmTest::new());
        add.component(patina_performance::component::performance_config_provider::PerformanceConfigurationProvider);
        add.component(patina_performance::component::performance::Performance);
        // Boot orchestration component
        add.component(BootOrchestrator);
    }
}

impl PlatformInfo for Q35 {
    type CpuInfo = Self;
    type MemoryInfo = Self;
    type ComponentInfo = Self;
    type Extractor = CompositeSectionExtractor;
}

static CORE: Core<Q35> = Core::new(CompositeSectionExtractor::new());

#[cfg_attr(target_os = "uefi", unsafe(export_name = "efi_main"))]
pub extern "efiapi" fn _start(physical_hob_list: *const c_void) -> ! {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Trace)).unwrap();
    // SAFETY: The physical_hob_list pointer is considered valid at this point as it's provided by the core
    // to the entry point.
    unsafe {
        LOGGER.init(physical_hob_list).unwrap();
    }

    #[cfg(feature = "build_debugger")]
    patina_debugger::set_debugger(&DEBUGGER);

    log::info!("DXE Core Platform Binary v{}", env!("CARGO_PKG_VERSION"));
    CORE.entry_point(physical_hob_list)
}
