//! DXE Core Sample AARCH64 Binary for QEMU SBSA
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
#![cfg(all(target_os = "uefi", feature = "aarch64"))]
#![no_std]
#![no_main]

use core::{ffi::c_void, panic::PanicInfo};
use patina::{
    device_path::{node_defs::{FilePath, HardDrive}, paths::DevicePathBuf},
    log::Format,
    serial::uart::UartPl011,
};
use patina_adv_logger::{component::AdvancedLoggerComponent, logger::AdvancedLogger};
use patina_boot::{BootDispatcher, SimpleBootManager, config::BootConfig};
use patina_dxe_core::*;
use patina_ffs_extractors::CompositeSectionExtractor;
use patina_smbios;
use patina_stacktrace::StackTrace;
#[cfg(feature = "exit_on_patina_test_failure")]
use qemu_exit::QEMUExit;
use qemu_resources::sbsa::component::service as sbsa_services;
extern crate alloc;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("{}", info);

    if let Err(err) = unsafe { StackTrace::dump() } {
        log::error!("StackTrace: {}", err);
    }

    patina_debugger::breakpoint();

    loop {}
}

static LOGGER: AdvancedLogger<UartPl011> = AdvancedLogger::new(
    Format::Standard,
    &[
        ("goblin", log::LevelFilter::Off),
        ("gcd_measure", log::LevelFilter::Off),
        ("allocations", log::LevelFilter::Off),
        ("efi_memory_map", log::LevelFilter::Off),
    ],
    log::LevelFilter::Info,
    UartPl011::new(0x6000_0000),
);

#[cfg(feature = "enable_debugger")]
const _ENABLE_DEBUGGER: bool = true;
#[cfg(not(feature = "enable_debugger"))]
const _ENABLE_DEBUGGER: bool = false;

#[cfg(feature = "build_debugger")]
static DEBUGGER: patina_debugger::PatinaDebugger<UartPl011> =
    patina_debugger::PatinaDebugger::new(UartPl011::new(0x6000_0000)).with_force_enable(_ENABLE_DEBUGGER);

struct Sbsa;

// Default `MemoryInfo` implementation is sufficient for SBSA.
impl MemoryInfo for Sbsa {}

impl CpuInfo for Sbsa {
    fn gic_bases() -> GicBases {
        // SAFETY: gicd and gicr bases correctly point to the register spaces.
        // SAFETY: Access to these registers is exclusive to this struct instance.
        unsafe { GicBases::new(0x40060000, 0x40080000) }
    }
}

/// Create a partial device path for the EFI System Partition boot target.
///
/// Uses a short-form (partial) device path with just the GPT partition and file path.
/// The boot helpers expand this to the full path at runtime via `LocateDevicePath`.
fn create_boot_path() -> DevicePathBuf {
    // EFI System Partition: GUID 48EC37EC-89AF-4BC1-BC56-CD714048A6B5
    // Start LBA 128, size 409600 sectors, partition 1
    let partition_guid: [u8; 16] = [
        0xEC, 0x37, 0xEC, 0x48, 0xAF, 0x89, 0xC1, 0x4B,
        0xBC, 0x56, 0xCD, 0x71, 0x40, 0x48, 0xA6, 0xB5,
    ];
    let mut path = DevicePathBuf::from_device_path_node_iter(
        core::iter::once(HardDrive::new_gpt(1, 128, 409600, partition_guid)),
    );
    let file_path = DevicePathBuf::from_device_path_node_iter(
        core::iter::once(FilePath::new("\\EFI\\Boot\\BOOTAA64.efi")),
    );
    path.append_device_path(&file_path);

    log::info!(
        "SBSA boot path (partial): HD(1,GPT,48EC37EC-89AF-4BC1-BC56-CD714048A6B5)/\\EFI\\Boot\\BOOTAA64.efi"
    );
    path
}

impl ComponentInfo for Sbsa {
    fn components(mut add: Add<Component>) {
        add.component(AdvancedLoggerComponent::<UartPl011>::new(&LOGGER));
        add.component(patina_smbios::component::SmbiosProvider::new(3, 9));
        add.component(sbsa_services::smbios_platform::SbsaSmbiosPlatform::new());
        add.component(patina::test::TestRunner::default().with_callback(|test_name, err_msg| {
            log::error!("Test {} failed: {}", test_name, err_msg);
            #[cfg(feature = "exit_on_patina_test_failure")]
            qemu_exit::AArch64::new().exit_failure();
        }));
        add.component(patina_performance::component::performance_config_provider::PerformanceConfigurationProvider);
        add.component(patina_performance::component::performance::Performance);
        add.component(patina_acpi::component::AcpiComponent::default());
        // Boot orchestration with connect-dispatch interleaving
        add.component(BootDispatcher::new(
            SimpleBootManager::new(
                BootConfig::new(create_boot_path())
                    .with_failure_handler(|| {
                        log::error!("Boot failed: all boot options exhausted");
                    }),
            ),
        ));
    }

    fn configs(mut add: Add<Config>) {
        add.config(patina_performance::config::PerfConfig {
            enable_component: true,
            enabled_measurements: {
                patina::performance::Measurement::DriverBindingStart         // Adds driver binding start measurements.
               | patina::performance::Measurement::DriverBindingStop        // Adds driver binding stop measurements.
               | patina::performance::Measurement::LoadImage                // Adds load image measurements.
               | patina::performance::Measurement::StartImage // Adds start image measurements.
            },
        })
    }
}

impl PlatformInfo for Sbsa {
    type CpuInfo = Self;
    type MemoryInfo = Self;
    type ComponentInfo = Self;
    type Extractor = CompositeSectionExtractor;
}

static CORE: Core<Sbsa> = Core::new(CompositeSectionExtractor::new());

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
