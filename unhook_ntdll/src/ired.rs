use std::ffi::CStr;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::minwindef::{HMODULE, PDWORD, PWORD};
use winapi::um::libloaderapi::{LoadLibraryA};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_EXPORT_DIRECTORY};
use winapi::um::psapi::{GetMappedFileNameA};
use winapi::um::winnt::{PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS};

pub fn detect_hooks() {
    // Get ntdll base address
    let library_base: HMODULE = unsafe { LoadLibraryA("ntdll\0".as_ptr() as *const i8) };

    // Get DOS header and NT headers
    let dos_header: PIMAGE_DOS_HEADER = unsafe { std::mem::transmute(library_base) };
    let nt_headers_offset: usize = (unsafe { *dos_header }).e_lfanew as usize; // AQUI CAMBIO A PUNTERO
    let nt_headers: PIMAGE_NT_HEADERS = unsafe { std::mem::transmute((library_base as usize + nt_headers_offset) as *const u8) };

    // Locate export address table
    let export_directory_rva: DWORD_PTR = unsafe { (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress.try_into().unwrap() };
    let export_directory: PIMAGE_EXPORT_DIRECTORY = unsafe { std::mem::transmute((library_base as usize + export_directory_rva as usize) as *const u8) };

    // Offsets to list of exported functions and their names
    let addresses_of_functions_rva: PDWORD = unsafe { std::mem::transmute((library_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u8) };
    let addresses_of_names_rva: PDWORD = unsafe { std::mem::transmute((library_base as usize + (*export_directory).AddressOfNames as usize) as *const u8) };
    let address_of_name_ordinals_rva: PWORD = unsafe { std::mem::transmute((library_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u8) };

    // Iterate through exported functions of ntdll
    for i in 0..(unsafe { *export_directory }).NumberOfNames {
        let function_name_rva = unsafe { *addresses_of_names_rva.offset(i as isize) };
        let function_name_va = (library_base as usize + function_name_rva as usize) as *const u8;
        let function_name = unsafe { CStr::from_ptr(function_name_va as *const i8) };

        let function_address_rva = unsafe { *addresses_of_functions_rva.offset(*address_of_name_ordinals_rva.offset(i as isize) as isize) };
        let function_address = (library_base as usize + function_address_rva as usize) as *const u8;

        // Syscall stubs start with these bytes
        let syscall_prologue: [u8; 4] = [0x4c, 0x8b, 0xd1, 0xb8];

        // Only interested in Nt|Zw functions
        if function_name.to_bytes().starts_with(b"Nt") || function_name.to_bytes().starts_with(b"Zw") {
            // Check if the first 4 instructions of the exported function are the same as the sycall's prologue
            if unsafe { (*(function_address as *const u32)).to_le_bytes() } != syscall_prologue { 
                if unsafe { *(function_address as *const u8) } == 0xE9 {
                    let jump_target_relative = unsafe { *(function_address as *const i32) }; 
                    let jump_target = unsafe { function_address.add(5).add(jump_target_relative as usize) } as *const u8;
                    let mut module_name_buffer: [u8; 512] = [0; 512];
                    let _ = unsafe { GetMappedFileNameA(
                        GetCurrentProcess(),
                        jump_target as *mut c_void,
                        module_name_buffer.as_mut_ptr() as *mut i8,
                        512,
                    ) };
                    let module_name = unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(&module_name_buffer) };
                    println!("Hooked: {} : {:p} into module {}", function_name.to_string_lossy(), function_address, module_name.to_string_lossy());
                } else {
                    println!("Potentially hooked: {} : {:p}", function_name.to_string_lossy(), function_address);
                }
            }
        }
    }
}
