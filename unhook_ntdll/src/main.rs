use winapi::shared::minwindef::HMODULE;
use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use core::panic;
use std::fs::File;
use std::ptr::{self};
mod ired;
use memmap2::{MmapOptions};
use pelite::pe64::{Pe, PeFile};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION};




fn unhook() -> Result<(), Box<dyn std::error::Error>> {
    /* 
    1. Map a fresh copy of ntdll.dll from disk to process memory
    */ 
    let file = File::open("C:\\Windows\\System32\\ntdll.dll")?;
    let map = unsafe { MmapOptions::new().map(&file)? };

    /* 
    2. Find virtual address of the .text section of the hooked ntdll.dll
        1. Get ntdll.dll base address
        2. Module base address + module's .text section VirtualAddress
    */

    // 2.1. Get ntdll.dll base address
    let hmodule: HMODULE = unsafe { GetModuleHandleA("ntdll.dll\0".as_ptr() as *const i8) };
    if hmodule.is_null() {
        panic!("Failed to get ntdll.dll base address.");
    }

    // Parse the PE file
    let pe= PeFile::from_bytes(&map).map_err(|_| "Failed to parse ntdll.dll PE file.")?;

    // 2.2. Module base address + module's .text section VirtualAddress
    let text_section = pe
        .section_headers()
        .iter()
        .find(|header| header.name() == Ok(".text"))
        .ok_or(".text section not found in ntdll.dll.")?;

    let text_section_virtual_address = hmodule as usize + text_section.VirtualAddress as usize;
    
    /*
    3. Find virtual address of the .text section of the freshly mapped ntdll.dll
    */

    // Parse the PE file
    let pe_fresh = PeFile::from_bytes(&map).map_err(|_| "Failed to parse ntdll.dll PE file.")?;

    // Find .text section of the freshly mapped ntdll.dll
    let text_section_fresh = pe_fresh
        .section_headers()
        .iter()
        .find(|header| header.name() == Ok(".text"))
        .ok_or(".text section not found in the freshly mapped ntdll.dll.")?;

    //let text_section_fresh_virtual_address = text_section_fresh.VirtualAddress as usize;

    /*
    4. Get original memory protections of the hooked module's .text section
    */

    // Query memory information for the .text section of the originally loaded module
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let query_result = unsafe {
        VirtualQuery(
            text_section_virtual_address as *const winapi::ctypes::c_void,
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if query_result == 0 {
        return Err("Failed to query memory information for the .text section of the originally loaded module.".into());
    }

    let original_protection = mem_info.Protect;    

    /* 
    5. Copy .text section from the freshly mapped dll to the virtual address 
    (found in step 3) of the original (hooked) ntdll.dll - this is the meat 
    of the unhooking as all hooked bytes get overwritten with fresh ones 
    from the disk
    */

    // Change memory protection of the .text section of the original ntdll.dll to PAGE_EXECUTE_READWRITE
    let mut old_protection: u32 = 0;
    let protect_result = unsafe {
        VirtualProtect(
            text_section_virtual_address as *mut winapi::ctypes::c_void,
            text_section.SizeOfRawData as usize,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
    };

    if protect_result == 0 {
        return Err("Failed to change memory protection of the .text section of the original ntdll.dll.".into());
    }

    // Copy .text section from the freshly mapped dll to the virtual address of the original ntdll.dll
    let src = map[text_section_fresh.PointerToRawData as usize..].as_ptr();
    let dst = text_section_virtual_address as *mut u8;
    unsafe {
        ptr::copy_nonoverlapping(src, dst, text_section_fresh.SizeOfRawData as usize);
    }

    /* 
    6. Apply original memory protections to the freshly unhooked .text section 
    of the original ntdll.dll
    */

    // Restore the original memory protection of the .text section of the original ntdll.dll
    let protect_result = unsafe {
        VirtualProtect(
            text_section_virtual_address as *mut winapi::ctypes::c_void,
            text_section.SizeOfRawData as usize,
            original_protection,
            &mut old_protection,
        )
    };

    if protect_result == 0 {
        return Err("Failed to restore memory protection of the .text section of the original ntdll.dll.".into());
    } 

    println!("Donzo (?)");


    Ok(())
}

fn main() {
    println!("-------------------- HOOOKS B --------------------");
    ired::detect_hooks();
    println!("------------------------------------------------");

    println!("\n\n----------------- **UNHOOKING** -----------------");
    let _ = unhook();
    println!("------------------------------------------------");

    println!("\n\n-------------------- HOOOKS A --------------------");
    ired::detect_hooks();
    println!("------------------------------------------------");
}

