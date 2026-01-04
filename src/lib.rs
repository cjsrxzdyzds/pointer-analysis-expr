use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

static LOG_LOCK: Mutex<()> = Mutex::new(());

use std::sync::atomic::{AtomicBool, Ordering};

// Global re-entrancy guard (lossy but safe)
static IN_CHECKER: AtomicBool = AtomicBool::new(false);

pub fn init() {
    println!("SVF Runtime Initialized");
    // Force linkage of __svf_check_alias
    // We use a volatile read or similar to prevent optimization, 
    // but just calling it is enough for the linker.
    // We pass arguments that won't match anything meaningful or use 0 ID (assuming 0 is "system" or unused)
    unsafe { 
        // We need to allow this call? No, it's unsafe but we are in pub fn init()
        // Wait, __svf_check_alias is unsafe.
        // We rely on the guard to return early if we are not "really" doing checking? 
        // No, if we call it here, it WILL execute.
        // But since p=0, q=0, it will say Alias.
        // That's fine for init.
        // However, we don't want to pollute the log?
        // Let's rely on black_box or similar if available, or just take address?
        let ptr = __svf_check_alias as *const ();
        println!("__svf_check_alias at {:?}", ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn __svf_check_alias(p: usize, q: usize, id: u32) {
    // Panic to verify execution
    // panic!("__svf_check_alias called!");
    // (Panic commented out to avoid crashing if it DOES work, relying on log file now)

    // Try to acquire the guard. If swap returns true, it was already locked (recursive or concurrent).
    if IN_CHECKER.swap(true, Ordering::Acquire) {
        return;
    }

    // No need to set it, swap did it.
    // Wrap in cleanup ensures we release it (though here we just release at end)
    
    // Treat inputs as addresses (integers).
    // This signature (usize, usize, u32) matches the registers used for (ptr, ptr, u32) on x86_64.
    
    let is_alias = p == q;
    
    // We can output logged addresses in hex for debug if needed.
    // Use try-blocks or careful logic to avoid panic-during-lock if possible, 
    // but here we just need to ensure we don't recurse.
    
    // Note: format! itself might allocate, so we must be inside the guard before calling it.
    let output = format!("ID:{} RES:{} (0x{:x} vs 0x{:x})\n", 
        id, 
        if is_alias { 1 } else { 0 },
        p, q
    );

    {
        let _guard = LOG_LOCK.lock().unwrap();
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/svf_runtime_results.txt") 
        {
            let _ = file.write_all(output.as_bytes());
        }
    }

    // Reset the guard
    IN_CHECKER.store(false, Ordering::Release);
}
