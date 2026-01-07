#![feature(thread_local)]

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::cell::Cell;

static LOG_LOCK: Mutex<()> = Mutex::new(());

#[thread_local]
static IN_CHECKER: Cell<bool> = Cell::new(false);

pub fn init() {
    println!("SVF Runtime Initialized");
    let ptr = __svf_check_alias as *const ();
    println!("__svf_check_alias at {:?}", ptr);
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __svf_check_alias(p: usize, q: usize, id: u32) {
    // Check thread-local guard to prevent recursion
    // Since it's a primitive thread_local static, we access it directly.
    if IN_CHECKER.get() {
        return;
    }
    IN_CHECKER.set(true);

    // Use a struct to ensure the guard is reset even if we panic/return early
    struct GuardReset;
    impl Drop for GuardReset {
        fn drop(&mut self) {
            IN_CHECKER.set(false);
        }
    }
    let _guard_reset = GuardReset;

    let is_alias = p == q;
    
    // Note: format! might allocate, potentially recursing (caught by guard).
    let output = format!("ID:{} RES:{} (0x{:x} vs 0x{:x})\n", 
        id, 
        if is_alias { 1 } else { 0 },
        p, q
    );

    {
        // Global lock only for the I/O part
        let _guard = LOG_LOCK.lock().unwrap();
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/svf_runtime_results.txt") 
        {
            let _ = file.write_all(output.as_bytes());
        }
    }
}
