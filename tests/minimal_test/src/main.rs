#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Stub for the instrumentation call.
// In the full app, this is in svf_runtime.
#[no_mangle]
pub unsafe extern "C" fn __svf_check_alias(_p: *const u8, _q: *const u8, _id: u64) {
    // No-op for static analysis verification
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let x: i32 = 42;
    let y: i32 = 100;
    
    let p = &x as *const i32;
    let q = &y as *const i32;

    // Unsafe loads to trigger RuntimeAliasPass instrumentation
    unsafe {
        let _v1 = *p;
        let _v2 = *q;
    }

    loop {}
}
