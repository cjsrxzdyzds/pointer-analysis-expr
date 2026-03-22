//! svf runtime library — modular design.
//! provides runtime hooks for svf-based analysis:
//! - alias checking (__svf_check_alias)
//! - heap verification (__svf_report_alloc, __svf_report_dealloc)
//! - unsafe heap access counting (__svf_unsafe_heap_access)

#![feature(thread_local)]

use std::sync::Once;
use std::cell::Cell;

#[macro_use]
extern crate lazy_static;

pub mod alias;
pub mod heap;
pub mod unsafe_heap_access;

thread_local! {
    /// shared reentrancy guard used by heap and alias modules.
    pub(crate) static IN_CHECKER: Cell<bool> = Cell::new(false);
}

/// raii guard that resets IN_CHECKER when dropped, ensuring the reentrancy
/// flag is cleared even if a panic occurs inside the hook functions.
pub(crate) struct ReentrancyGuard;
impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        IN_CHECKER.with(|c| c.set(false));
    }
}

extern "C" {
    pub(crate) fn atexit(cb: extern "C" fn()) -> i32;
}

pub(crate) static REGISTER_ATEXIT: Once = Once::new();

pub(crate) extern "C" fn print_stats_wrapper() {
    print_stats();
}

pub fn init() {
    println!("SVF Runtime Initialized");
    // register atexit handler
    REGISTER_ATEXIT.call_once(|| {
        unsafe { atexit(print_stats_wrapper); }
    });
}

pub fn print_stats() {
    alias::print_alias_stats();
    heap::print_heap_stats();
    unsafe_heap_access::print_unsafe_heap_stats();
}

#[no_mangle]
pub extern "C" fn __svf_print_stats() {
    print_stats();
}
