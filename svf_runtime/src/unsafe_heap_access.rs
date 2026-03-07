//! unsafe heap access counting module for svf runtime.
//! mirrors heap_tracker.rs metrics: counts unsafe heap objects, unsafe load/store,
//! and unsafe memory bytes — driven by svf's compile-time analysis.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::BTreeSet;
use std::cell::Cell;

use crate::IN_CHECKER;
use crate::heap::LIVE_HEAP;

// counters aligned with heap_tracker.rs
static UNSAFE_LOAD: AtomicUsize = AtomicUsize::new(0);
static UNSAFE_STORE: AtomicUsize = AtomicUsize::new(0);
static TOTAL_UNSAFE_OBJS: AtomicUsize = AtomicUsize::new(0);
static UNSAFE_MEM: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    /// set of base addresses of heap objects accessed unsafely.
    /// used to deduplicate: only count each object once.
    static ref LIVE_UNSAFE_OBJS: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());
}

thread_local! {
    /// reentrancy guard specific to this module to avoid deadlock
    /// when LIVE_UNSAFE_OBJS insertion triggers internal allocations.
    static IN_UNSAFE_ACCESS: Cell<bool> = Cell::new(false);
}

/// print unsafe heap access statistics aligned with heap_tracker.rs format.
pub fn print_unsafe_heap_stats() {
    let unsafe_objs = TOTAL_UNSAFE_OBJS.load(Ordering::Relaxed);
    let unsafe_mem = UNSAFE_MEM.load(Ordering::Relaxed);
    let unsafe_load = UNSAFE_LOAD.load(Ordering::Relaxed);
    let unsafe_store = UNSAFE_STORE.load(Ordering::Relaxed);

    println!("\n=== SVF Unsafe Heap Access Stats ===");
    println!("Total unsafe heap objects: {}", unsafe_objs);
    println!("Unsafe heap memory: {} bytes", unsafe_mem);
    println!("Unsafe load: {}", unsafe_load);
    println!("Unsafe store: {}", unsafe_store);
    println!("====================================\n");
}

/// runtime hook: called for each unsafe-region load/store that svf says
/// may point to a heap object.
///
/// mirrors heap_tracker.rs's dyn_unsafe_mem_access(ptr, is_load):
/// - checks if ptr falls within a live heap allocation (from LIVE_HEAP)
/// - if yes, records the base address in LIVE_UNSAFE_OBJS (counts object + size on first access)
/// - increments UNSAFE_LOAD or UNSAFE_STORE
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __svf_unsafe_heap_access(ptr: *const u8, is_load: bool) {
    if ptr.is_null() { return; }
    if IN_CHECKER.with(|c| c.get()) { return; }
    if IN_UNSAFE_ACCESS.with(|c| c.get()) { return; }

    IN_UNSAFE_ACCESS.with(|c| c.set(true));

    let addr = ptr as usize;

    // range query: find the last allocation base <= addr
    let heap_obj = {
        let heap_map = LIVE_HEAP.read().unwrap();
        heap_map.range(..=addr)
            .next_back()
            .and_then(|(&base_addr, &(size, _site_id))| {
                if addr < base_addr + size {
                    Some((base_addr, size))
                } else {
                    None
                }
            })
    };

    if let Some((base_addr, size)) = heap_obj {
        // record this object if first time
        {
            let mut unsafe_objs = LIVE_UNSAFE_OBJS.lock().unwrap();
            if unsafe_objs.insert(base_addr) {
                // first time seeing this object as unsafe
                TOTAL_UNSAFE_OBJS.fetch_add(1, Ordering::Relaxed);
                UNSAFE_MEM.fetch_add(size, Ordering::Relaxed);
            }
        }

        // count load/store
        if is_load {
            UNSAFE_LOAD.fetch_add(1, Ordering::Relaxed);
        } else {
            UNSAFE_STORE.fetch_add(1, Ordering::Relaxed);
        }
    }

    IN_UNSAFE_ACCESS.with(|c| c.set(false));
}
