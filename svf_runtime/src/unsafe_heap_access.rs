//! unsafe heap access counting module for svf runtime.
//! tracks both svf-predicted and runtime-confirmed unsafe heap accesses.
//! predicted: counts unique svf node ids (heap objects svf says are unsafely accessed).
//! confirmed: tracks unique runtime ticket IDs of actually touched heap objects.
//!
//! IMPORTANT: this function is called for EVERY load/store in sese regions,
//! including loads/stores inside this module and the runtime itself.
//! all operations must be non-allocating and non-blocking to prevent
//! stack overflow and deadlocks.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::BTreeSet;

// predicted counters: track svf's raw prediction (unique node ids)
static PREDICTED_LOAD: AtomicUsize = AtomicUsize::new(0);
static PREDICTED_STORE: AtomicUsize = AtomicUsize::new(0);
static PREDICTED_OBJS: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    /// set of svf node ids that svf predicts are unsafely accessed.
    static ref PREDICTED_SITE_IDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
    
    /// set of globally unique allocation tickets that were ACTUALLY touched by an unsafe pointer.
    /// Since memory addresses are reused after `free`, we track unique ticket IDs to 
    /// explicitly prevent double-counting or under-counting of historically touched objects.
    static ref ACTUALLY_TOUCHED_TICKETS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
}

// zero-cost reentrancy guard — prevents recursive calls from instrumented
// code inside this module (locks, btreemap ops, etc.)
#[thread_local]
static mut IN_UNSAFE_ACCESS: bool = false;

/// print unsafe heap access statistics: actual vs predicted vs confirmed.
pub fn print_unsafe_heap_stats() {
    let pred_load = PREDICTED_LOAD.load(Ordering::Relaxed);
    let pred_store = PREDICTED_STORE.load(Ordering::Relaxed);
    let pred_objs = PREDICTED_OBJS.load(Ordering::Relaxed);
    
    // dynamically tally actual memory allocated by the SVF predicted site IDs.
    let mut pred_mem = 0;
    if let Ok(predicted) = PREDICTED_SITE_IDS.try_lock() {
        for &site_id in predicted.iter() {
            pred_mem += crate::heap::get_site_alloc_bytes(site_id);
        }
    }

    let actual_touched_count = if let Ok(touched) = ACTUALLY_TOUCHED_TICKETS.try_lock() {
        touched.len()
    } else {
        0
    };

    println!("\n=== SVF Unsafe Heap Access Stats ===");
    println!("--- SVF Predicted (static analysis) ---");
    println!("Predicted unsafe heap objects: {}", pred_objs);
    println!("Predicted unsafe heap memory: {} bytes", pred_mem);
    println!("Predicted unsafe load: {}", pred_load);
    println!("Predicted unsafe store: {}", pred_store);
    println!("Predicted total accesses: {}", pred_load + pred_store);
    println!("--- Runtime Tracked Ground Truth ---");
    println!("Historically Touched Unique Heap Objects: {}", actual_touched_count);
    println!("====================================\n");
}

/// runtime hook: called ONCE per load/store execution to act as SVF base usage.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __svf_predict_heap_access(ptr: *const u8, is_load: bool) {
    if ptr.is_null() { return; }
    if IN_UNSAFE_ACCESS { return; }

    // Before matching HeapTracker, SESE tracks ALL valid pointers, even stack. Wait! Ground truth only tracks unsafe 'heap'.
    // Check if it's genuinely inside the LIVE HEAP boundary and retrieve its unique ticket!
    if let Some(ticket) = crate::heap::get_live_heap_ticket(ptr) {
        IN_UNSAFE_ACCESS = true;

        if let Ok(mut touched) = ACTUALLY_TOUCHED_TICKETS.try_lock() {
            touched.insert(ticket);
        }

        if is_load { PREDICTED_LOAD.fetch_add(1, Ordering::Relaxed); }
        else { PREDICTED_STORE.fetch_add(1, Ordering::Relaxed); }

        IN_UNSAFE_ACCESS = false;
    }
}

/// runtime hook: called for EACH targetId predicted by SVF.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __svf_predict_heap_obj(ptr: *const u8, site_id: u64) {
    if ptr.is_null() { return; }
    if IN_UNSAFE_ACCESS { return; }
    IN_UNSAFE_ACCESS = true;

    if site_id > 0 {
        if let Ok(mut predicted) = PREDICTED_SITE_IDS.try_lock() {
            if predicted.insert(site_id) {
                PREDICTED_OBJS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    IN_UNSAFE_ACCESS = false;
}
