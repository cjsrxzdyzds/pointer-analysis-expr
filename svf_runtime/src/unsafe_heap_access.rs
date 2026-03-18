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

    /// set of live allocations that were touched AND whose site_id was analyzed by SVF.
    static ref MATCHED_TOUCHED_TICKETS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

    /// set of unique site_ids that SVF successfully analyzed and were touched at runtime.
    static ref MATCHED_SITE_IDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

    /// set of unique site_ids that SVF missed but were touched at runtime (False Negatives).
    static ref MISSED_SITE_IDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
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
    let matched_count = if let Ok(matched) = MATCHED_TOUCHED_TICKETS.try_lock() {
        matched.len()
    } else {
        0
    };
    
    let matched_sites = if let Ok(m) = MATCHED_SITE_IDS.try_lock() { m.len() } else { 0 };
    let missed_sites = if let Ok(m) = MISSED_SITE_IDS.try_lock() { m.len() } else { 0 };
    
    println!("\n=== SVF Unsafe Heap Access Stats ===");
    println!("--- SVF Static Prediction Targets ---");
    println!("Predicted unsafe allocation sites: {}", pred_objs);

    println!("--- Runtime Tracked Ground Truth ---");
    println!("Unsafe heap loads executed: {}", pred_load);
    println!("Unsafe heap stores executed: {}", pred_store);
    println!("Memory allocated by predicted sites: {} bytes", pred_mem);
    println!("Historically Touched Unique Heap Objects: {}", actual_touched_count);
    println!("  -> Matched by SVF (True Positives): {} [from {} unique sites]", matched_count, matched_sites);
    if let Ok(matched) = MATCHED_SITE_IDS.try_lock() {
        print!("     Matched Static Site IDs: ");
        for &id in matched.iter() { print!("{} ", id); }
        println!();
    }
    println!("  -> Missed by SVF (False Negatives): {} [from {} unique sites]", actual_touched_count - matched_count, missed_sites);
    if let Ok(missed) = MISSED_SITE_IDS.try_lock() {
        print!("     Missed Static Site IDs: ");
        for &id in missed.iter() { print!("{} ", id); }
        println!();
    }
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
    if let Some((ticket, site_id)) = crate::heap::get_live_heap_ticket(ptr) {
        IN_UNSAFE_ACCESS = true;

        if let Ok(mut touched) = ACTUALLY_TOUCHED_TICKETS.try_lock() {
            touched.insert(ticket);
        }

        if let Ok(predicted) = PREDICTED_SITE_IDS.try_lock() {
            if predicted.contains(&site_id) {
                if let Ok(mut matched) = MATCHED_TOUCHED_TICKETS.try_lock() {
                    matched.insert(ticket);
                }
                if let Ok(mut sites) = MATCHED_SITE_IDS.try_lock() {
                    sites.insert(site_id);
                }
            } else {
                if let Ok(mut sites) = MISSED_SITE_IDS.try_lock() {
                    sites.insert(site_id);
                }
            }
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
