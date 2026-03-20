//! unsafe heap access tracking module for svf runtime.
//!
//! ## overview
//! this module cross-checks svf's static alias analysis against runtime ground truth.
//! for every instrumented load/store within an unsafe sese region, we classify the access
//! into one of four categories (confusion matrix):
//!
//! - **true positive (TP)**: svf identified >=1 heap allocation target for this pointer,
//!   AND at runtime the pointer actually accessed a live heap object.
//! - **false positive (FP)**: svf identified >=1 heap allocation target for this pointer,
//!   BUT at runtime the pointer did NOT access any live heap object (e.g., stack/global).
//! - **false negative (FN)**: svf identified 0 heap targets for this pointer (no alias found),
//!   BUT at runtime the pointer DID access a live heap object.
//! - **true negative (TN)**: svf identified 0 heap targets for this pointer,
//!   AND at runtime the pointer did NOT access any live heap object. this is correct.
//!
//! ## how stats are calculated
//! - `ANALYZED_SITES`: count of unique svf abstract heap object node ids seen via
//!   `__svf_analyze_heap_obj`. this is the total number of allocation sites svf's
//!   andersen analysis linked to at least one unsafe-region pointer.
//! - `ACCESS_TP/FP/FN/TN`: incremented once per instrumented load/store in sese regions.
//!   determined by matching `(svf_has_targets, runtime_is_heap)`.
//! - `MATCHED_SITE_IDS`: unique allocation site ids where svf's analysis matched the
//!   runtime heap object's site_id for a given pointer.
//! - `MISSED_SITE_IDS`: unique allocation site ids where the runtime found a heap object
//!   but svf either had no targets or had different targets for that pointer.
//! - `FP_SITE_IDS`: unique allocation site ids that svf associated with a pointer,
//!   but at runtime the pointer was not accessing any heap object.
//!
//! ## hook call order (per instrumented load/store)
//! 1. `__svf_analyze_heap_obj(ptr, site_id)` is called once per svf target — populates
//!    the thread-local `CURRENT_ANALYSIS` array with the analyzed site ids.
//! 2. `__svf_check_heap_access(ptr, is_load)` is called once per access — classifies
//!    the access as TP/FP/FN/TN by checking the pointer against `LIVE_HEAP`.
//!
//! IMPORTANT: these hooks are called for EVERY load/store in sese regions,
//! including loads/stores inside this module and the runtime itself.
//! all operations must be non-allocating and non-blocking to prevent
//! stack overflow and deadlocks.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::BTreeSet;

// heap access counters: count how many loads/stores actually targeted heap objects.
// these only increment when the runtime confirms the pointer is in LIVE_HEAP.
static HEAP_LOAD_COUNT: AtomicUsize = AtomicUsize::new(0);
static HEAP_STORE_COUNT: AtomicUsize = AtomicUsize::new(0);
// count of unique svf abstract heap object node ids (allocation sites svf analyzed).
static ANALYZED_SITES: AtomicUsize = AtomicUsize::new(0);

// per-access confusion matrix counters.
// each instrumented sese load/store increments exactly one of these.
// TP: svf identified >=1 heap target AND runtime confirms pointer is on heap.
// FP: svf identified >=1 heap target BUT runtime says pointer is NOT on heap.
// FN: svf identified 0 heap targets BUT runtime says pointer IS on heap.
// TN: svf identified 0 heap targets AND runtime confirms pointer is NOT on heap.
static ACCESS_TP: AtomicUsize = AtomicUsize::new(0);
static ACCESS_FP: AtomicUsize = AtomicUsize::new(0);
static ACCESS_FN: AtomicUsize = AtomicUsize::new(0);
static ACCESS_TN: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    /// global set of all unique allocation site ids that svf analyzed across the program.
    static ref GLOBAL_ANALYZED_SITE_IDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
    
    /// set of globally unique allocation tickets that were actually touched by unsafe pointers.
    /// uses monotonic ticket ids (not addresses) to avoid double-counting after free/reuse.
    static ref ACTUALLY_TOUCHED_TICKETS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

    /// tickets where svf correctly identified the allocation site (true positives).
    static ref MATCHED_TOUCHED_TICKETS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

    /// unique site_ids where svf's analysis matched the runtime object (true positive sites).
    static ref MATCHED_SITE_IDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

    /// unique site_ids touched at runtime but missed by svf (false negative sites).
    static ref MISSED_SITE_IDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

    /// unique site_ids svf associated with a pointer that was NOT on heap (false positive sites).
    static ref FP_SITE_IDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
}

// reentrancy guard — prevents recursive calls from instrumented
// code inside this module (locks, btreemap ops, etc.)
#[thread_local]
static mut IN_UNSAFE_ACCESS: bool = false;

// thread-local array of svf analysis results for the *current* instruction.
// populated by `__svf_analyze_heap_obj` and consumed/cleared by `__svf_check_heap_access`.
#[thread_local]
static mut CURRENT_ANALYSIS: Option<[u64; 16]> = None;
#[thread_local]
static mut CURRENT_ANALYSIS_LEN: usize = 0;

/// print unsafe heap access statistics.
/// called via atexit handler registered in `__svf_analyze_heap_obj`.
pub fn print_unsafe_heap_stats() {
    let heap_loads = HEAP_LOAD_COUNT.load(Ordering::Relaxed);
    let heap_stores = HEAP_STORE_COUNT.load(Ordering::Relaxed);
    let analyzed_objs = ANALYZED_SITES.load(Ordering::Relaxed);
    
    // tally actual memory allocated by the svf-analyzed site ids.
    let mut analyzed_mem = 0;
    if let Ok(analyzed) = GLOBAL_ANALYZED_SITE_IDS.try_lock() {
        for &site_id in analyzed.iter() {
            analyzed_mem += crate::heap::get_site_alloc_bytes(site_id);
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

    let mut never_accessed_fp_sites = BTreeSet::new();
    if let (Ok(analyzed), Ok(matched)) = (GLOBAL_ANALYZED_SITE_IDS.try_lock(), MATCHED_SITE_IDS.try_lock()) {
        for &id in analyzed.iter() {
            if !matched.contains(&id) {
                never_accessed_fp_sites.insert(id);
            }
        }
    }

    let mut never_accessed_fp_objs = 0;
    for &id in never_accessed_fp_sites.iter() {
        never_accessed_fp_objs += crate::heap::get_site_alloc_count(id);
    }

    let tp = ACCESS_TP.load(Ordering::Relaxed);
    let fp = ACCESS_FP.load(Ordering::Relaxed);
    let fn_ = ACCESS_FN.load(Ordering::Relaxed);
    let tn = ACCESS_TN.load(Ordering::Relaxed);
    let total = tp + fp + fn_ + tn;

    println!("\n=== SVF Unsafe Heap Access Analysis ===");

    // section 1: per-access confusion matrix
    // classifies each instrumented sese load/store based on whether svf identified
    // heap targets and whether the pointer actually accessed heap at runtime.
    println!("--- Per-Access Confusion Matrix ---");
    println!("(each instrumented load/store in SESE unsafe regions is classified once)");
    println!("Total instrumented SESE accesses: {}", total);
    println!("  True Positive  (SVF identified heap target, runtime IS  heap): {}", tp);
    println!("  False Positive (SVF identified heap target, runtime NOT heap): {}", fp);
    println!("  False Negative (SVF found no heap target,   runtime IS  heap): {}", fn_);
    println!("  True Negative  (SVF found no heap target,   runtime NOT heap): {}", tn);
    if total > 0 {
        let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 * 100.0 } else { 0.0 };
        let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 * 100.0 } else { 0.0 };
        println!("  Precision (TP / (TP + FP)): {:.2}%", precision);
        println!("  Recall    (TP / (TP + FN)): {:.2}%", recall);
    }
    if fp > 0 {
        if let Ok(fps) = FP_SITE_IDS.try_lock() {
            print!("  FP site IDs (SVF static analysis claimed pointer targets these sites, but actually not): ");
            for &id in fps.iter() { print!("{} ", id); }
            println!();
        }
    }

    // section 2: svf static analysis overview
    // how many unique allocation sites svf's andersen analysis linked to unsafe pointers.
    println!("--- SVF Static Analysis ---");
    println!("Unique allocation sites SVF identified as aliased by unsafe ptrs: {}", analyzed_objs);
    println!("Total memory allocated by SVF-identified sites at runtime: {} bytes", analyzed_mem);

    // section 3: runtime heap object tracking (ground truth)
    // tracks unique heap objects (by monotonic ticket id) to avoid reuse confusion.
    // a heap object is "touched" if any instrumented unsafe pointer accessed it.
    println!("--- Runtime Heap Object Tracking (Ground Truth) ---");
    println!("Unsafe heap loads observed at runtime: {}", heap_loads);
    println!("Unsafe heap stores observed at runtime: {}", heap_stores);
    println!("Historically touched unique heap objects: {}", actual_touched_count);
    println!("  -> True Positive objects (SVF correctly identified): {} [from {} unique sites]", matched_count, matched_sites);
    if let Ok(matched) = MATCHED_SITE_IDS.try_lock() {
        print!("     Matched site IDs: ");
        for &id in matched.iter() { print!("{} ", id); }
        println!();
    }
    let fn_objs = if actual_touched_count >= matched_count { actual_touched_count - matched_count } else { 0 };
    println!("  -> False Negative objects (SVF missed): {} [from {} unique sites]", fn_objs, missed_sites);
    if let Ok(missed) = MISSED_SITE_IDS.try_lock() {
        print!("     Missed site IDs: ");
        for &id in missed.iter() { print!("{} ", id); }
        println!();
    }
    if !never_accessed_fp_sites.is_empty() {
        println!("  -> False Positive objects (SVF identified but NEVER accessed by unsafe ptr): {} [from {} unique sites]", never_accessed_fp_objs, never_accessed_fp_sites.len());
        print!("     FP site IDs: ");
        for &id in never_accessed_fp_sites.iter() { print!("{} ", id); }
        println!();
    }
    // true negative objects: pointers that svf correctly did not associate with heap,
    // and at runtime they indeed did not access heap. reported as access count above.
    println!("  -> True Negative accesses (no heap target, confirmed not heap): {}", tn);
    println!("======================================\n");
}

/// runtime hook: called once per instrumented load/store to cross-check svf analysis
/// against runtime heap state. classifies each access as TP/FP/FN/TN.
///
/// ## classification logic:
/// - has_svf_targets = CURRENT_ANALYSIS_LEN > 0 (svf identified heap allocation targets)
/// - is_heap = get_live_heap_ticket(ptr) returns Some (pointer is in LIVE_HEAP)
/// - (true, Some)  => TP: svf correctly identified a heap target
/// - (true, None)  => FP: svf said heap but pointer is actually stack/global
/// - (false, Some) => FN: svf missed this heap access entirely
/// - (false, None) => TN: svf correctly had no heap targets for a non-heap pointer
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __svf_check_heap_access(ptr: *const u8, is_load: bool) {
    if ptr.is_null() { return; }
    if IN_UNSAFE_ACCESS { return; }
    IN_UNSAFE_ACCESS = true;

    let a_len = CURRENT_ANALYSIS_LEN;
    let svf_has_targets = a_len > 0;
    let heap_hit = crate::heap::get_live_heap_ticket(ptr);

    match (svf_has_targets, heap_hit) {
        // TRUE POSITIVE: svf identified heap target(s) AND pointer is on heap
        (true, Some((ticket, site_id))) => {
            ACCESS_TP.fetch_add(1, Ordering::Relaxed);
            if is_load { HEAP_LOAD_COUNT.fetch_add(1, Ordering::Relaxed); }
            else { HEAP_STORE_COUNT.fetch_add(1, Ordering::Relaxed); }

            if let Ok(mut touched) = ACTUALLY_TOUCHED_TICKETS.try_lock() {
                touched.insert(ticket);
            }

            // check if *this specific* site_id was among svf's analysis results
            let mut matched_current = false;
            for i in 0..a_len {
                if let Some(analysis) = CURRENT_ANALYSIS {
                    if analysis[i] == site_id {
                        matched_current = true;
                        break;
                    }
                }
            }
            if matched_current {
                if let Ok(mut matched) = MATCHED_TOUCHED_TICKETS.try_lock() {
                    matched.insert(ticket);
                }
                if let Ok(mut sites) = MATCHED_SITE_IDS.try_lock() {
                    sites.insert(site_id);
                }
            } else {
                // svf identified *some* heap target, but not THIS specific site
                if let Ok(mut sites) = MISSED_SITE_IDS.try_lock() {
                    sites.insert(site_id);
                }
                println!("[SVF RUNTIME WARNING] False Negative Detected!");
                println!("  -> Pointer {:?} accessed heap object from allocation site {}.", ptr, site_id);
                println!("  -> SVF's analysis did not identify this alias relation for this pointer. (analyzed targets: {})", a_len);
            }
        }
        // FALSE POSITIVE: svf identified heap target(s) BUT pointer is NOT on heap
        (true, None) => {
            ACCESS_FP.fetch_add(1, Ordering::Relaxed);
            // record which site_ids were incorrectly associated
            if let Ok(mut fps) = FP_SITE_IDS.try_lock() {
                for i in 0..a_len {
                    if let Some(analysis) = CURRENT_ANALYSIS {
                        if analysis[i] > 0 {
                            fps.insert(analysis[i]);
                        }
                    }
                }
            }
        }
        // FALSE NEGATIVE: svf identified 0 heap targets BUT pointer IS on heap
        (false, Some((ticket, site_id))) => {
            ACCESS_FN.fetch_add(1, Ordering::Relaxed);
            if is_load { HEAP_LOAD_COUNT.fetch_add(1, Ordering::Relaxed); }
            else { HEAP_STORE_COUNT.fetch_add(1, Ordering::Relaxed); }

            if let Ok(mut touched) = ACTUALLY_TOUCHED_TICKETS.try_lock() {
                touched.insert(ticket);
            }
            if let Ok(mut sites) = MISSED_SITE_IDS.try_lock() {
                sites.insert(site_id);
            }
            println!("[SVF RUNTIME WARNING] False Negative Detected!");
            println!("  -> Pointer {:?} accessed heap object from allocation site {}.", ptr, site_id);
            println!("  -> SVF's analysis found no heap targets for this pointer. (analyzed targets: 0)");
        }
        // TRUE NEGATIVE: svf identified 0 heap targets AND pointer is NOT on heap
        (false, None) => {
            ACCESS_TN.fetch_add(1, Ordering::Relaxed);
        }
    }

    // unconditionally clear analysis results for next instruction
    CURRENT_ANALYSIS_LEN = 0;
    IN_UNSAFE_ACCESS = false;
}

/// runtime hook: called for EACH allocation site svf identified as aliasing a given pointer.
/// populates the thread-local CURRENT_ANALYSIS array so that `__svf_check_heap_access`
/// can cross-check against runtime heap state.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __svf_analyze_heap_obj(ptr: *const u8, site_id: u64) {
    if ptr.is_null() { return; }
    if IN_UNSAFE_ACCESS { return; }
    IN_UNSAFE_ACCESS = true;

    // register atexit handler on first call so stats are printed at exit
    crate::REGISTER_ATEXIT.call_once(|| {
        crate::atexit(crate::print_stats_wrapper);
    });

    if site_id > 0 {
        if CURRENT_ANALYSIS.is_none() {
            CURRENT_ANALYSIS = Some([0; 16]);
        }
        if CURRENT_ANALYSIS_LEN < 16 {
            if let Some(ref mut analysis) = CURRENT_ANALYSIS {
                analysis[CURRENT_ANALYSIS_LEN] = site_id;
                CURRENT_ANALYSIS_LEN += 1;
            }
        }

        if let Ok(mut analyzed) = GLOBAL_ANALYZED_SITE_IDS.try_lock() {
            if analyzed.insert(site_id) {
                ANALYZED_SITES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    IN_UNSAFE_ACCESS = false;
}
