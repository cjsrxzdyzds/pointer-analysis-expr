#![feature(thread_local)]

use std::sync::{Mutex, Once};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

static LOG_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static IN_CHECKER: Cell<bool> = Cell::new(false);
}

// Statistics
static CNT_TRUE_ALIAS: AtomicUsize = AtomicUsize::new(0);
static CNT_TRUE_DISJOINT: AtomicUsize = AtomicUsize::new(0);
static CNT_FALSE_ALIAS: AtomicUsize = AtomicUsize::new(0);
static CNT_FALSE_DISJOINT: AtomicUsize = AtomicUsize::new(0);
static CNT_TOTAL: AtomicUsize = AtomicUsize::new(0);
static CNT_NO_INFO: AtomicUsize = AtomicUsize::new(0);

pub fn init() {
    println!("SVF Runtime Initialized");
    let ptr = __svf_check_alias as *const ();
    println!("__svf_check_alias at {:?}", ptr);
}

pub fn print_stats() {
    let t_alias = CNT_TRUE_ALIAS.load(Ordering::Relaxed);
    let t_disjoint = CNT_TRUE_DISJOINT.load(Ordering::Relaxed);
    let f_alias = CNT_FALSE_ALIAS.load(Ordering::Relaxed);
    let f_disjoint = CNT_FALSE_DISJOINT.load(Ordering::Relaxed);
    let no_info = CNT_NO_INFO.load(Ordering::Relaxed);
    let total = CNT_TOTAL.load(Ordering::Relaxed);

    println!("\n=== SVF Runtime Statistics ===");
    println!("Total Checks: {}", total);
    println!("Correct Predictions:");
    println!("  True Alias (Predicted Alias & is Alias): {}", t_alias);
    println!("  True Disjoint (Predicted NoAlias & No Alias): {}", t_disjoint);
    println!("Incorrect Predictions:");
    println!("  False Alias (False Positive): {}", f_alias);
    println!("  False Disjoint (False Negative): {}", f_disjoint); // Critical bug if > 0
    println!("No Info / Low Confidence: {}", no_info);
    
    if total > 0 {
        let correct = t_alias + t_disjoint;
        let accuracy = (correct as f64 / total as f64) * 100.0;
        println!("Accuracy: {:.2}%", accuracy);
    }
    println!("==============================\n");

    // Heap Verification Stats
    let mut total_heap_checks = 0;
    let mut total_tp = 0;
    let mut total_fp = 0;
    
    {
        let stats = SITE_STATS.lock().unwrap();
        for (_, s) in stats.iter() {
            total_tp += s.true_positive;
            total_fp += s.false_positive;
        }
    }
    total_heap_checks = total_tp + total_fp;

    println!("\n=== Heap Allocation Verification Stats ===");
    println!("Total Heap Checks: {}", total_heap_checks);
    println!("True Positives (Correctly Identified Heap): {}", total_tp);
    println!("False Positives ( Identified Heap but not found): {}", total_fp);
    if total_heap_checks > 0 {
         let precision = (total_tp as f64 / total_heap_checks as f64) * 100.0;
         println!("Precision: {:.2}%", precision);
    }
    println!("==========================================\n");
}

extern "C" {
    fn atexit(cb: extern "C" fn()) -> i32;
}

static REGISTER_ATEXIT: Once = Once::new();

extern "C" fn print_stats_wrapper() {
    print_stats();
}

#[repr(C)]
struct ThreadStats {
    true_alias: usize,
    true_disjoint: usize,
    false_alias: usize,
    false_disjoint: usize,
    total: usize,
    no_info: usize,
}

impl ThreadStats {
    fn new() -> Self {
        Self {
            true_alias: 0,
            true_disjoint: 0,
            false_alias: 0,
            false_disjoint: 0,
            total: 0,
            no_info: 0,
        }
    }
}

impl Drop for ThreadStats {
    fn drop(&mut self) {
        CNT_TRUE_ALIAS.fetch_add(self.true_alias, Ordering::Relaxed);
        CNT_TRUE_DISJOINT.fetch_add(self.true_disjoint, Ordering::Relaxed);
        CNT_FALSE_ALIAS.fetch_add(self.false_alias, Ordering::Relaxed);
        CNT_FALSE_DISJOINT.fetch_add(self.false_disjoint, Ordering::Relaxed);
        CNT_TOTAL.fetch_add(self.total, Ordering::Relaxed);
        CNT_NO_INFO.fetch_add(self.no_info, Ordering::Relaxed);
    }
}

use std::cell::RefCell;

// using BTreeMap for range queries
#[macro_use]
extern crate lazy_static;

use std::sync::RwLock;
use std::collections::{BTreeMap, HashMap};

struct AllocInfo {
    site_id: u64,
    size: usize,
}

struct SiteStats {
    alloc_count: u64,
    alloc_bytes: u64,
    free_count: u64,
    free_bytes: u64,
    // Verification Stats
    true_positive: u64,  // Unsafe access correctly identified as heap
    false_positive: u64, // Unsafe access identified as heap but wasn't (likely impossible if we only track heap?) 
                         // Actually: "Check Heap" means "Is this ptr a heap ptr?".
                         // If svf says "This is heap", and we find it in map -> True Positive (Analysis correctness)
                         // If svf says "This is heap", and we DO NOT find it -> False Positive (Analysis thought it was heap, but it wasn't allocated/active)
    
}

impl SiteStats {
    fn new() -> Self {
        Self {
            alloc_count: 0,
            alloc_bytes: 0,
            free_count: 0,
            free_bytes: 0,
            true_positive: 0,
            false_positive: 0,
        }
    }
}

lazy_static! {
    // Map Address -> (Size, SiteID)
    // We use BTreeMap to allow range queries (ptr in [base, base+size))
    static ref LIVE_HEAP: RwLock<BTreeMap<usize, (usize, u64)>> = RwLock::new(BTreeMap::new());
    
    // Map Site ID -> Statistics
    static ref SITE_STATS: Mutex<HashMap<u64, SiteStats>> = Mutex::new(HashMap::new());
}

#[no_mangle]
pub unsafe extern "C" fn __svf_report_alloc(ptr: *mut u8, size: usize, site_id: u64) {
    if ptr.is_null() { return; }
    let addr = ptr as usize;
    
    // Update per-site stats
    {
        let mut stats = SITE_STATS.lock().unwrap();
        let entry = stats.entry(site_id).or_insert_with(SiteStats::new);
        entry.alloc_count += 1;
        entry.alloc_bytes += size as u64;
    }

    // Record pointer info
    {
        // Skip if tracking (avoid reentrancy if BTreeMap allocates)
        // For simplicity assuming RwLock doesn't alloc, but BTreeMap insert might.
        // In heap_tracker.rs they used threads_local reentrancy guard.
        // We really should use that here too if we were hooking malloc directly.
        // Since we are inserting explicit calls, it's safer, but let's be careful.
        let mut heap_map = LIVE_HEAP.write().unwrap();
        heap_map.insert(addr, (size, site_id));
    }
}

#[no_mangle]
pub unsafe extern "C" fn __svf_report_dealloc(ptr: *mut u8) {
    if ptr.is_null() { return; }
    let addr = ptr as usize;

    let removed_info = {
        let mut heap_map = LIVE_HEAP.write().unwrap();
        heap_map.remove(&addr)
    };

    if let Some((size, site_id)) = removed_info {
        let mut stats = SITE_STATS.lock().unwrap();
        if let Some(entry) = stats.get_mut(&site_id) {
            entry.free_count += 1;
            entry.free_bytes += size as u64;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn __svf_check_heap(ptr: *const u8, site_id: u64) {
    if ptr.is_null() { return; }
    let addr = ptr as usize;

    // Range query: find the last key <= addr
    let is_valid_heap = {
        let heap_map = LIVE_HEAP.read().unwrap();
        if let Some((&base_addr, &(size, _alloc_site_id))) = heap_map.range(..=addr).next_back() {
            // Check if addr is within [base_addr, base_addr + size)
            addr < base_addr + size
        } else {
            false
        }
    };

    // Update Verification Stats
    {
        let mut stats = SITE_STATS.lock().unwrap();
        let entry = stats.entry(site_id).or_insert_with(SiteStats::new);
        
        if is_valid_heap {
            entry.true_positive += 1;
        } else {
            entry.false_positive += 1; 
            // This means SVF claimed it was a heap access (by checking site_id),
            // but at runtime we couldn't find a live object covering this address.
            // Could be:
            // 1. Logic error in Analysis (Static Said Heap, Runtime says Stack/Global)
            // 2. Use-After-Free (Valid Heap Object existed but is gone)
            // 3. OOB Access (Valid Heap Object exists nearby but we are outside)
        }
    }
}


thread_local! {
    static LOCAL_STATS: RefCell<ThreadStats> = RefCell::new(ThreadStats::new());
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __svf_check_alias(p: usize, q: usize, id: u32) {
    if IN_CHECKER.with(|c| c.get()) { return; }
    IN_CHECKER.with(|c| c.set(true));

    // Register atexit handler once
    REGISTER_ATEXIT.call_once(|| {
        atexit(print_stats_wrapper);
    });

    struct GuardReset;
    impl Drop for GuardReset { fn drop(&mut self) { IN_CHECKER.with(|c| c.set(false)); } }
    let _guard_reset = GuardReset;

    let is_actual_alias = p == q;
    
    // Decode ID (MSB = prediction valid, next bit = prediction)
    // Actually current logic says MSB (31) is "Prediction Bit".
    // Let's stick to the previous logic: Bit 31: 1=Alias, 0=NoAlias/NoInfo
    // id & 0x7FFFFFFF is the real ID.
    
    let prediction_bit = (id >> 31) & 1;
    let predicted_alias = prediction_bit == 1;

    LOCAL_STATS.with(|stats| {
        let mut s = stats.borrow_mut();
        s.total += 1;

        if predicted_alias {
            if is_actual_alias {
                s.true_alias += 1;
            } else {
                s.false_alias += 1;
            }
        } else {
            if is_actual_alias {
                s.false_disjoint += 1;
            } else {
                s.true_disjoint += 1;
            }
        }
    });
    // Removed File Output as requested.
}
