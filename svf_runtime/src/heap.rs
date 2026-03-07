//! heap checking module for svf runtime.
//! contains __svf_report_alloc, __svf_report_dealloc, __svf_check_heap
//! and the LIVE_HEAP map shared with unsafe_heap_access module.

use std::sync::Mutex;
use std::collections::{BTreeMap, HashMap};

use crate::{IN_CHECKER, ReentrancyGuard};

/// allocation metadata stored per live heap object.
#[allow(dead_code)]
pub(crate) struct AllocInfo {
    pub site_id: u64,
    pub size: usize,
}

/// per-site statistics for heap verification.
struct SiteStats {
    alloc_count: u64,
    alloc_bytes: u64,
    free_count: u64,
    free_bytes: u64,
    true_positive: u64,
    false_positive: u64,
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
    /// map address -> (size, site_id). uses BTreeMap for range queries.
    /// shared with unsafe_heap_access module for heap lookups.
    pub(crate) static ref LIVE_HEAP: std::sync::RwLock<BTreeMap<usize, (usize, u64)>> =
        std::sync::RwLock::new(BTreeMap::new());

    /// per-site verification statistics.
    static ref SITE_STATS: Mutex<HashMap<u64, SiteStats>> = Mutex::new(HashMap::new());
}

/// print heap verification statistics.
pub fn print_heap_stats() {
    let total_heap_checks;
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
    println!("False Positives (Identified Heap but not found): {}", total_fp);
    if total_heap_checks > 0 {
        let precision = (total_tp as f64 / total_heap_checks as f64) * 100.0;
        println!("Precision: {:.2}%", precision);
    }
    println!("==========================================\n");
}

#[no_mangle]
pub unsafe extern "C" fn __svf_report_alloc(ptr: *mut u8, size: usize, site_id: u64) {
    if ptr.is_null() { return; }
    if IN_CHECKER.with(|c| c.get()) { return; }
    IN_CHECKER.with(|c| c.set(true));
    let _guard = ReentrancyGuard;

    let addr = ptr as usize;

    {
        let mut heap_map = LIVE_HEAP.write().unwrap();
        heap_map.insert(addr, (size, site_id));
    }

    {
        let mut stats = SITE_STATS.lock().unwrap();
        let entry = stats.entry(site_id).or_insert_with(SiteStats::new);
        entry.alloc_count += 1;
        entry.alloc_bytes += size as u64;
    }
}

#[no_mangle]
pub unsafe extern "C" fn __svf_report_dealloc(ptr: *mut u8) {
    if ptr.is_null() { return; }
    if IN_CHECKER.with(|c| c.get()) { return; }
    IN_CHECKER.with(|c| c.set(true));
    let _guard = ReentrancyGuard;

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
    if IN_CHECKER.with(|c| c.get()) { return; }
    IN_CHECKER.with(|c| c.set(true));
    let _guard = ReentrancyGuard;

    // register atexit handler on first call
    crate::REGISTER_ATEXIT.call_once(|| {
        crate::atexit(crate::print_stats_wrapper);
    });

    let addr = ptr as usize;

    let is_valid_heap;
    {
        let heap_map = LIVE_HEAP.read().unwrap();
        if let Some((&base_addr, &(size, _alloc_site_id))) = heap_map.range(..=addr).next_back() {
            is_valid_heap = addr < base_addr + size;
        } else {
            is_valid_heap = false;
        }
    }

    {
        let mut stats = SITE_STATS.lock().unwrap();
        let entry = stats.entry(site_id).or_insert_with(SiteStats::new);

        if is_valid_heap {
            entry.true_positive += 1;
        } else {
            entry.false_positive += 1;
            eprintln!("[SVF RUNTIME WARNING] False Positive Detected!");
            eprintln!("  -> SVF static analysis indicated pointer {:#x} accessing site {} was a valid heap object.", addr, site_id);
            eprintln!("  -> However, at runtime, NO LIVE ALLOCATION bounds contained this pointer.");
            eprintln!("  -> This indicates either (1) use-after-free, (2) out-of-bounds, or (3) static aliasing mismatch.");
        }
    }
}
