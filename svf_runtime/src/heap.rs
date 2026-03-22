//! heap checking module for svf runtime.
//! contains __svf_report_alloc, __svf_report_dealloc
//! and the LIVE_HEAP map shared with unsafe_heap_access module.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::{BTreeMap, HashMap};

use crate::{IN_CHECKER, ReentrancyGuard};

/// global monotonic ticket counter for unique allocation id tracking
static ALLOCATION_TICKET_COUNTER: AtomicU64 = AtomicU64::new(1);

/// per-site statistics for heap verification.
struct SiteStats {
    alloc_count: u64,
    alloc_bytes: u64,
    free_count: u64,
    free_bytes: u64,
}

impl SiteStats {
    fn new() -> Self {
        Self {
            alloc_count: 0,
            alloc_bytes: 0,
            free_count: 0,
            free_bytes: 0,
        }
    }
}

lazy_static! {
    /// map address -> (size, site_id, ticket). uses BTreeMap for range queries.
    /// shared with unsafe_heap_access module for heap lookups.
    pub(crate) static ref LIVE_HEAP: std::sync::RwLock<BTreeMap<usize, (usize, u64, u64)>> =
        std::sync::RwLock::new(BTreeMap::new());

    static ref SITE_STATS: Mutex<HashMap<u64, SiteStats>> = Mutex::new(HashMap::new());
}

/// Helper method to quickly identify if a given pointer hits a live heap object
/// Returns (ticket, site_id) if found, or None.
pub(crate) fn get_live_heap_ticket(ptr: *const u8) -> Option<(u64, u64)> {
    let addr = ptr as usize;
    let heap_map = LIVE_HEAP.read().unwrap();
    if let Some((&base_addr, &(size, site_id, ticket))) = heap_map.range(..=addr).next_back() {
        if addr < base_addr + size {
            return Some((ticket, site_id));
        }
    }
    None
}

/// heap stats are now reported by unsafe_heap_access::print_unsafe_heap_stats().
/// this function is kept as a no-op for backward compatibility.
pub fn print_heap_stats() {}

/// Helper function for `unsafe_heap_access` to query dynamic allocation volumes
/// for SVF statically predicted `site_id`s.
pub(crate) fn get_site_alloc_bytes(site_id: u64) -> u64 {
    if let Ok(stats) = SITE_STATS.try_lock() {
        if let Some(entry) = stats.get(&site_id) {
            return entry.alloc_bytes;
        }
    }
    0
}

/// Helper function for `unsafe_heap_access` to query dynamic allocation frequencies
/// for SVF statically predicted `site_id`s.
pub(crate) fn get_site_alloc_count(site_id: u64) -> u64 {
    if let Ok(stats) = SITE_STATS.try_lock() {
        if let Some(entry) = stats.get(&site_id) {
            return entry.alloc_count;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn __svf_report_alloc(ptr: *mut u8, size: usize, site_id: u64) {
    if ptr.is_null() { return; }
    if IN_CHECKER.with(|c| c.get()) { return; }
    IN_CHECKER.with(|c| c.set(true));
    let _guard = ReentrancyGuard;

    let addr = ptr as usize;
    let ticket = ALLOCATION_TICKET_COUNTER.fetch_add(1, Ordering::SeqCst);

    {
        let mut heap_map = LIVE_HEAP.write().unwrap();
        heap_map.insert(addr, (size, site_id, ticket));
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

    if let Some((size, site_id, _ticket)) = removed_info {
        let mut stats = SITE_STATS.lock().unwrap();
        if let Some(entry) = stats.get_mut(&site_id) {
            entry.free_count += 1;
            entry.free_bytes += size as u64;
        }
    }
}

