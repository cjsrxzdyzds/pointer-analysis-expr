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
