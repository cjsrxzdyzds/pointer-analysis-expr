extern crate svf_runtime;

fn foo(p: *const u8, q: *const u8) {
    unsafe {
        println!("Checking pointers: {:?} vs {:?}", p, q);
    }
}

fn main() {
    svf_runtime::init();
    let x = 10;
    let y = 20;
    println!("Running app...");
    foo(&x, &x);
    foo(&x, &y);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instrumentation() {
        let x = 100;
        let y = 200;
        // These calls should be instrumented by the LLVM pass.
        // We expect entries in /tmp/svf_runtime_results.txt
        foo(&x, &x);
        foo(&x, &y);
    }
}
