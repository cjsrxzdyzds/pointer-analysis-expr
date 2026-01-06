extern crate svf_runtime;

fn main() {
    // Force linkage of svf_runtime
    svf_runtime::init();
    
    println!("Starting verification test...");

    // 1. Heap allocation (Box) to ensure we bypass the Stack Filter
    // My RuntimeAlias pass explicitly ignores AllocaInst, so we need Heap.
    let mut x = Box::new(10);
    let mut y = Box::new(20);

    let px = &mut *x as *mut i32;
    let py = &mut *y as *mut i32;

    unsafe {
        // 2. Unsafe Store and Load
        // Ideally, the compiler marks these with !unsafe_inst
        // The RuntimeAlias pass should find them, confirm they are not stack,
        // and insert __svf_check_alias(px, py, id)
        
        *px = 100;      // Store
        let val = *py;  // Load
        *py = val + 5;  // Store
        
        // This simple sequence ensures px and py are available and 'dominate' each other 
        // in the flow (linear block).
        
        println!("Performed unsafe operations. x={}, y={}", *px, *py);
    }
}
