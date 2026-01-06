add_library(SvfPlugin MODULE SvfLtoPlugin.cpp)

# Link against SVF. 
# Note: SVF libraries include LLVM dependencies implicitly in some builds,
# but for a plugin we must be careful not to double-link common symbols if possible,
# though MODULE libraries are usually safe.
target_link_libraries(SvfPlugin 
    PRIVATE 
    SvfLLVM 
    SvfCore
)

# Since we are a plugin loaded by opt/rustc, we generally do NOT want to link static LLVM into the .so
# because the host binary already has them. However, for compiling the C++ code we need headers.
# SVF's cmake setup usually handles header includes.
# We ensure we can ignore unresolved symbols because they will be provided by key host executable (rustc/opt)

