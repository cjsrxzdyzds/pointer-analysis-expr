add_executable(svf-checker svf-checker.cpp)

target_link_libraries(svf-checker
    PRIVATE
    SvfLLVM
    SvfCore
    ${Z3_LIBRARIES}
    # LLVM libraries are transitive from SvfLLVM usually, but we can be explicit if needed
)
