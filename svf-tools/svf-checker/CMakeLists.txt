add_executable(svf-checker svf-checker.cpp)

target_link_libraries(svf-checker
    PRIVATE
    SvfLLVM
    SvfCore
    ${Z3_LIBRARIES}
    LLVM
)
