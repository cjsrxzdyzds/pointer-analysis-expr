#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"
#include <chrono>

// SVF Headers
#include "SVF-LLVM/LLVMModule.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "WPA/Andersen.h"
#include "Util/SVFUtil.h"

using namespace llvm;
using namespace SVF;

// -----------------------------------------------------------------------------
// SVF LTO Pass
// -----------------------------------------------------------------------------
struct SvfLtoPass : public PassInfoMixin<SvfLtoPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &FAM) {
        errs() << "\n[SVF-LTO] Starting In-Process Analysis...\n";
        errs() << "[SVF-LTO] Module: " << M.getModuleIdentifier() << "\n";

        auto start = std::chrono::high_resolution_clock::now();

        // 1. Build SVF Module from In-Memory LLVM Module
        errs() << "[SVF-LTO] Step 1: Building SVF Module...\n";
        // FIX: Rust's LTO context discards value names by default, which breaks SVF's extapi loading.
        M.getContext().setDiscardValueNames(false);
        LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
        
        auto t1 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff1 = t1 - start;
        errs() << "[SVF-LTO] Done building SVF Module in " << diff1.count() << "s\n";

        // 2. Build SVF IR (PAG)
        errs() << "[SVF-LTO] Step 2: Building PAG...\n";
        SVFIRBuilder builder;
        SVFIR* pag = builder.build();
        
        auto t2 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff2 = t2 - t1;
        errs() << "[SVF-LTO] Done building PAG in " << diff2.count() << "s. Total Nodes: " << pag->getTotalNodeNum() << "\n";

        // 3. Run Andersen's Pointer Analysis
        errs() << "[SVF-LTO] Step 3: Running AndersenWaveDiff...\n";
        Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
        ander->analyze();
        
        auto t3 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff3 = t3 - t2;
        errs() << "[SVF-LTO] Analysis Done in " << diff3.count() << "s\n";

        // 4. Scan for __svf_check_alias calls
        // Since we are running at LTO time, all checks from all crates should be present.
        int checkCount = 0;
        for (Function &F : M) {
            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                        Function *CalledFn = CI->getCalledFunction();
                        if (CalledFn && CalledFn->getName() == "__svf_check_alias") {
                            // Signature: void __svf_check_alias(i8* p, i8* q, i32 id)
                            if (CI->arg_size() < 3) continue;

                            Value *P = CI->getArgOperand(0);
                            Value *Q = CI->getArgOperand(1);
                            
                            // Get ID (Argument 2)
                            uint64_t ID = 0;
                            if (ConstantInt *C = dyn_cast<ConstantInt>(CI->getArgOperand(2))) {
                                ID = C->getZExtValue();
                            }

                            // Query SVF
                            // We need NodeIDs for P and Q
                            NodeID pId = LLVMModuleSet::getLLVMModuleSet()->getValueNode(P);
                            NodeID qId = LLVMModuleSet::getLLVMModuleSet()->getValueNode(Q);
                            
                            // Check Alias
                            AliasResult res = ander->alias(pId, qId);
                            bool isAlias = (res != NoAlias);

                            // Output Result (Stdout for now, maybe file later)
                            // Format: ID:<id> RES:<1|0>
                            outs() << "ID:" << ID << " RES:" << (isAlias ? "1" : "0") << "\n";
                            checkCount++;
                        }
                    }
                }
            }
        }

        errs() << "[SVF-LTO] Processed " << checkCount << " alias checks.\n";

        // Cleanup
        // In a real plugin we might want to keep generic graphs, but here we are done.
        // LLVMModuleSet::releaseLLVMModuleSet(); 

        return PreservedAnalyses::all();
    }
};

// -----------------------------------------------------------------------------
// Plugin Registration
// -----------------------------------------------------------------------------
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "SvfLtoPlugin", "v0.1",
    [](PassBuilder &PB) {
      // Automatically register into the LTO pipeline
      PB.registerFullLinkTimeOptimizationLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel Level) {
            MPM.addPass(SvfLtoPass());
        }
      );
    }
  };
}
