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

using namespace SVF;
using namespace llvm;

#include "z3++.h"
#include "llvm/Analysis/ValueTracking.h"

static void buildSVFModule(Module& M)
{
    errs() << "[SVF-LTO] Step 1: Building SVF Module...\n";
    errs() << "[SVF-LTO] Probing Z3 Initialization...\n";
    try {
        z3::context ctx;
        errs() << "[SVF-LTO] Z3 Context Created Successfully.\n";
    } catch (...) {
        errs() << "[SVF-LTO] Z3 Context Creation Failed.\n";
    }
    
    // FIX: Rust's LTO context discards value names by default, which breaks SVF's extapi loading.
    M.getContext().setDiscardValueNames(false);
    LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
}

// Helper to strip casts (ptrtoint, bitcast)
static Value* stripCasts(Value* V) {
    if (auto *Op = llvm::dyn_cast<llvm::Operator>(V)) {
        if (Op->getOpcode() == Instruction::PtrToInt || Op->getOpcode() == Instruction::BitCast) {
            // errs() << "Stripping cast: " << *V << "\n";
            return stripCasts(Op->getOperand(0));
        }
    }
    return V;
}

// -----------------------------------------------------------------------------
// SVF LTO Pass
// -----------------------------------------------------------------------------
struct SvfLtoPass : public PassInfoMixin<SvfLtoPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &FAM) {
        errs() << "\n[SVF-LTO] Starting In-Process Analysis...\n";
        errs() << "[SVF-LTO] Module: " << M.getModuleIdentifier() << "\n";

        auto start = std::chrono::high_resolution_clock::now();

        // 1. Build SVF Module from In-Memory LLVM Module
        buildSVFModule(M);
        
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
        errs() << "[SVF-LTO] Returned from ander->analyze()\n";
        
        auto t3 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff3 = t3 - t2;
        errs() << "[SVF-LTO] Analysis Done in " << diff3.count() << "s\n";

        // 4. Scan for __svf_check_alias calls
        errs() << "[SVF-LTO] Step 4: Scanning for instrumentation...\n";
        // Since we are running at LTO time, all checks from all crates should be present.
        int checkCount = 0;
        for (Function &F : M) {
            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    if (CallInst *CI = llvm::dyn_cast<CallInst>(&I)) {
                        Function *CalledFn = CI->getCalledFunction();
                        if (CalledFn && CalledFn->getName() == "__svf_check_alias") {
                            // Signature: void __svf_check_alias(i8* p, i8* q, i32 id)
                            if (CI->arg_size() < 3) continue;

                            Value *P = stripCasts(CI->getArgOperand(0));
                            Value *Q = stripCasts(CI->getArgOperand(1));
                            
                            // Get ID (Argument 2)
                            uint64_t ID = 0;
                            if (ConstantInt *C = llvm::dyn_cast<ConstantInt>(CI->getArgOperand(2))) {
                                ID = C->getZExtValue();
                            }

                            // Query SVF
                            // We need NodeIDs for P and Q
                            NodeID pId = LLVMModuleSet::getLLVMModuleSet()->getValueNode(P);
                            NodeID qId = LLVMModuleSet::getLLVMModuleSet()->getValueNode(Q);

                            // Fallback: If NodeID is 0 (missing), try underlying object (conservative)
                            if (pId == 0) {
                                Value* pBase = getUnderlyingObject(P);
                                if (pBase && pBase != P) {
                                     pId = LLVMModuleSet::getLLVMModuleSet()->getValueNode(pBase);
                                     if (pId != 0) {
                                         errs() << "[SVF-LTO-DEBUG] Resolved P (GEP/Optimized) to Base: " << *pBase << " (NodeID: " << pId << ")\n";
                                     }
                                }
                            }
                            if (qId == 0) {
                                Value* qBase = getUnderlyingObject(Q);
                                if (qBase && qBase != Q) {
                                     qId = LLVMModuleSet::getLLVMModuleSet()->getValueNode(qBase);
                                     if (qId != 0) {
                                         errs() << "[SVF-LTO-DEBUG] Resolved Q (GEP/Optimized) to Base: " << *qBase << " (NodeID: " << qId << ")\n";
                                     }
                                }
                            }
                            
                            // Check Alias
                            // If still 0, we treat as NoAlias (or could treat as MayAlias if strict safety needed)
                            AliasResult res = NoAlias;
                            if (pId != 0 && qId != 0) {
                                res = ander->alias(pId, qId);
                            } else {
                                errs() << "[SVF-LTO-DEBUG] WARNING: Could not resolve NodeID for P or Q. Assuming NoAlias (Unsafe?).\n";
                                if (pId == 0) errs() << "  Missing P: " << *P << "\n";
                                if (qId == 0) errs() << "  Missing Q: " << *Q << "\n";
                            }

                            bool isAlias = (res != NoAlias);

                            // Output Result (Stdout for now, maybe file later)
                            // Format: ID:<id> RES:<1|0>
                            // outs() << "ID:" << ID << " RES:" << (isAlias ? "1" : "0") << "\n";

                            // Inject Analysis Result into ID (Argument 2)
                            // Top bit (31) = 1 if Alias (Predicted), 0 if NoAlias
                            if (isAlias) {
                                uint32_t newID = (uint32_t)ID | (1 << 31);
                                CI->setArgOperand(2, ConstantInt::get(Type::getInt32Ty(M.getContext()), newID));
                            } else {
                                // Ensure top bit is 0 just in case (though likely already is)
                                // If the ID uses top bit, we are in trouble, but assuming standard u32 IDs.
                                uint32_t newID = (uint32_t)ID & ~(1 << 31);
                                CI->setArgOperand(2, ConstantInt::get(Type::getInt32Ty(M.getContext()), newID));
                            }

                            // Debugging Info
                            errs() << "[SVF-LTO-DEBUG] Check #" << checkCount << " in " << CI->getFunction()->getName() << "\n";
                            errs() << "  P: " << *P << " (NodeID: " << pId << ")\n";
                            errs() << "  Q: " << *Q << " (NodeID: " << qId << ")\n";
                            if (pId != 0 && qId != 0) {
                                const PointsTo& ptsP = ander->getPts(pId);
                                const PointsTo& ptsQ = ander->getPts(qId);
                                errs() << "  PTS(P) Size: " << ptsP.count() << "\n";
                                errs() << "  PTS(Q) Size: " << ptsQ.count() << "\n";
                                
                                if (ptsP.empty() || ptsQ.empty()) {
                                    errs() << "  [WARNING] One or more points-to sets are empty!\n";
                                }
                            }

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
      // And standard pipeline (for non-LTO testing / debugging)
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel Level) {
            errs() << "[SVF-LTO] OptimizerLast Callback triggered.\n";
            // MPM.addPass(SvfLtoPass());
        }
      );
    }
  };
}
