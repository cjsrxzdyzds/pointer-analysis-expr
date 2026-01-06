#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "SVF-LLVM/LLVMModule.h"
#include "WPA/Andersen.h"
#include "Util/Options.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"

using namespace llvm;
using namespace std;
using namespace SVF;

int main(int argc, char **argv) {
    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(argc, argv, "SVF Static Checker", "[options] <input-bitcode...>");

    if (moduleNameVec.empty()) {
        outs() << "Please provide an input bitcode file.\n";
        return 1;
    }

    // 1. Build SVF Module (loads bitcode)
    LLVMModuleSet* moduleSet = LLVMModuleSet::getLLVMModuleSet();
    moduleSet->buildSVFModule(moduleNameVec);

    // 2. Build SVFIR (Program Assignment Graph)
    SVFIRBuilder builder;
    SVFIR* pag = builder.build();

    // 3. Run Andersen's Pointer Analysis
    AndersenWaveDiff* ander = new AndersenWaveDiff(pag);
    ander->analyze();

    outs() << "SVF Analysis Done. Checking instrumentation points...\n";

    // 4. Iterate over the module to find __svf_check_alias calls
    // We assume there's one module loaded
    Module* mod = moduleSet->getModule(0); 

    // Find the function declaration for __svf_check_alias to easily identify calls
    Function* checkFn = mod->getFunction("__svf_check_alias");
    if (!checkFn) {
        outs() << "Warning: __svf_check_alias function not found in bitcode. Is it instrumented?\n";
        return 0;
    }

    for (Function& F : *mod) {
        for (BasicBlock& BB : F) {
            for (Instruction& I : BB) {
                if (CallInst* CI = dyn_cast<CallInst>(&I)) {
                    if (CI->getCalledFunction() == checkFn) {
                        // Signature: void __svf_check_alias(i8* p, i8* q, i32 id)
                        Value* argP = CI->getArgOperand(0);
                        Value* argQ = CI->getArgOperand(1);
                        Value* argID = CI->getArgOperand(2);

                        // Extract ID
                        uint64_t idVal = 0;
                        if (ConstantInt* C = dyn_cast<ConstantInt>(argID)) {
                            idVal = C->getZExtValue();
                        } else {
                            // Should likely be a constant, but handle dynamic just in case (skip or log)
                            continue;
                        }

                        // Resolve SVF Nodes
                        NodeID nodeP = moduleSet->getValueNode(argP);
                        NodeID nodeQ = moduleSet->getValueNode(argQ);

                        // Query Alias
                        AliasResult res = ander->alias(nodeP, nodeQ);
                        
                        // Output in format: ID:<id> RES:<1|0>
                        // SVF AliasResult: NoAlias, MayAlias, MustAlias.
                        // We map NoAlias -> 0, May/Must -> 1.
                        int isAlias = (res != AliasResult::NoAlias) ? 1 : 0;
                        
                        outs() << "ID:" << idVal << " RES:" << isAlias << "\n";
                    }
                }
            }
        }
    }

    // Cleanup
    delete ander;
    SVFIR::releaseSVFIR();
    SVF::LLVMModuleSet::releaseLLVMModuleSet();
    llvm::llvm_shutdown();

    return 0;
}
