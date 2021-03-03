/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>
#include "llvm/Config/llvm-config.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif

#include <set>
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class FuncLogInstructions : public ModulePass {

 public:
  static char ID;
  FuncLogInstructions() : ModulePass(ID) {

    initInstrumentList();

  }

  bool runOnModule(Module &M) override;

#if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {

#else
  StringRef getPassName() const override {

#endif
    return "func logging instructions";

  }

 private:
  bool hookInstrs(Module &M);

};

}  // namespace

char FuncLogInstructions::ID = 0;

bool FuncLogInstructions::hookInstrs(Module &M) {

  
  LLVMContext &              C = M.getContext();

  Type *       VoidTy = Type::getVoidTy(C);
  //IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  //IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  //IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      cmplogfunc = M.getOrInsertFunction("__func_log_hook", VoidTy, Int32Ty, Int32Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns = cast<Function>(cmplogfunc);
#else
  FunctionCallee cmplogHookIns = cmplogfunc;
#endif

  unsigned int func_id = 0;
  unsigned int cmp_id = 0;
  std::ofstream func;
  func.open("afl_func_id" , std::ofstream::out | std::ofstream::trunc);

  std::vector<unsigned int> func_cmp;
  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F)) continue;

    std::vector<Instruction *> icomps;

    //func << func_id << "," << F.getName().data() << "\n";
    
    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() == CmpInst::ICMP_EQ ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_NE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_UGT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SGT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_ULT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SLT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_UGE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SGE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_ULE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SLE) {

            icomps.push_back(selectcmpInst);

          }

        }

      }

    }

    for (auto &selectcmpInst : icomps) {
      Instruction * InsertPoint = selectcmpInst->getNextNode();
      if (!InsertPoint || isa<ConstantInt>(selectcmpInst)) {
        errs() << "Warn: Can't get cmp insert\n";
        continue;
      }

      //errs() << "cmp instr : " << *selectcmpInst << "\n";

      IRBuilder<> IRB(InsertPoint);

      //auto op0 = selectcmpInst->getOperand(0);
      //auto op1 = selectcmpInst->getOperand(1);

      Type::TypeID InstrTypeId = selectcmpInst->getType()->getTypeID();

      //There are some vector cmp instructions...
      //TODO : divide vector cmps to scalar ones.
      if (InstrTypeId == Type::TypeID::FixedVectorTyID) {
        continue;
      } 

      std::vector<Value *> args;
      auto arg1_cmpid = ConstantInt::get(Int32Ty, cmp_id);
      auto arg2_condition = IRB.CreateZExt(selectcmpInst, Int32Ty);
      //auto arg3_func_id = ConstantInt::get(Int32Ty, func_id);

      args.push_back(arg1_cmpid);
      args.push_back(arg2_condition);
      //args.push_back(arg3_func_id);

      IRB.CreateCall(cmplogHookIns, args);

      cmp_id ++;
    }

    if (icomps.size() == 0) continue;

    func_cmp.push_back(cmp_id);

    func_id ++;
  }

  func << func_id << "," << cmp_id << "\n";
  for (auto iter = func_cmp.begin() ; iter != func_cmp.end(); iter++) {
    func << *iter << "\n";
  }

  func.close();

  errs() << "Hooking " << cmp_id << " cmp instructions (func rel mode)\n";

  return true;

}

bool FuncLogInstructions::runOnModule(Module &M) {

  if (getenv("AFL_QUIET") == NULL)
    llvm::errs()
        << "Running func-log-pass\n";
  else
    be_quiet = 1;
  hookInstrs(M);
  verifyModule(M);

  return true;

}

static void registerFuncLogInstructionspass(const PassManagerBuilder &,
                                             legacy::PassManagerBase &PM) {

  PM.add(new FuncLogInstructions());

}

static RegisterStandardPasses RegisterFuncLogInstructionspass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    registerFuncLogInstructionspass);

static RegisterStandardPasses RegisterFuncLogInstructionspass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    registerFuncLogInstructionspass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterFuncLogInstructionspassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerFuncLogInstructionspass);
#endif