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
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
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
  void Insert_magicbyte_hook(Instruction * IN, Instruction * insertPoint);
  FunctionCallee magicbytesHookptr;
};

}  // namespace

char FuncLogInstructions::ID = 0;

void FuncLogInstructions::Insert_magicbyte_hook(Instruction * IN, Instruction * insertPoint) {
  
  GetElementPtrInst * gepIN = NULL;
  PHINode * phiIN = NULL;

  //blacklist
  CallInst * callIN = NULL;

  if ((callIN = dyn_cast<CallInst>(IN))) {
    Function *Callee = callIN->getCalledFunction();
    if (!Callee) return;
    if (callIN->getCallingConv() != llvm::CallingConv::C) return;
    if (!Callee->getName().str().compare(0,5, "__afl")) return;
    if (!Callee->getName().str().compare(0,7, "__magic")) return;
    if (!Callee->getName().str().compare(0,5, "__cmp")) return;
    if (!Callee->getName().str().compare(0,4, "llvm")) return;
    if (!isInInstrumentList(Callee)) return;
    if (!Callee->getName().str().compare("malloc")) return;
  }

  if ((gepIN = dyn_cast<GetElementPtrInst>(IN)) && (gepIN->getNumOperands() > 2)) {
    Type * pointerTy = gepIN->getType();
    if (pointerTy->getPointerElementType()->isIntegerTy(8)) {
      Value * idx = gepIN->getOperand(2);
      ConstantInt * cidx;
      if ((cidx = dyn_cast<ConstantInt>(idx)) && (cidx->getZExtValue() == 0)) {
        IRBuilder<> IRB(insertPoint);
        std::vector<Value *> args;
        args.push_back(IN);
        IRB.CreateCall(magicbytesHookptr, args);
      }
    }
  } else if ((phiIN = dyn_cast<PHINode>(IN))) {
    Type * pointerTy = phiIN->getType();
    if (pointerTy->isPointerTy() && pointerTy->getPointerElementType()->isIntegerTy(8)) {
      IRBuilder<> IRB(insertPoint);
      std::vector<Value *> args;
      args.push_back(IN);
      IRB.CreateCall(magicbytesHookptr, args);
    }
  } else {
    for (auto iter = IN->op_begin(); iter != IN->op_end(); iter++) {
      Value * parm = iter->get();

      GEPOperator * parmop = NULL;
      if ((parmop = dyn_cast<GEPOperator>(parm)) && (parmop->getNumOperands() > 2)) {
        Type * pointerTy = parmop->getType();
        if (pointerTy->getPointerElementType()->isIntegerTy(8)) {
          Value * idx = parmop->getOperand(2);
          ConstantInt * cidx;
          if ((cidx = dyn_cast<ConstantInt>(idx)) && (cidx->getZExtValue() == 0)) {
            IRBuilder<> IRB(insertPoint);
            std::vector<Value *> args;
            args.push_back(parm);
            IRB.CreateCall(magicbytesHookptr, args);
          }
        }
      }
    }
  }
}

bool FuncLogInstructions::hookInstrs(Module &M) {

  LLVMContext &              C = M.getContext();

  Type *       VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  PointerType * Int8PtrTy = PointerType::get(Int8Ty, 0);
  PointerType * Int8PtrPtrTy = PointerType::get(Int8PtrTy, 0);
  PointerType * Int8PtrPtrPtrTy = PointerType::get(Int8PtrPtrTy, 0);
  PointerType * Int32PtrTy = PointerType::get(Int32Ty, 0);

  Type * FileTy = NULL;
  for (auto &GT : M.getGlobalList()) {
    if (GT.getName().str() == "stderr") {
      FileTy = GT.getType()->getPointerElementType();
    }
  }

  if (FileTy == nullptr) {
    errs() << "Can't find IO_FILE type! Abort.\n";
    return false;
  }

  
  FunctionCallee cmplogHookIns = M.getOrInsertFunction("__cmp_log_hook", VoidTy, Int32Ty, Int32Ty, Int32Ty);

  FunctionCallee argvHook = M.getOrInsertFunction("__afl_parse_argv", VoidTy, Int32PtrTy, Int8PtrPtrPtrTy);
  Value * fopen_wrapperHook = M.getOrInsertFunction("__afl_fopen_wrapper", FileTy, Int8PtrTy, Int8PtrTy).getCallee();
  Value * freopen_wrapperHook = M.getOrInsertFunction("__afl_freopen_wrapper", FileTy, Int8PtrTy, Int8PtrTy, FileTy).getCallee();
  std::vector<Type *> parm_types;
  parm_types.push_back(Int8PtrTy);
  parm_types.push_back(Int32Ty);
  FunctionType * open_ft = FunctionType::get(Int32Ty, parm_types, true);
  Value * open_wrapperHook = M.getOrInsertFunction("__afl_open_wrapper", open_ft).getCallee();
  Value * creat_wrapperHook = M.getOrInsertFunction("__afl_creat_wrapper", Int32Ty, Int8PtrTy, Int32Ty).getCallee();

  unsigned int func_id = 0;
  unsigned int cmp_id = 0;
  
  std::vector<unsigned int> func_cmp;

  DenseMap<Value *, std::string *> valueMap;

  char argv_mut = 0;

  if (getenv("AFL_ARGV") != NULL) argv_mut = 1;

  std::ofstream func2;
  func2.open("FRIEND_func_info" , std::ofstream::out | std::ofstream::trunc);

  for (auto &F : M) {

    if (F.getName().equals(StringRef("open"))) {
      errs() << "found open\n";
      FunctionType * ft = F.getFunctionType();
      errs() << "num parames : " << ft->getNumParams() << "\n";
      if (ft->getNumParams() >= 2 &&
          ft->getReturnType()->isIntegerTy(32) &&
          ft->getParamType(0)->isPointerTy() &&
          ft->getParamType(1)->isIntegerTy(32)) {
        fprintf(stderr, "replacing open\n");
        F.replaceAllUsesWith(open_wrapperHook);
        continue;
      }
    } else if (F.getName().equals(StringRef("fopen"))) {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 2 &&
          ft->getReturnType()->isPointerTy() &&
          ft->getParamType(0)->isPointerTy() &&
          ft->getParamType(1)->isPointerTy()) {
        fprintf(stderr, "replacing fopen\n");
        F.replaceAllUsesWith(fopen_wrapperHook);
        continue;
      }
    } else if (F.getName().equals(StringRef("freopen"))) {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 3 &&
        ft->getReturnType()->isPointerTy() &&
        ft->getParamType(0)->isPointerTy() &&
        ft->getParamType(1)->isPointerTy() &&
        ft->getParamType(2)->isPointerTy()) {
        F.replaceAllUsesWith(freopen_wrapperHook);
        continue;
      }
    } else if (F.getName().equals(StringRef("creat"))) {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 2 &&
      ft->getReturnType()->isIntegerTy(32) &&
      ft->getParamType(0)->isPointerTy() &&
      ft->getParamType(1)->isIntegerTy(32)) {
        F.replaceAllUsesWith(creat_wrapperHook);
        continue;
      }
    }

    if (!isInInstrumentList(&F)) continue;

    if (!F.getName().str().compare(0,5, "__afl")) continue;
    if (!F.getName().str().compare(0,5, "__cmp")) continue;

    func2 << func_id << "," << F.getName().data() << "\n";

    if (argv_mut && F.getName().equals(StringRef("main"))) {
      BasicBlock & entryblock = F.getEntryBlock();
      IRBuilder<> IRB(&(*entryblock.begin()));
      Value * argc = F.getArg(0);
      Value * argv = F.getArg(1);
      AllocaInst * argc_ptr = IRB.CreateAlloca(Int32Ty);
      AllocaInst * argv_ptr = IRB.CreateAlloca(Int8PtrPtrTy);

      std::vector<Value *> args;
      args.push_back(argc_ptr);
      args.push_back(argv_ptr);

      CallInst * argv_call = IRB.CreateCall(argvHook, args);
      Value * new_argc = IRB.CreateLoad(argc_ptr);
      Value * new_argv = IRB.CreateLoad(argv_ptr);

      argc->replaceAllUsesWith(new_argc);
      argv->replaceAllUsesWith(new_argv);

      IRB.SetInsertPoint(argv_call);

      IRB.CreateStore(argc, argc_ptr);
      IRB.CreateStore(argv, argv_ptr);
    }

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *cmpInst = nullptr;
        
        if ((cmpInst = dyn_cast<CmpInst>(&IN))) {

          Instruction * InsertPoint = cmpInst->getNextNode();
          if (!InsertPoint || isa<ConstantInt>(cmpInst)) {
            errs() << "Warn: Can't get cmp insert\n";
            continue;
          }

          //errs() << "cmp instr : " << *cmpInst << "\n";

          IRBuilder<> IRB(InsertPoint);

          //auto op0 = cmpInst->getOperand(0);
          //auto op1 = cmpInst->getOperand(1);

          Type::TypeID InstrTypeId = cmpInst->getType()->getTypeID();

          //There are some vector cmp instructions...
          //TODO : divide vector cmps to scalar ones.
          if (InstrTypeId == Type::TypeID::FixedVectorTyID) {
            continue;
          } 

          Value * operand1 = cmpInst->getOperand(0);
          Value * operand2 = cmpInst->getOperand(1);

          std::vector<Value *> args;
          Value * arg1_cmpid = ConstantInt::get(Int32Ty, cmp_id);
          Value * arg2_condition = IRB.CreateZExt(cmpInst, Int32Ty);
          Value * arg3_value = operand1;

          if ((dyn_cast<Constant> (operand1))) {
            arg3_value = operand2;
          }

          if(arg3_value->getType()->getTypeID() != Type::TypeID::IntegerTyID) {
            arg3_value = ConstantInt::get(Int32Ty, 0);
          } else if (arg3_value->getType()->getScalarSizeInBits() > 32) {
            arg3_value = IRB.CreateTrunc(arg3_value, Int32Ty);
          } else if (arg3_value->getType()->getScalarSizeInBits() < 32) {
            arg3_value = IRB.CreateZExt(arg3_value, Int32Ty);
          }

          args.push_back(arg1_cmpid);
          args.push_back(arg2_condition);          
          args.push_back(arg3_value);

          IRB.CreateCall(cmplogHookIns, args);

          cmp_id ++;

        }
      }
    }

    func_cmp.push_back(cmp_id);

    func_id ++;
    
  }

  func2.close();

  std::ofstream func;
  func.open("FRIEND_func_cmp_id_info" , std::ofstream::out | std::ofstream::trunc);

  func << func_id << "," << cmp_id << "\n";
  for (auto iter = func_cmp.begin() ; iter != func_cmp.end(); iter++) {
    func << *iter << "\n";
  }

  func.close();

  errs() << "Hooking " << cmp_id << " cmp instructions (func rel mode)\n";

  if (getenv("AFL_PRINT_IR") != NULL) {
    std::error_code Errinfo;
    raw_fd_ostream result_ir("FRIEND_result.ir", Errinfo, sys::fs::OpenFlags::OF_Text);

    func_id = 0;
    cmp_id = 0;

    result_ir << "Global table \n";

    for (auto &GT : M.getGlobalList()) {
      result_ir << GT << "\n";
    }

    result_ir << "IR : \n";

    for (auto &F : M) {
      if (!isInInstrumentList(&F)) { 
        continue;
      }

      std::vector<Instruction *> icomps;
      
      for (auto &BB : F) {
        for (auto &IN : BB) {
          CmpInst *selectcmpInst = nullptr;
          if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {
            icomps.push_back(selectcmpInst); 
          } 
        }
      }


      if (icomps.size() == 0) continue;
    
      const char * fname = F.getName().data();
      result_ir << "FUNCTION reading " << fname  << ":" << func_id << " ############\n"; 
      func_id ++;

      for (auto &BB : F) {
        result_ir << "BLOCK " <<  " *********************\n";
        for (auto &IN : BB) {
          DILocation * Loc = IN.getDebugLoc();
          result_ir << IN;
          if (Loc) {
            result_ir << " " << Loc->getFilename().str() << ":" << Loc->getLine();
          }

          CmpInst *selectcmpInst = nullptr;
          if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {
            Instruction * InsertPoint = selectcmpInst->getNextNode();
            if (!InsertPoint || isa<ConstantInt>(selectcmpInst)) {
              result_ir << "\n";
              continue;
            }

            Type::TypeID InstrTypeId = selectcmpInst->getType()->getTypeID();
            if (InstrTypeId == Type::TypeID::FixedVectorTyID) {
              result_ir << "\n";
              continue;
            }
    
            result_ir << " #### cmp id : " << cmp_id;
            cmp_id ++;
          }

          result_ir << "\n";
        }
      }
    }
    result_ir.close();
  }

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
