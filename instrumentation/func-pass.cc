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
  void Insert_magicbyte_hook(Instruction * IN, Instruction * insertPoint, unsigned int rec);
  FunctionCallee magicbytesHookptr;
};

}  // namespace

char FuncLogInstructions::ID = 0;

void FuncLogInstructions::Insert_magicbyte_hook(Instruction * IN, Instruction * insertPoint, unsigned int rec) {
  
  GetElementPtrInst * gepIN = NULL;

  if (rec == 0) return;

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
    return;
  }

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

bool FuncLogInstructions::hookInstrs(Module &M) {

  LLVMContext &              C = M.getContext();

  Type *       VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  //IntegerType *Int128Ty = IntegerType::getInt128Ty(C);
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

  FunctionCallee magicbytesHook8 = M.getOrInsertFunction("__magic_bytes_record_8", VoidTy, Int8Ty);
  FunctionCallee magicbytesHook16 = M.getOrInsertFunction("__magic_bytes_record_16", VoidTy, Int16Ty);
  FunctionCallee magicbytesHook32 = M.getOrInsertFunction("__magic_bytes_record_32", VoidTy, Int32Ty);
  FunctionCallee magicbytesHook64 = M.getOrInsertFunction("__magic_bytes_record_64", VoidTy, Int64Ty);
  //FunctionCallee magicbytesHook128 = M.getOrInsertFunction("__magic_bytes_record_128", VoidTy, Int128Ty);
  magicbytesHookptr = M.getOrInsertFunction("__magic_bytes_record_ptr", VoidTy, Int8PtrTy);
  FunctionCallee magicbytesHooknptr = M.getOrInsertFunction("__magic_bytes_record_nptr", VoidTy, Int8PtrTy, Int32Ty);
  
  FunctionCallee argvHook = M.getOrInsertFunction("__afl_parse_argv", VoidTy, Int32PtrTy, Int8PtrPtrPtrTy);
  FunctionCallee fopen_wrapperHook = M.getOrInsertFunction("__afl_fopen_wrapper", FileTy, Int8PtrTy, Int8PtrTy);
  FunctionCallee freopen_wrapperHook = M.getOrInsertFunction("__afl_freopen_wrapper", FileTy, Int8PtrTy, Int8PtrTy, FileTy);
  FunctionCallee open_wrapperHook = M.getOrInsertFunction("__afl_fopen_wrapper", Int32Ty, Int8PtrTy, Int32Ty, Int32Ty);

  unsigned int func_id = 0;
  unsigned int cmp_id = 0;
  
  std::vector<unsigned int> func_cmp;

  DenseMap<Value *, std::string *> valueMap;

  char argv_mut = 0;

  if (getenv("AFL_ARGV") != NULL) argv_mut = 1;

  std::ofstream func2;
  func2.open("FRIEND_getopt_info" , std::ofstream::out | std::ofstream::trunc);

  for (auto &F : M) {

    if (!isInInstrumentList(&F)) continue;

    if (!F.getName().str().compare(0,5, "__afl")) continue;
    if (!F.getName().str().compare(0,7, "__magic")) continue;
    if (!F.getName().str().compare(0,5, "__cmp")) continue;

    //func << func_id << "," << F.getName().data() << "\n";

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
        CallInst *callInst = nullptr;

        //Just check parameters...
        if (argv_mut) {
          Instruction * InsertPoint = IN.getNextNode();
          while (InsertPoint && dyn_cast<PHINode>(InsertPoint)) {
            InsertPoint = InsertPoint->getNextNode();
          }
          if (InsertPoint) {
            Insert_magicbyte_hook(&IN, InsertPoint, 3);
          }
        }
        
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

          //TODO : float
          CmpInst::Predicate pred = cmpInst->getPredicate();
          if (argv_mut && (pred == CmpInst::Predicate::ICMP_EQ || pred == CmpInst::Predicate::ICMP_NE) && cmpInst->getNumOperands() == 2) {
            Value * op1 = cmpInst->getOperand(0);
            Value * op2 = cmpInst->getOperand(1);
            ConstantInt * cop = dyn_cast<ConstantInt>(op1);
            if (cop == NULL) {
              cop = dyn_cast<ConstantInt>(op2);
            }

            if (cop != NULL) {
              std::vector<Value *> args2;
              switch(cop->getBitWidth()) {
                case 8:
                  args2.push_back((Value *) cop);
                  IRB.CreateCall(magicbytesHook8, args2);
                  break;
                case 16:
                  args2.push_back((Value *) cop);
                  IRB.CreateCall(magicbytesHook16, args2);
                  break;
                case 32:
                  args2.push_back((Value *) cop);
                  IRB.CreateCall(magicbytesHook32, args2);
                  break;
                case 64:
                  args2.push_back((Value *) cop);
                  IRB.CreateCall(magicbytesHook64, args2);
                  break;
                case 128:
                  errs() << "128 bit length : TODO\n";
                  break;
                default:
                  errs() << "Warn : unkonwn length constant\n";
                  break;
              }
            }
          }

          cmp_id ++;

        } else if (argv_mut && (callInst = dyn_cast<CallInst>(&IN))) {
          bool isStrcmp = true;
          bool isMemcmp = true;
          bool isStrncmp = true;
          bool isStrcasecmp = true;
          bool isStrncasecmp = true;
          bool isIntMemcpy = true;
          bool isGetOpt = true;
          bool isGetOptLong = true;
          bool isfopen = true;
          bool isfreopen = true;
          bool isopen = true;

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;

          if (!Callee->getName().str().compare(0,5, "__afl")) continue;
          if (!Callee->getName().str().compare(0,7, "__magic")) continue;
          if (!Callee->getName().str().compare(0,5, "__cmp")) continue;

          StringRef FuncName = Callee->getName();
          isStrcmp &= !FuncName.compare(StringRef("strcmp"));
          isMemcmp &= (!FuncName.compare(StringRef("memcmp")) ||
                       !FuncName.compare(StringRef("bcmp")));
          isStrncmp &= !FuncName.compare(StringRef("strncmp"));
          isStrcasecmp &= !FuncName.compare(StringRef("strcasecmp"));
          isStrncasecmp &= !FuncName.compare(StringRef("strncasecmp"));
          isIntMemcpy &= !FuncName.compare("llvm.memcpy.p0i8.p0i8.i64");
          isGetOpt &= !FuncName.compare(StringRef("getopt"));
          isGetOptLong &= !FuncName.compare(StringRef("getopt_long"));
          isfopen &= !FuncName.compare(StringRef("fopen"));
          isfreopen &= !FuncName.compare(StringRef("freopen"));
          isopen &= !FuncName.compare(StringRef("open"));

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy && !isGetOpt && !isGetOptLong && !isfopen && !isfreopen && !isopen) {
            continue;
          }

          /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp function
           * prototype */
          FunctionType *FT = Callee->getFunctionType();

          isStrcmp &=
              FT->getNumParams() == 2 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) == IntegerType::getInt8PtrTy(M.getContext());
          isStrcasecmp &=
              FT->getNumParams() == 2 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) == IntegerType::getInt8PtrTy(M.getContext());
          isMemcmp &= FT->getNumParams() == 3 &&
                      FT->getReturnType()->isIntegerTy(32) &&
                      FT->getParamType(0)->isPointerTy() &&
                      FT->getParamType(1)->isPointerTy() &&
                      FT->getParamType(2)->isIntegerTy();
          isStrncmp &= FT->getNumParams() == 3 &&
                       FT->getReturnType()->isIntegerTy(32) &&
                       FT->getParamType(0) == FT->getParamType(1) &&
                       FT->getParamType(0) ==
                           IntegerType::getInt8PtrTy(M.getContext()) &&
                       FT->getParamType(2)->isIntegerTy();
          isStrncasecmp &= FT->getNumParams() == 3 &&
                           FT->getReturnType()->isIntegerTy(32) &&
                           FT->getParamType(0) == FT->getParamType(1) &&
                           FT->getParamType(0) ==
                               IntegerType::getInt8PtrTy(M.getContext()) &&
                           FT->getParamType(2)->isIntegerTy();
          isGetOpt &= FT->getNumParams() == 3 &&
                      FT->getReturnType()->isIntegerTy(32) &&
                      FT->getParamType(0)->isIntegerTy(32) &&
                      FT->getParamType(1)->isPointerTy() &&
                      FT->getParamType(2)->isPointerTy();

          isGetOptLong &= FT->getNumParams() == 5 &&
                          FT->getReturnType()->isIntegerTy(32) &&
                          FT->getParamType(0)->isIntegerTy(32) &&
                          FT->getParamType(1)->isPointerTy() &&
                          FT->getParamType(2)->isPointerTy() &&
                          FT->getParamType(3)->isPointerTy() &&
                          FT->getParamType(4)->isPointerTy();
          isfopen &= FT->getNumParams() == 2 &&
                     FT->getReturnType()->isPointerTy() &&
                     FT->getParamType(0)->isPointerTy() &&
                     FT->getParamType(1)->isPointerTy();
          
          isfreopen &= FT->getNumParams() == 3 &&
                       FT->getReturnType()->isPointerTy() &&
                       FT->getParamType(0)->isPointerTy() &&
                       FT->getParamType(1)->isPointerTy() &&
                       FT->getParamType(2)->isPointerTy();
          isopen &= FT->getNumParams() == 3 &&
                    FT->getReturnType()->isIntegerTy(32) &&
                    FT->getParamType(0)->isPointerTy() &&
                    FT->getParamType(1)->isIntegerTy(32) &&
                    FT->getParamType(2)->isIntegerTy(32);

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy && !isGetOptLong && !isfopen && !isfreopen && !isopen) {
            //just check arguments
          }

          
          if (isGetOpt || isGetOptLong) {
            Value * StrP = callInst->getArgOperand(2);
            StringRef OptStr;
            bool HasStr = getConstantStringInfo(StrP, OptStr);
            if (!HasStr) {
              errs() << "Warn : Can't get string of getopt";
              continue;
            }

            for (auto iter = OptStr.begin(); iter != OptStr.end(); iter++) {
              switch (*iter) {
                case '-':
                case ':':
                case '+':
                  continue;
                default:
                  func2 << "-" << *iter << "\n";
              }
            }

            if (isGetOptLong) {
              Value * optionstruct = callInst->getArgOperand(3);
              ConstantExpr * ce_optionstruct = dyn_cast<ConstantExpr>(optionstruct);

              //TODO!

              if (ce_optionstruct && ce_optionstruct->isGEPWithNoNotionalOverIndexing()) {
                ce_optionstruct->printAsOperand(errs());
                errs() << "\n";
                ce_optionstruct->getType()->print(errs());
                errs() << " \n";
                errs() << dyn_cast<Instruction>(optionstruct) << "\n";

              } else {
                errs() << "Warn : Can't get option string\n"; 
              }
            }

            continue;
          }

          if (isfopen) {
            callInst->setCalledFunction(fopen_wrapperHook);
            continue;
          } else if (isfreopen) {
            callInst->setCalledFunction(freopen_wrapperHook);
            continue;
          } else if (isopen) {
            callInst->setCalledFunction(open_wrapperHook);
            continue;
          }

          Value *Str1P = callInst->getArgOperand(0),
                *Str2P = callInst->getArgOperand(1);
          StringRef Str1, Str2;
          bool      HasStr1 = getConstantStringInfo(Str1P, Str1);
          bool      HasStr2 = getConstantStringInfo(Str2P, Str2);

          if (isIntMemcpy && HasStr2) {

            valueMap[Str1P] = new std::string(Str2.str());
            // fprintf(stderr, "saved %s for %p\n", Str2.str().c_str(), Str1P);
            continue;

          }

          // not literal? maybe global or local variable
          if (!(HasStr1 || HasStr2)) {

            auto *Ptr = dyn_cast<ConstantExpr>(Str2P);
            if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

              if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                if (Var->hasInitializer()) {

                  if (auto *Array =
                          dyn_cast<ConstantDataArray>(Var->getInitializer())) {

                    HasStr2 = true;
                    Str2 = Array->getAsString();
                    valueMap[Str2P] = new std::string(Str2.str());
                    fprintf(stderr, "glo2 %s\n", Str2.str().c_str());

                  }

                }

              }

            }

            if (!HasStr2) {

              Ptr = dyn_cast<ConstantExpr>(Str1P);
              if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

                if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                  if (Var->hasInitializer()) {

                    if (auto *Array = dyn_cast<ConstantDataArray>(
                            Var->getInitializer())) {

                      HasStr1 = true;
                      Str1 = Array->getAsString();
                      valueMap[Str1P] = new std::string(Str1.str());
                      // fprintf(stderr, "glo1 %s\n", Str1.str().c_str());

                    }

                  }

                }

              }

            } else if (isIntMemcpy) {

              valueMap[Str1P] = new std::string(Str2.str());
              // fprintf(stderr, "saved\n");

            }

          }

          if (isIntMemcpy) continue;

          if (!(HasStr1 || HasStr2)) {

            // do we have a saved local variable initialization?
            std::string *val = valueMap[Str1P];
            if (val && !val->empty()) {

              Str1 = StringRef(*val);
              HasStr1 = true;
              // fprintf(stderr, "loaded1 %s\n", Str1.str().c_str());

            } else {

              val = valueMap[Str2P];
              if (val && !val->empty()) {

                Str2 = StringRef(*val);
                HasStr2 = true;
                // fprintf(stderr, "loaded2 %s\n", Str2.str().c_str());

              }

            }

          }

          /* handle cases of one string is const, one string is variable */
          if (!(HasStr1 || HasStr2)) continue;

          if (isMemcmp || isStrncmp || isStrncasecmp) {

            /* check if third operand is a constant integer
             * strlen("constStr") and sizeof() are treated as constant */
            Value *      op2 = callInst->getArgOperand(2);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
            if (ilen) {

              uint64_t len = ilen->getZExtValue();
              // if len is zero this is a pointless call but allow real
              // implementation to worry about that
              if (!len) continue;

              if (isMemcmp) {

                // if size of compare is larger than constant string this is
                // likely a bug but allow real implementation to worry about
                // that
                uint64_t literalLength = HasStr1 ? Str1.size() : Str2.size();
                if (literalLength + 1 < ilen->getZExtValue()) continue;

              }

            } else if (isMemcmp) {
              // this *may* supply a len greater than the constant string at
              // runtime so similarly we don't want to have to handle that
              continue;
            }

          }

          Instruction * InsertPoint = callInst->getNextNode();
          if (!InsertPoint) {
            errs() << "Warn: Can't get call insert\n";
            continue;
          }

          //errs() << "cmp instr : " << *cmpInst << "\n";

          IRBuilder<> IRB(InsertPoint);
          std::vector<Value *> args;
          if (HasStr1) {
            args.push_back(Str1P);
          } else {
            args.push_back(Str2P);
          }

          if (isStrcmp || isMemcmp || isStrcasecmp) {
            IRB.CreateCall(magicbytesHookptr, args);
          } else if (isStrncmp || isStrncasecmp) {
            Value * op2 = callInst->getArgOperand(2);
            ConstantInt *cop2 = dyn_cast<ConstantInt>(op2);
            if (cop2) {
              if (cop2->getBitWidth() == 32) {
                args.push_back(op2);
              } else {
                uint32_t len = (uint32_t) cop2->getZExtValue();
                args.push_back(ConstantInt::get(Int32Ty, len));
              }
              IRB.CreateCall(magicbytesHooknptr, args);
            }
          }
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
