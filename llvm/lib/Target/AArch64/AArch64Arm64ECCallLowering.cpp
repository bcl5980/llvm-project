//===-- AArch64Arm64ECCallLowering.cpp - Lower Arm64EC calls ----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the IR transform to lower external or indirect calls for
/// the ARM64EC calling convention. Such calls must go through the runtime, so
/// we can translate the calling convention for calls into the emulator.
///
/// This subsumes Control Flow Guard handling.
///
//===----------------------------------------------------------------------===//

#include "AArch64.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Triple.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"

using namespace llvm;

using OperandBundleDef = OperandBundleDefT<Value *>;

#define DEBUG_TYPE "arm64eccalllowering"

STATISTIC(Arm64ECCallsLowered, "Number of Arm64EC calls lowered");

namespace {

class AArch64Arm64ECCallLowering : public FunctionPass {
public:
  static char ID;
  AArch64Arm64ECCallLowering() : FunctionPass(ID) {
    initializeAArch64Arm64ECCallLoweringPass(*PassRegistry::getPassRegistry());
  }

  Function *buildExitThunk(CallBase *CB);
  void lowerCall(CallBase *CB);
  bool doInitialization(Module &M) override;
  bool runOnFunction(Function &F) override;

private:
  int cfguard_module_flag = 0;
  FunctionType *GuardFnType = nullptr;
  PointerType *GuardFnPtrType = nullptr;
  Constant *GuardFnCFGlobal = nullptr;
  Constant *GuardFnGlobal = nullptr;
  Module *M = nullptr;
};

} // end anonymous namespace

Function *AArch64Arm64ECCallLowering::buildExitThunk(CallBase *CB) {
  Type *RetTy = CB->getFunctionType()->getReturnType();
  SmallVector<Type *> DefArgTypes;
  // The first argument to a thunk is the called function, stored in x9.
  // (Normally, we won't explicitly refer to this in the assembly; it just
  // gets passed on by the call.)
  DefArgTypes.push_back(Type::getInt8PtrTy(M->getContext()));
  for (unsigned i = 0; i < CB->arg_size(); ++i) {
    DefArgTypes.push_back(CB->getArgOperand(i)->getType());
  }
  FunctionType *Ty = FunctionType::get(RetTy, DefArgTypes, false);
  Function *F =
      Function::Create(Ty, GlobalValue::InternalLinkage, 0, "thunk", M);
  F->setCallingConv(CallingConv::ARM64EC_Thunk_Native);
  // Copy MSVC, and always set up a frame pointer. (Maybe this isn't necessary.)
  F->addFnAttr("frame-pointer", "all");
  // Only copy sret from the first argument. For C++ instance methods, clang can
  // stick an sret marking on a later argument, but it doesn't actually affect
  // the ABI, so we can omit it. This avoids triggering a verifier assertion.
  if (CB->arg_size() > 0) {
    auto Attr = CB->getParamAttr(0, Attribute::StructRet);
    if (Attr.isValid())
      F->addParamAttr(1, Attr);
  }
  // FIXME: Copy anything other than sret?  Shouldn't be necessary for normal
  // C ABI, but might show up in other cases.
  BasicBlock *BB = BasicBlock::Create(M->getContext(), "", F);
  IRBuilder<> IRB(BB);
  PointerType *DispatchPtrTy =
      FunctionType::get(IRB.getVoidTy(), false)->getPointerTo(0);
  Value *CalleePtr = M->getOrInsertGlobal(
      "__os_arm64x_dispatch_call_no_redirect", DispatchPtrTy);
  Value *Callee = IRB.CreateLoad(DispatchPtrTy, CalleePtr);
  auto &DL = M->getDataLayout();
  SmallVector<Value *> Args;
  SmallVector<Type *> ArgTypes;

  // Pass the called function in x9.
  Args.push_back(F->arg_begin());
  ArgTypes.push_back(Args.back()->getType());

  Type *X64RetType = RetTy;
  if (RetTy->isArrayTy() || RetTy->isStructTy()) {
    // If the return type is an array or struct, translate it. Values of size
    // 8 or less go into RAX; bigger values go into memory, and we pass a
    // pointer.
    if (DL.getTypeStoreSize(RetTy) > 8) {
      Args.push_back(IRB.CreateAlloca(RetTy));
      ArgTypes.push_back(Args.back()->getType());
      X64RetType = IRB.getVoidTy();
    } else {
      X64RetType = IRB.getIntNTy(DL.getTypeStoreSizeInBits(RetTy));
    }
  }

  for (auto &Arg : make_range(F->arg_begin() + 1, F->arg_end())) {
    // Translate arguments from AArch64 calling convention to x86 calling
    // convention.
    //
    // For simple types, we don't need to do any translation: they're
    // represented the same way. (Implicit sign extension is not part of
    // either convention.)
    //
    // The big thing we have to worry about is struct types... but
    // fortunately AArch64 clang is pretty friendly here: the cases that need
    // translation are always passed as a struct or array. (If we run into
    // some cases where this doesn't work, we can teach clang to mark it up
    // with an attribute.)
    //
    // The first argument is the called function, stored in x9.
    if (Arg.getType()->isArrayTy() || Arg.getType()->isStructTy()) {
      Value *Mem = IRB.CreateAlloca(Arg.getType());
      IRB.CreateStore(&Arg, Mem);
      if (DL.getTypeStoreSize(Arg.getType()) <= 8)
        Args.push_back(IRB.CreateLoad(
            IRB.getIntNTy(DL.getTypeStoreSizeInBits(Arg.getType())), Mem));
      else
        Args.push_back(Mem);
    } else {
      Args.push_back(&Arg);
    }
    ArgTypes.push_back(Args.back()->getType());
  }
  // FIXME: Transfer necessary attributes? sret? anything else?
  // FIXME: Try to share thunks.  This probably involves simplifying the
  // argument types (translating all integers/pointers to i64, etc.)
  auto *CallTy = FunctionType::get(X64RetType, ArgTypes, false);

  Callee = IRB.CreateBitCast(Callee, CallTy->getPointerTo(0));
  CallInst *Call = IRB.CreateCall(CallTy, Callee, Args);
  Call->setCallingConv(CallingConv::ARM64EC_Thunk_X64);

  Value *RetVal = Call;
  if (RetTy->isArrayTy() || RetTy->isStructTy()) {
    // If we rewrote the return type earlier, convert the return value to
    // the proper type.
    if (DL.getTypeStoreSize(RetTy) > 8) {
      RetVal = IRB.CreateLoad(RetTy, Args[1]);
    } else {
      Value *CastAlloca = IRB.CreateAlloca(RetTy);
      IRB.CreateStore(Call, IRB.CreateBitCast(
                                CastAlloca, Call->getType()->getPointerTo(0)));
      RetVal = IRB.CreateLoad(RetTy, CastAlloca);
    }
  }

  if (RetTy->isVoidTy())
    IRB.CreateRetVoid();
  else
    IRB.CreateRet(RetVal);
  return F;
}

void AArch64Arm64ECCallLowering::lowerCall(CallBase *CB) {
  assert(Triple(CB->getModule()->getTargetTriple()).isOSWindows() &&
         "Only applicable for Windows targets");

  IRBuilder<> B(CB);
  Value *CalledOperand = CB->getCalledOperand();

  // If the indirect call is called within catchpad or cleanuppad,
  // we need to copy "funclet" bundle of the call.
  SmallVector<llvm::OperandBundleDef, 1> Bundles;
  if (auto Bundle = CB->getOperandBundle(LLVMContext::OB_funclet))
    Bundles.push_back(OperandBundleDef(*Bundle));

  // Load the global symbol as a pointer to the check function.
  Value *GuardFn;
  if (cfguard_module_flag == 2 && !CB->hasFnAttr("guard_nocf"))
    GuardFn = GuardFnCFGlobal;
  else
    GuardFn = GuardFnGlobal;
  LoadInst *GuardCheckLoad = B.CreateLoad(GuardFnPtrType, GuardFn);

  // Create new call instruction. The CFGuard check should always be a call,
  // even if the original CallBase is an Invoke or CallBr instruction.
  Function *Thunk = buildExitThunk(CB);
  CallInst *GuardCheck =
      B.CreateCall(GuardFnType, GuardCheckLoad,
                   {B.CreateBitCast(CalledOperand, B.getInt8PtrTy()),
                    B.CreateBitCast(Thunk, B.getInt8PtrTy())},
                   Bundles);

  // Ensure that the first argument is passed in the correct register
  // (e.g. ECX on 32-bit X86 targets).
  GuardCheck->setCallingConv(CallingConv::CFGuard_Check);

  Value *GuardRetVal = B.CreateBitCast(GuardCheck, CalledOperand->getType());
  CB->setCalledOperand(GuardRetVal);
}

bool AArch64Arm64ECCallLowering::doInitialization(Module &Mod) {
  M = &Mod;

  // Check if this module has the cfguard flag and read its value.
  if (auto *MD =
          mdconst::extract_or_null<ConstantInt>(M->getModuleFlag("cfguard")))
    cfguard_module_flag = MD->getZExtValue();

  Type *Int8Ptr = Type::getInt8PtrTy(M->getContext());
  GuardFnType = FunctionType::get(Int8Ptr, {Int8Ptr, Int8Ptr}, false);
  GuardFnPtrType = PointerType::get(GuardFnType, 0);
  GuardFnCFGlobal =
      M->getOrInsertGlobal("__os_arm64x_check_icall_cfg", GuardFnPtrType);
  GuardFnGlobal =
      M->getOrInsertGlobal("__os_arm64x_check_icall", GuardFnPtrType);
  return true;
}

bool AArch64Arm64ECCallLowering::runOnFunction(Function &F) {
  SmallVector<CallBase *, 8> IndirectCalls;

  // Iterate over the instructions to find all indirect call/invoke/callbr
  // instructions. Make a separate list of pointers to indirect
  // call/invoke/callbr instructions because the original instructions will be
  // deleted as the checks are added.
  for (BasicBlock &BB : F.getBasicBlockList()) {
    for (Instruction &I : BB.getInstList()) {
      auto *CB = dyn_cast<CallBase>(&I);
      if (!CB || CB->getCallingConv() == CallingConv::ARM64EC_Thunk_X64 ||
          CB->isInlineAsm())
        continue;

      // We need to instrument any call that isn't directly calling an
      // ARM64 function.
      //
      // FIXME: isDSOLocal() doesn't do what we want; even if the symbol is
      // technically local, automatic dllimport means the function it refers
      // to might not be.
      //
      // FIXME: If a function is dllimport, we can just mark up the symbol
      // using hybmp$x, and everything just works.  If the function is not
      // marked dllimport, we can still mark up the symbol, but we somehow
      // need an extra stub to compute the correct callee. Not really
      // understanding how this works.
      if (Function *F = CB->getCalledFunction()) {
        if (F->isDSOLocal() || F->isIntrinsic())
          continue;
      }

      IndirectCalls.push_back(CB);
      ++Arm64ECCallsLowered;
    }
  }

  if (IndirectCalls.empty())
    return false;

  for (CallBase *CB : IndirectCalls)
    lowerCall(CB);

  return true;
}

char AArch64Arm64ECCallLowering::ID = 0;
INITIALIZE_PASS(AArch64Arm64ECCallLowering, "Arm64ECCallLowering",
                "AArch64Arm64ECCallLowering", false, false)

FunctionPass *llvm::createAArch64Arm64ECCallLoweringPass() {
  return new AArch64Arm64ECCallLowering;
}
