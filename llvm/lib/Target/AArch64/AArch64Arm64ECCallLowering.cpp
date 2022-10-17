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
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Triple.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instruction.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"

using namespace llvm;

using OperandBundleDef = OperandBundleDefT<Value *>;

#define DEBUG_TYPE "arm64eccalllowering"

#define ARM64EC_CALL_LOWERING_NAME "Arm64EC call lowering"

STATISTIC(Arm64ECCallsLowered, "Number of Arm64EC calls lowered");

namespace {

class AArch64Arm64ECCallLowering : public ModulePass {
public:
  static char ID;
  AArch64Arm64ECCallLowering() : ModulePass(ID) {
    initializeAArch64Arm64ECCallLoweringPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return ARM64EC_CALL_LOWERING_NAME; }

  bool runOnModule(Module &Mod) override;

  // TODO: find the other types
  enum HybridInfoType {
    Exitthunk_To_Guest = 0,
    Native_To_Entrythunk = 1,
    Native_To_Icall_Thunk = 4
  };

private:
  int cfguard_module_flag = 0;
  FunctionType *GuardFnType = nullptr;
  PointerType *GuardFnPtrType = nullptr;
  Constant *GuardFnCFGlobal = nullptr;
  Constant *GuardFnGlobal = nullptr;
  Module *M = nullptr;

  using HybridType = std::tuple<GlobalValue *, GlobalValue *, HybridInfoType>;

  StructType *HybridInfoStructType = nullptr;
  SmallVector<llvm::Constant *, 32> HybridInfoTable;
  SmallSet<HybridType, 32> HybridInfoSet;

  Type *I8PtrTy;
  Type *I64Ty;
  Type *VoidTy;

  FunctionType *getThunkType(FunctionType *FT, AttributeList AttrList,
                             bool entry, raw_ostream &Out);
  Type *getThunkRetType(FunctionType *FT, AttributeList AttrList,
                        bool EntryThunk, raw_ostream &Out);
  void getThunkArgTypes(FunctionType *FT, AttributeList AttrList,
                        bool EntryThunk, SmallVector<Type *> &ArgTypes,
                        raw_ostream &Out);
  Type *canonicalizeThunkType(Type *T, Align Alignment, bool EntryThunk,
                              bool Ret, uint64_t ArgSizeBytes,
                              raw_ostream &Out);
  void addHybridInfo(GlobalValue *From, GlobalValue *To,
                     HybridInfoType InfoType);

  bool genEntryThunk(Function &F);
  Function *buildEntryThunk(Function *F);

  bool genExitThunk(Function &F);
  Function *buildExitThunk(CallBase *CB);

  void lowerCall(CallBase *CB);
  void lowerDirectCall(CallBase *CB, Function *F);

  static bool passByRefInX86(unsigned ArgSize);
  static bool isSRetInX86(unsigned ArgSize);
};

} // end anonymous namespace

char AArch64Arm64ECCallLowering::ID = 0;
INITIALIZE_PASS(AArch64Arm64ECCallLowering, DEBUG_TYPE,
                ARM64EC_CALL_LOWERING_NAME, false, false)

static bool isArm64ECSymbol(const std::string &MangleName) {
  size_t Index = MangleName.find('#');
  if (Index == 0)
    return true;

  Index = MangleName.find("@@$$h");
  if (Index != std::string::npos)
    return true;

  return false;
}

static std::string toArm64ECMangle(std::string MangleName) {
  if (!isArm64ECSymbol(MangleName)) {
    if (MangleName._Starts_with("?")) {
      size_t InsertIdx = MangleName.find("@@");
      if (InsertIdx != std::string::npos)
        MangleName.insert(InsertIdx + 2, "$$h");
    } else {
      MangleName.insert(0, "#");
    }
  }

  return MangleName;
}

static std::string toNormalMangle(std::string MangleName) {
  size_t Index = MangleName.find('#');
  if (Index != std::string::npos) {
    MangleName.erase(MangleName.begin() + Index);
  } else {
    Index = MangleName.find("$$h");
    if (Index != std::string::npos)
      MangleName.erase(MangleName.begin() + Index,
                       MangleName.begin() + Index + 3);
  }

  return MangleName;
}

bool AArch64Arm64ECCallLowering::passByRefInX86(unsigned ArgSize) {
  if (ArgSize > 16)
    return false;

  return (ArgSize & (ArgSize - 1)) != 0;
}

bool AArch64Arm64ECCallLowering::isSRetInX86(unsigned ArgSize) {
  return ArgSize > 8 && ArgSize <= 16;
}

FunctionType *AArch64Arm64ECCallLowering::getThunkType(FunctionType *FT,
                                                       AttributeList AttrList,
                                                       bool EntryThunk,
                                                       raw_ostream &Out) {
  Out << (EntryThunk ? "$ientry_thunk$cdecl$" : "$iexit_thunk$cdecl$");

  SmallVector<Type *> DefArgTypes;
  DefArgTypes.push_back(I8PtrTy);
  Type *RetTy = getThunkRetType(FT, AttrList, EntryThunk, Out);

  unsigned RetArgSize = AttrList.getRetArm64ECArgSizeBytes();
  if (RetArgSize == 0 && !RetTy->isVoidTy())
    RetArgSize = M->getDataLayout().getTypeSizeInBits(RetTy) / 8;
  if (EntryThunk && isSRetInX86(RetArgSize)) {
    // x86 signature will return value from stack when ret type
    // size is larger than 8 and less than 16. But arm64
    // signature is still passed by register here.
    RetTy = VoidTy;
    DefArgTypes.push_back(I8PtrTy);
  }

  getThunkArgTypes(FT, AttrList, EntryThunk, DefArgTypes, Out);

  return FunctionType::get(RetTy, DefArgTypes, false);
}

void AArch64Arm64ECCallLowering::getThunkArgTypes(FunctionType *FT,
                                                  AttributeList AttrList,
                                                  bool EntryThunk,
                                                  SmallVector<Type *> &ArgTypes,
                                                  raw_ostream &Out) {
  Out << "$";
  if (FT->isVarArg()) {
    // We treat the variadic function's exit thunk as a normal function
    // with type:
    //   rettype exitthunk(
    //     ptr x9, ptr x0, i64 x1, i64 x2, i64 x3, ptr x4, i64 x5)
    // that can coverage all types of variadic function.
    // x9 is similar to normal exit thunk, store the called function.
    // x0-x3 is the arguments be stored in registers.
    // x4 is the address of the arguments on the stack.
    // x5 is the size of the arguments on the stack.
    Out << "varargs";
    ArgTypes.push_back(I8PtrTy);
    for (int i = 0; i < 3; i++)
      ArgTypes.push_back(I64Ty);

    ArgTypes.push_back(I8PtrTy);
    ArgTypes.push_back(I64Ty);
    return;
  }

  if (FT->getNumParams() == 0) {
    Out << "v";
    return;
  }

  unsigned I = 0;
  if (AttrList.getParamAttr(I, Attribute::StructRet).isValid()) {
    ArgTypes.push_back(FT->getParamType(I));
    I++;
  }

  if (I == FT->getNumParams()) {
    Out << "v";
    return;
  }

  for (unsigned E = FT->getNumParams(); I != E; ++I) {
    Align ParamAlign = AttrList.getParamAlignment(I).valueOrOne();
    uint64_t ArgSizeBytes = AttrList.getParamArm64ECArgSizeBytes(I);
    ArgTypes.push_back(canonicalizeThunkType(FT->getParamType(I), ParamAlign,
                                             EntryThunk,
                                             /*Ret*/ false, ArgSizeBytes, Out));
  }
}

Type *AArch64Arm64ECCallLowering::getThunkRetType(FunctionType *FT,
                                                  AttributeList AttrList,
                                                  bool EntryThunk,
                                                  raw_ostream &Out) {
  Type *T = FT->getReturnType();
  uint64_t ArgSizeBytes = AttrList.getRetArm64ECArgSizeBytes();
  if (T->isVoidTy()) {
    if (FT->getNumParams()) {
      auto Attr = AttrList.getParamAttr(0, Attribute::StructRet);
      if (Attr.isValid()) {
        Type *SRetType = Attr.getValueAsType();
        Align SRetAlign = AttrList.getParamAlignment(0).valueOrOne();
        canonicalizeThunkType(SRetType, SRetAlign, EntryThunk, /*Ret*/ true,
                              ArgSizeBytes, Out);
        return VoidTy;
      }
    }

    Out << "v";
    return VoidTy;
  }

  return canonicalizeThunkType(T, Align(), EntryThunk, /*Ret*/ true,
                               ArgSizeBytes, Out);
}

Type *AArch64Arm64ECCallLowering::canonicalizeThunkType(
    Type *T, Align Alignment, bool EntryThunk, bool Ret, uint64_t ArgSizeBytes,
    raw_ostream &Out) {
  Type *CanonicalizedTy = T;
  auto &DL = M->getDataLayout();
  if (T->isFloatTy()) {
    Out << "f";
  } else if (T->isDoubleTy()) {
    Out << "d";
  } else if (T->isIntegerTy(128)) {
    Out << "m16a16";
  } else {
    if (auto *StructTy = dyn_cast<StructType>(T))
      if (StructTy->getNumElements() == 1)
        CanonicalizedTy = T = StructTy->getElementType(0);

    if (T->isArrayTy()) {
      Type *ElementTy = T->getArrayElementType();
      uint64_t ElementCnt = T->getArrayNumElements();
      uint64_t ElementSizePerBytes = DL.getTypeSizeInBits(ElementTy) / 8;
      if (ElementTy->isFloatTy()) {
        Out << "F" << ElementCnt * ElementSizePerBytes;
        if (Alignment.value() >= 8 && !T->isPointerTy())
          Out << "a" << Alignment.value();
        if (ArgSizeBytes & (ArgSizeBytes - 1))
          CanonicalizedTy = T->getPointerTo();
        return CanonicalizedTy;
      } else if (ElementTy->isDoubleTy()) {
        Out << "D" << ElementCnt * ElementSizePerBytes;
        if (Alignment.value() >= 8 && !T->isPointerTy())
          Out << "a" << Alignment.value();
        if (ArgSizeBytes & (ArgSizeBytes - 1))
          CanonicalizedTy = T->getPointerTo();
        return CanonicalizedTy;
      }
    }

    unsigned TypeSize = ArgSizeBytes;
    if (TypeSize == 0)
      TypeSize = DL.getTypeSizeInBits(T) / 8;
    if (!Ret && !EntryThunk && TypeSize > 16) {
      Out << "i8";
      CanonicalizedTy = I8PtrTy;
    } else if (ArgSizeBytes || T->isArrayTy() || T->isStructTy()) {
      Out << "m";
      if (TypeSize != 4)
        Out << TypeSize;
      if (Alignment.value() >= 8 && !T->isPointerTy())
        Out << "a" << Alignment.value();

      if (EntryThunk && passByRefInX86(TypeSize))
        CanonicalizedTy = I8PtrTy;
    } else {
      Out << "i8";
      CanonicalizedTy = I64Ty;
    }
  }
  return CanonicalizedTy;
}

void AArch64Arm64ECCallLowering::addHybridInfo(GlobalValue *From,
                                               GlobalValue *To,
                                               HybridInfoType InfoType) {
  if (HybridInfoSet.insert(std::make_tuple(From, To, InfoType)).second) {
    // FIXME: do we really need to consider non-opaque pointer mode?
    Constant *HybridInfo[3] = {
        ConstantExpr::getBitCast(From, I8PtrTy),
        ConstantExpr::getBitCast(To, I8PtrTy),
        ConstantInt::get(Type::getInt32Ty(M->getContext()), InfoType)};

    HybridInfoTable.push_back(
        ConstantStruct::get(HybridInfoStructType, HybridInfo));
  }
}

Function *AArch64Arm64ECCallLowering::buildEntryThunk(Function *F) {
  FunctionType *OrignFTy = F->getFunctionType();
  SmallString<256> EntryThunkName;
  llvm::raw_svector_ostream Out(EntryThunkName);
  FunctionType *ThunkTy =
      getThunkType(OrignFTy, F->getAttributes(), /*EntryThunk*/ true, Out);
  Function *Thunk = M->getFunction(EntryThunkName);
  if (Thunk)
    return Thunk;

  auto &DL = M->getDataLayout();
  Thunk = Function::Create(ThunkTy, GlobalValue::ExternalLinkage, 0,
                           EntryThunkName, M);
  Thunk->setCallingConv(CallingConv::ARM64EC_Thunk_X64);
  Thunk->addFnAttr("frame-pointer", "all");
  Thunk->setSection(".wowthk$aa");
  Thunk->setLinkage(GlobalValue::LinkOnceODRLinkage);
  Thunk->setComdat(M->getOrInsertComdat(EntryThunkName));

  unsigned ArgDelta = 1;
  Type *X64RetType = ThunkTy->getReturnType();
  Type *RetTy = X64RetType;
  unsigned RetArgSize = F->getAttributes().getRetArm64ECArgSizeBytes();
  Attribute SRetAttr;
  if (X64RetType->isVoidTy()) {
    if (isSRetInX86(RetArgSize)) {
      // if the return value size is larger than 8 and less than 16
      // the thunk should be x86 signature with struct ret
      ArgDelta++;
      RetTy = Type::getIntNTy(M->getContext(), RetArgSize * 8);
      SRetAttr = Attribute::getWithStructRetType(M->getContext(), RetTy);
      Thunk->addParamAttr(1, SRetAttr);
    } else if (F->arg_size() > 0) {
      // if the function already has struct ret,
      // change the struct type to equivalent intN type.
      SRetAttr = F->getParamAttribute(0, Attribute::StructRet);
      if (SRetAttr.isValid()) {
        unsigned RetArgSizeInBits = F->getParamArm64ECArgSizeBytes(0) * 8;
        if (RetArgSizeInBits == 0)
          RetArgSizeInBits = DL.getTypeSizeInBits(SRetAttr.getValueAsType());
        SRetAttr = Attribute::getWithStructRetType(
            M->getContext(),
            Type::getIntNTy(M->getContext(), RetArgSizeInBits));
        Thunk->addParamAttr(1, SRetAttr);
      }
    }
  }

  BasicBlock *BB = BasicBlock::Create(M->getContext(), "", Thunk);
  IRBuilder<> IRB(BB);
  SmallVector<Value *> Args;
  SmallVector<Type *> ArgTypes;

  for (unsigned i = 0; i < F->arg_size(); ++i) {
    Argument *Arg = Thunk->getArg(i + ArgDelta);
    unsigned ArgSize = F->getParamArm64ECArgSizeBytes(i);
    if (passByRefInX86(ArgSize)) {
      bool FloatCase = false;
      Type *FArgTy = F->getArg(i)->getType();
      if (FArgTy->isArrayTy()) {
        Type *ElementTy = FArgTy->getArrayElementType();
        if (ElementTy->isFloatTy() || ElementTy->isDoubleTy()) {
          Value *LoadData = IRB.CreateLoad(FArgTy, Arg);
          Args.push_back(LoadData);
          FloatCase = true;
        }
      }
      if (!FloatCase) {
        unsigned NativeArgSize = DL.getTypeSizeInBits(FArgTy);
        Type *NativeType = Type::getIntNTy(M->getContext(), NativeArgSize);
        Type *LoadType = Type::getIntNTy(M->getContext(), ArgSize * 8);
        Value *BitCast = IRB.CreateBitCast(Arg, LoadType->getPointerTo());
        Value *LoadData = IRB.CreateLoad(LoadType, BitCast);
        Args.push_back(IRB.CreateZExt(LoadData, NativeType));
      }
    } else {
      Args.push_back(Arg);
    }
    ArgTypes.push_back(Args.back()->getType());
  }

  auto *CallTy = FunctionType::get(RetTy, ArgTypes, F->isVarArg());

  Value *Callee =
      IRB.CreateBitCast(Thunk->arg_begin(), CallTy->getPointerTo(0));
  CallInst *Call = IRB.CreateCall(CallTy, Callee, Args);
  Call->setCallingConv(F->getCallingConv());
  if (F->hasParamAttribute(0, Attribute::StructRet))
    Call->addParamAttr(0, SRetAttr);

  FunctionType *FVoidVoidTy = FunctionType::get(VoidTy, false);

  InlineAsm *IA = InlineAsm::get(
      FVoidVoidTy, "",
      "~{v6},~{v7},~{v8},~{v9},~{v10},~{v11},~{v12},~{v13},~{v14},~{v15}",
      /*hasSideEffects=*/true);
  IRB.CreateCall(IA, None);

  if (ArgDelta == 2)
    IRB.CreateStore(Call, Thunk->getArg(1));

  if (X64RetType->isVoidTy())
    IRB.CreateRetVoid();
  else
    IRB.CreateRet(Call);

  return Thunk;
}

Function *AArch64Arm64ECCallLowering::buildExitThunk(CallBase *CB) {
  FunctionType *FT = CB->getFunctionType();
  SmallString<256> ExitThunkName;
  llvm::raw_svector_ostream Out(ExitThunkName);
  FunctionType *Ty =
      getThunkType(FT, CB->getAttributes(), /*EntryThunk*/ false, Out);
  Function *F = M->getFunction(ExitThunkName);
  if (F)
    return F;

  bool IsVarArg = FT->isVarArg();
  F = Function::Create(Ty, GlobalValue::ExternalLinkage, 0, ExitThunkName, M);
  F->setCallingConv(CallingConv::ARM64EC_Thunk_Native);
  // Copy MSVC, and always set up a frame pointer. (Maybe this isn't necessary.)
  F->addFnAttr("frame-pointer", "all");
  F->setSection(".wowthk$aa");
  F->setLinkage(GlobalValue::LinkOnceODRLinkage);
  F->setComdat(M->getOrInsertComdat(ExitThunkName));
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

  Type *RetTy = Ty->getReturnType();
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
    if (!IsVarArg)
      ArgTypes.push_back(Args.back()->getType());
  }
  // FIXME: Transfer necessary attributes? sret? anything else?
  // FIXME: Try to share thunks.  This probably involves simplifying the
  // argument types (translating all integers/pointers to i64, etc.)
  auto *CallTy = FunctionType::get(X64RetType, ArgTypes, IsVarArg);

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

void AArch64Arm64ECCallLowering::lowerDirectCall(CallBase *CB, Function *F) {
  if (F->hasDLLImportStorageClass()) {
    Function *Thunk = buildExitThunk(CB);
    addHybridInfo(F, Thunk, Native_To_Icall_Thunk);
    return;
  }

  std::string FuncName = F->getName().str();
  std::string Arm64SignName = toArm64ECMangle(FuncName);
  std::string CallThunkName = Arm64SignName;
  if (CallThunkName._Starts_with("#"))
    CallThunkName = CallThunkName + "$exit_thunk";
  else
    CallThunkName =
        CallThunkName.insert(CallThunkName.find("@@"), "$exit_thunk");
  Function *CallThunk = M->getFunction(CallThunkName);
  if (CallThunk)
    return;

  Type *RetTy = F->getReturnType();
  FunctionType *FT = F->getFunctionType();
  CallThunk =
      Function::Create(FT, GlobalValue::ExternalLinkage, 0, CallThunkName, M);
  CallThunk->setComdat(M->getOrInsertComdat(CallThunkName));
  CallThunk->setSection(".wowthk$aa");

  std::string X86SignName = toNormalMangle(Arm64SignName);
  if (!isArm64ECSymbol(FuncName))
    F->setName(Arm64SignName);

  auto *NativeAlias = GlobalAlias::create("", CallThunk);
  NativeAlias->takeName(F);
  NativeAlias->setLinkage(GlobalValue::WeakODRLinkage);
  NativeAlias->setIsAntiDependency(true);
  F->replaceAllUsesWith(NativeAlias);
  F->eraseFromParent();

  auto *X86Alias = GlobalAlias::create(X86SignName, NativeAlias);
  X86Alias->setLinkage(GlobalValue::WeakODRLinkage);
  X86Alias->setIsAntiDependency(true);

  BasicBlock *BB = BasicBlock::Create(M->getContext(), "", CallThunk);
  IRBuilder<> IRB(BB);

  SmallVector<Value *> Args;
  for (auto &Arg : CallThunk->args())
    Args.push_back(&Arg);
  Value *RetVal = IRB.CreateCall(FT, X86Alias, Args);
  if (RetTy->isVoidTy())
    IRB.CreateRetVoid();
  else
    IRB.CreateRet(RetVal);

  genExitThunk(*CallThunk);
}

void AArch64Arm64ECCallLowering::lowerCall(CallBase *CB) {
  assert(Triple(CB->getModule()->getTargetTriple()).isOSWindows() &&
         "Only applicable for Windows targets");
  Value *CalledOperand = CB->getCalledOperand();
  Function *F = dyn_cast<Function>(CalledOperand);
  if (F != nullptr) {
    lowerDirectCall(CB, F);
    return;
  }

  IRBuilder<> B(CB);
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
  if (auto *GV = dyn_cast<GlobalValue>(CalledOperand)) {
    addHybridInfo(GV, Thunk, Native_To_Icall_Thunk);
    addHybridInfo(CB->getFunction(), GV, Exitthunk_To_Guest);
  }
}

bool AArch64Arm64ECCallLowering::genEntryThunk(Function &F) {
  if (F.isDeclaration() || F.hasLocalLinkage() || F.isIntrinsic())
    return false;

  std::string FuncName = F.getName().str();
  if (!isArm64ECSymbol(FuncName)) {
    std::string Arm64SignName = toArm64ECMangle(FuncName);
    auto *Alias = GlobalAlias::create("", &F);
    Alias->takeName(&F);
    Alias->setLinkage(GlobalValue::WeakODRLinkage);
    Alias->setIsAntiDependency(true);
    F.setName(Arm64SignName);
    F.setComdat(M->getOrInsertComdat(FuncName));
  }

  Function *Thunk = buildEntryThunk(&F);
  addHybridInfo(&F, Thunk, Native_To_Entrythunk);

  return false;
}

bool AArch64Arm64ECCallLowering::genExitThunk(Function &F) {
  SmallVector<CallBase *, 8> CallsNeedExitThunk;

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
        if (!F->isDeclaration() || F->isIntrinsic())
          continue;
      }

      CallsNeedExitThunk.push_back(CB);
      ++Arm64ECCallsLowered;
    }
  }

  for (CallBase *CB : CallsNeedExitThunk)
    lowerCall(CB);

  return CallsNeedExitThunk.size() != 0;
}

bool AArch64Arm64ECCallLowering::runOnModule(Module &Mod) {
  M = &Mod;

  // Check if this module has the cfguard flag and read its value.
  if (auto *MD =
          mdconst::extract_or_null<ConstantInt>(M->getModuleFlag("cfguard")))
    cfguard_module_flag = MD->getZExtValue();

  I8PtrTy = Type::getInt8PtrTy(M->getContext());
  I64Ty = Type::getInt64Ty(M->getContext());
  VoidTy = Type::getVoidTy(M->getContext());

  GuardFnType = FunctionType::get(I8PtrTy, {I8PtrTy, I8PtrTy}, false);
  GuardFnPtrType = PointerType::get(GuardFnType, 0);
  GuardFnCFGlobal =
      M->getOrInsertGlobal("__os_arm64x_dispatch_icall_cfg", GuardFnPtrType);
  GuardFnGlobal =
      M->getOrInsertGlobal("__os_arm64x_dispatch_icall", GuardFnPtrType);

  HybridInfoStructType =
      StructType::get(I8PtrTy, I8PtrTy, Type::getInt32Ty(M->getContext()));
  HybridInfoTable.clear();

  for (auto &F : M->getFunctionList()) {
    if (F.getSection() != ".wowthk$aa") {
      genEntryThunk(F);
      genExitThunk(F);
    }
  }

  if (HybridInfoTable.size()) {
    ArrayType *HybridTableType =
        ArrayType::get(HybridInfoStructType, HybridInfoTable.size());
    Constant *HybridTableInit =
        ConstantArray::get(HybridTableType, HybridInfoTable);
    new GlobalVariable(*M, HybridTableType, true,
                       GlobalValue::LinkageTypes::ExternalLinkage,
                       HybridTableInit, "arm64ec.hybmp");
  }

  return true;
}

ModulePass *llvm::createAArch64Arm64ECCallLoweringPass() {
  return new AArch64Arm64ECCallLowering;
}
