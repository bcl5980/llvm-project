//===- DomConditionAnalysis.cpp - ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the DomConditionAnalysis class
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ANALYSIS_DOMCONDITIONANALYSIS_H
#define LLVM_ANALYSIS_DOMCONDITIONANALYSIS_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instructions.h"

namespace llvm {

struct DomCondition {
  const BasicBlock *DomBB;
  Value *LHS;
  Value *RHS;
  CmpInst::Predicate Pred;
};

class DomConditionInfo {
  typedef SmallVector<DomCondition, 4> DomCondVector;

private:
  // Map from basic block to the list of conditions that dominate it.
  SmallDenseMap<const BasicBlock *, DomCondVector, 8> DomCondMap;

public:
  DomConditionInfo() {}
  DomConditionInfo(Function &F, DominatorTree &DT);

  std::pair<const BasicBlock *, CmpInst::Predicate>
  getDominatingCondition(const BasicBlock *BB, const Value *LHS,
                         const Value *RHS) const;
  void print(raw_ostream &OS) const;
  void clear() { DomCondMap.clear(); }
};

// Dominate condition analysis pass.
class DomConditionAnalysis : public AnalysisInfoMixin<DomConditionAnalysis> {
  friend AnalysisInfoMixin<DomConditionAnalysis>;

  static AnalysisKey Key;

public:
  using Result = DomConditionInfo;

  // Run the analysis pass over a function and produce DomConditionInfo.
  Result run(Function &F, FunctionAnalysisManager &AM);
};

// Printer pass for DomConditionAnalysis.
struct DomConditionAnalysisPrinterPass
    : public PassInfoMixin<DomConditionAnalysisPrinterPass> {
  DomConditionAnalysisPrinterPass(raw_ostream &OS) : OS(OS) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);

private:
  raw_ostream &OS;
}; // class DomConditionAnalysisPrinterPass

/// Legacy analysis pass which computes a \c DomConditionInfo.
class DomConditionWrapper : public FunctionPass {
  DomConditionInfo DCI;

public:
  static char ID;

  DomConditionWrapper();

  DomConditionInfo &getDomConditionInfo() { return DCI; }
  const DomConditionInfo &getDomConditionInfo() const { return DCI; }

  bool runOnFunction(Function &F) override;

  void verifyAnalysis() const override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }

  void releaseMemory() override { DCI.clear(); }

  void print(raw_ostream &OS, const Module *M = nullptr) const override;
};

}; // namespace llvm

#endif // LLVM_ANALYSIS_DOMCONDITIONANALYSIS_H