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

  void InsertDomCondition(DominatorTree &DT, BasicBlock *BB, Instruction *Term,
                          Instruction *Cond, bool TrueEdge, bool FalseEdge);

public:
  DomConditionInfo() {}
  DomConditionInfo(Function &F, DominatorTree &DT);

  std::pair<const BasicBlock *, CmpInst::Predicate>
  getDominatingCondition(const BasicBlock *BB, const Value *LHS,
                         const Value *RHS) const;
  void print(raw_ostream &OS) const;
  void clear() { DomCondMap.clear(); }
};


} // namespace llvm

#endif // LLVM_ANALYSIS_DOMCONDITIONANALYSIS_H