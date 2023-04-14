//===- DomConditionAnalysis.cpp -------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/DomConditionAnalysis.h"
#include "llvm/ADT/BreadthFirstIterator.h"
#include "llvm/IR/PatternMatch.h"

using namespace llvm;
using namespace PatternMatch;

DomConditionInfo::DomConditionInfo(Function &F, DominatorTree &DT) {
  DT.updateDFSNumbers();

  for (auto &BB : F) {
    if (BB.isEntryBlock())
      continue;

    auto *DTNode = DT.getNode(&BB);
    if (!DTNode)
      continue;

    while (DTNode->getIDom()) {
      auto *IDom = DTNode->getIDom();
      auto *IDomBB = IDom->getBlock();

      // We only handle the case where the terminator has two successors for
      // now.
      auto *Term = IDomBB->getTerminator();
      if (Term->getNumSuccessors() != 2)
        break;

      auto &CurrentVec = DomCondMap[&BB];
      if (auto *I = dyn_cast<Instruction>(Term->getOperand(0))) {
        std::function<void(Instruction *, bool, bool)> GenDomCondMap;
        GenDomCondMap = [&](Instruction *Cond, bool TrueEdge, bool FalseEdge) {
          Value *X, *Y;
          // We only handle the case where the terminator is an icmp for now.
          if (const auto *Cmp = dyn_cast<ICmpInst>(Cond)) {
            if (TrueEdge) {
              auto *TrueBB = Term->getSuccessor(0);
              BasicBlockEdge TrueEdge(IDomBB, TrueBB);
              if (DT.dominates(TrueEdge, &BB))
                CurrentVec.push_back({IDomBB, Cmp->getOperand(0),
                                      Cmp->getOperand(1), Cmp->getPredicate()});
            }
            if (FalseEdge) {
              auto *FalseBB = Term->getSuccessor(1);
              BasicBlockEdge FalseEdge(IDomBB, FalseBB);
              if (DT.dominates(FalseEdge, &BB))
                CurrentVec.push_back({IDomBB, Cmp->getOperand(0),
                                      Cmp->getOperand(1),
                                      Cmp->getInversePredicate()});
            }
          } else if (match(Cond, m_LogicalAnd(m_Value(X), m_Value(Y)))) {
            if (auto *I = dyn_cast<Instruction>(X))
              GenDomCondMap(I, true, false);
            if (auto *I = dyn_cast<Instruction>(Y))
              GenDomCondMap(I, true, false);
          } else if (match(Cond, m_LogicalOr(m_Value(X), m_Value(Y)))) {
            if (auto *I = dyn_cast<Instruction>(X))
              GenDomCondMap(I, false, true);
            if (auto *I = dyn_cast<Instruction>(Y))
              GenDomCondMap(I, false, true);
          }
        };
        GenDomCondMap(I, true, true);
      }

      auto DomVec = DomCondMap.find(IDomBB);
      if (DomVec != DomCondMap.end()) {
        CurrentVec.append(DomVec->second.begin(), DomVec->second.end());
        break;
      }
      DTNode = IDom;
      continue;
    }
  }
}

void DomConditionInfo::print(raw_ostream &OS) const {
  OS << "Basic Block Dominate Conditions:\n";
  for (const auto &Entry : DomCondMap) {
    OS << Entry.first->getName() << ":\n";
    for (const auto &Cond : Entry.second) {
      Cond.LHS->printAsOperand(OS, false);
      OS << " " << CmpInst::getPredicateName(Cond.Pred) << " ";
      Cond.RHS->printAsOperand(OS, false);
    }
    OS << "\n";
  }
}

std::pair<const BasicBlock *, CmpInst::Predicate>
DomConditionInfo::getDominatingCondition(const BasicBlock *BB, const Value *LHS,
                                         const Value *RHS) const {
  auto It = DomCondMap.find(BB);
  if (It == DomCondMap.end())
    return {nullptr, CmpInst::BAD_ICMP_PREDICATE};

  for (const auto &Cond : It->second) {
    if (Cond.LHS == LHS && Cond.RHS == RHS)
      return {Cond.DomBB, Cond.Pred};

    if (Cond.LHS == RHS && Cond.RHS == LHS)
      return {Cond.DomBB, CmpInst::getSwappedPredicate(Cond.Pred)};
  }
  return {nullptr, CmpInst::BAD_ICMP_PREDICATE};
}
