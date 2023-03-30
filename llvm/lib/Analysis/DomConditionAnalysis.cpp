//===- DomConditionAnalysis.cpp -------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/DomConditionAnalysis.h"
#include "llvm/InitializePasses.h"

using namespace llvm;

#define DEBUG_TYPE "dom-condition-analysis"

DomConditionInfo::DomConditionInfo(Function &F, DominatorTree &DT) {
  for (auto &BB : F) {
    if (BB.isEntryBlock())
      continue;

    const auto *DTNode = DT.getNode(&BB);
    if (!DTNode)
      continue;

    while (DTNode->getIDom()) {
      const auto *IDom = DTNode->getIDom();
      const auto *IDomBB = IDom->getBlock();

      // We only handle the case where the terminator has two successors for
      // now.
      const auto *IDomTerm = IDomBB->getTerminator();
      if (IDomTerm->getNumSuccessors() != 2)
        break;

      const auto *IDomCond = dyn_cast<ICmpInst>(IDomTerm->getOperand(0));
      // We only handle the case where the terminator is an icmp for now.
      if (!IDomCond)
        break;

      // Check if the true edge dominates the current block.
      const auto *TrueBB = IDomBB->getTerminator()->getSuccessor(0);
      BasicBlockEdge TrueEdge(IDomBB, TrueBB);
      if (DT.dominates(TrueEdge, &BB))
        DomCondMap[&BB].push_back({IDomBB, IDomCond->getOperand(0),
                                   IDomCond->getOperand(1),
                                   IDomCond->getPredicate()});

      // Check if the false edge dominates the current block.
      const auto *FalseBB = IDomBB->getTerminator()->getSuccessor(1);
      BasicBlockEdge FalseEdge(IDomBB, FalseBB);
      if (DT.dominates(FalseEdge, &BB))
        DomCondMap[&BB].push_back({IDomBB, IDomCond->getOperand(0),
                                   IDomCond->getOperand(1),
                                   IDomCond->getInversePredicate()});
      DTNode = IDom;
      continue;
    }
  }
}

void DomConditionInfo::print(raw_ostream &OS) const {
  for (const auto &Entry : DomCondMap) {
    OS << "BB: " << Entry.first->getName() << ": ";
    for (const auto &Cond : Entry.second) {
      OS << "(" << *Cond.LHS << ", " << *Cond.RHS << ", "
         << CmpInst::getPredicateName(Cond.Pred) << ") ";
    }
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

AnalysisKey DomConditionAnalysis::Key;

DomConditionAnalysis::Result
DomConditionAnalysis::run(Function &F, FunctionAnalysisManager &AM) {
  auto &DT = AM.getResult<DominatorTreeAnalysis>(F);
  return DomConditionInfo(F, DT);
}

PreservedAnalyses
DomConditionAnalysisPrinterPass::run(Function &F,
                                     FunctionAnalysisManager &FAM) {
  auto &DCA = FAM.getResult<DomConditionAnalysis>(F);
  OS << "'Dominate Condition Analysis for function '" << F.getName() << "':\n";
  DCA.print(OS);
  return PreservedAnalyses::all();
}

char DomConditionWrapper::ID = 0;

DomConditionWrapper::DomConditionWrapper() : FunctionPass(ID), DCI() {
  initializeDomConditionWrapperPass(*PassRegistry::getPassRegistry());
}

INITIALIZE_PASS_BEGIN(DomConditionWrapper, DEBUG_TYPE,
                      "Generate dominate condition info", false, true)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_END(DomConditionWrapper, DEBUG_TYPE,
                    "Generate dominate condition info", false, true)

bool DomConditionWrapper::runOnFunction(Function &F) {
  auto &DT = getAnalysis<DominatorTreeWrapperPass>().getDomTree();
  DCI = DomConditionInfo(F, DT);
  return false;
}

void DomConditionWrapper::verifyAnalysis() const {}

void DomConditionWrapper::print(raw_ostream &OS, const Module *) const {
  DCI.print(OS);
}
