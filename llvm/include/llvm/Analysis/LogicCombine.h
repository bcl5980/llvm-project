//===------------------ LogicCombine.h --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "LogicalExpr.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/Allocator.h"

namespace llvm {

class LogicCombiner;

class LogicalOpNode {
private:
  LogicCombiner *Helper;
  Value *Val;
  LogicalExpr Expr;
  unsigned Weight;
  unsigned OneUseWeight;
  uint64_t PoisonMaskSI; // Record Poison from Select Inst True/False Value

  void printAndChain(raw_ostream &OS, uint64_t LeafBits) const;

public:
  LogicalOpNode(LogicCombiner *Helper, Value *Val, const LogicalExpr &SrcExpr,
                unsigned Weight, unsigned OneUseWeight, uint64_t PoisonMaskSI)
      : Helper(Helper), Val(Val), Expr(SrcExpr), Weight(Weight),
        OneUseWeight(OneUseWeight), PoisonMaskSI(PoisonMaskSI) {}
  ~LogicalOpNode() {}

  Value *getValue() const { return Val; }
  const LogicalExpr &getExpr() const { return Expr; }
  unsigned getWeight() const { return Weight; }
  unsigned getOneUseWeight() const { return OneUseWeight; }
  uint64_t getPoisonMaskSI() const { return PoisonMaskSI; }

  bool worthToCombine(unsigned InstCnt) const {
    return (OneUseWeight + InstCnt) < Weight;
  }
  void print(raw_ostream &OS) const;
};

class LogicCombiner {
public:
  LogicCombiner()
      : LogicalOpNodes(), LeafValues(), LeafsMayPoison(), ConstantLeafs() {}
  ~LogicCombiner() { clear(); }

  Value *simplify(Value *Root, bool simplifyOnly = true);
  Value *simplify(unsigned Opcode, Value *LHS, Value *RHS,
                  bool simplifyOnly = true);

private:
  friend class LogicalOpNode;

  SpecificBumpPtrAllocator<LogicalOpNode> Alloc;
  SmallDenseMap<Value *, LogicalOpNode *, 16> LogicalOpNodes;
  SmallSetVector<Value *, 8> LeafValues;
  uint64_t LeafsMayPoison;
  uint64_t ConstantLeafs;
  Constant *ConstAllOne;
  Constant *ConstZero;

  void clear();

  LogicalOpNode *visitLeafNode(Value *Val, unsigned Depth);
  LogicalOpNode *visitBinOp(BinaryOperator *BO, unsigned Depth);
  LogicalOpNode *visitSelect(SelectInst *SI, unsigned Depth);
  LogicalOpNode *getLogicalOpNode(Value *Val, unsigned Depth = 0);
  void foldConstForExpr(LogicalExpr &Expr);

  Value *logicalOpToValue(LogicalOpNode *Node, bool simplifyOnly);
  Value *buildAndChain(Instruction *I, uint64_t LeafBits, bool simplifyOnly);
};

inline raw_ostream &operator<<(raw_ostream &OS, const LogicalOpNode &I) {
  I.print(OS);
  return OS;
}

} // namespace llvm
