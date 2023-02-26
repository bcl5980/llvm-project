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

  void printAndChain(raw_ostream &OS, uint64_t LeafBits) const;

public:
  LogicalOpNode(LogicCombiner *Helper, Value *Val, const LogicalExpr &SrcExpr,
                unsigned Weight, unsigned OneUseWeight)
      : Helper(Helper), Val(Val), Expr(SrcExpr), Weight(Weight),
        OneUseWeight(OneUseWeight) {}
  ~LogicalOpNode() {}

  Value *getValue() const { return Val; }
  const LogicalExpr &getExpr() const { return Expr; }
  unsigned getWeight() const { return Weight; }
  unsigned getOneUseWeight() const { return OneUseWeight; }

  bool worthToCombine(unsigned InstCnt) const {
    return (OneUseWeight + InstCnt) < Weight;
  }
  void print(raw_ostream &OS) const;
};

class LogicCombiner {
public:
  LogicCombiner() {}
  ~LogicCombiner() { clear(); }

  Value *simplify(Value *Root);

private:
  friend class LogicalOpNode;

  SpecificBumpPtrAllocator<LogicalOpNode> Alloc;
  SmallDenseMap<Value *, LogicalOpNode *, 16> LogicalOpNodes;
  SmallSetVector<Value *, 8> LeafValues;

  void clear();

  LogicalOpNode *visitLeafNode(Value *Val, unsigned Depth);
  LogicalOpNode *visitBinOp(BinaryOperator *BO, unsigned Depth);
  LogicalOpNode *getLogicalOpNode(Value *Val, unsigned Depth = 0);
  Value *logicalOpToValue(LogicalOpNode *Node);
  Value *buildAndChain(IRBuilder<> &Builder, Type *Ty, uint64_t LeafBits);
};

inline raw_ostream &operator<<(raw_ostream &OS, const LogicalOpNode &I) {
  I.print(OS);
  return OS;
}

} // namespace llvm
