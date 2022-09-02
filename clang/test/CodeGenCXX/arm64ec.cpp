// RUN: %clang_cc1 -no-opaque-pointers -triple arm64ec-windows-msvc -emit-llvm -o - %s | FileCheck %s

// CHECK: @"?g@@YAXUA@@UB@@@Z" = alias void ([2 x float], [4 x float]), void ([2 x float], [4 x float])* @"?g@@$$hYAXUA@@UB@@@Z"
// CHECK: define dso_local void @"?g@@$$hYAXUA@@UB@@@Z"
typedef struct { float x[2]; } A;
typedef struct { float x[4]; } B;
void g(A a, B b) { }
