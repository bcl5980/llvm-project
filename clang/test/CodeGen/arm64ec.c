// RUN: %clang_cc1 -no-opaque-pointers -triple arm64ec-windows-msvc -emit-llvm -o - %s | FileCheck %s

// CHECK: @g = alias void ([2 x float], [4 x float]), void ([2 x float], [4 x float])* @"#g"
// CHECK: define dso_local void @"#g"
// CHECK: call void (i64, ...) @f(i64 %{{.*}}, %struct.B* noundef %{{.*}})
typedef struct { float x[2]; } A;
typedef struct { float x[4]; } B;
void f(A a, ...);
void g(A a, B b) { f(a, b); }
