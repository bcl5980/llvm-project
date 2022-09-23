// RUN: %clang_cc1 %s -triple=arm64ec-pc-windows-msvc -emit-llvm -fms-compatibility -o - | FileCheck %s

#pragma pack(push, 1)
typedef long long i64;
typedef long double longdouble;
typedef void *VOIDP;
bool (*pfnbool)(bool x);
bool callbool(bool x) { return pfnbool(x); };
char (*pfnchar)(char x);
char callchar(char x) { return pfnchar(x); };
short (*pfnshort)(short x);
short callshort(short x) { return pfnshort(x); };
wchar_t (*pfnwchar_t)(wchar_t x);
wchar_t callwchar_t(wchar_t x) { return pfnwchar_t(x); };
int (*pfnint)(int x);
int callint(int x) { return pfnint(x); };
i64 (*pfni64)(i64 x);
i64 calli64(i64 x) { return pfni64(x); };
float (*pfnfloat)(float x);
float callfloat(float x) { return pfnfloat(x); };
double (*pfndouble)(double x);
double calldouble(double x) { return pfndouble(x); };
longdouble (*pfnlongdouble)(longdouble x);
longdouble calllongdouble(longdouble x) { return pfnlongdouble(x); };
VOIDP (*pfnVOIDP)(VOIDP x);
VOIDP callVOIDP(VOIDP x) { return pfnVOIDP(x); };
#pragma pack(pop)

// CHECK: define dso_local noundef i1 @"?callbool@@$$hYA_N_N@Z"(i1 noundef %x)
// CHECK: define dso_local noundef i8 @"?callchar@@$$hYADD@Z"(i8 noundef %x)
// CHECK: define dso_local noundef i16 @"?callshort@@$$hYAFF@Z"(i16 noundef %x)
// CHECK: define dso_local noundef i16 @"?callwchar_t@@$$hYA_W_W@Z"(i16 noundef %x)
// CHECK: define dso_local noundef i32 @"?callint@@$$hYAHH@Z"(i32 noundef %x)
// CHECK: define dso_local noundef i64 @"?calli64@@$$hYA_J_J@Z"(i64 noundef %x)
// CHECK: define dso_local noundef float @"?callfloat@@$$hYAMM@Z"(float noundef %x)
// CHECK: define dso_local noundef double @"?calldouble@@$$hYANN@Z"(double noundef %x)
// CHECK: define dso_local noundef double @"?calllongdouble@@$$hYAOO@Z"(double noundef %x)
// CHECK: define dso_local noundef ptr @"?callVOIDP@@$$hYAPEAXPEAX@Z"(ptr noundef %x)
