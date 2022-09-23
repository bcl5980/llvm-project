// RUN: %clang_cc1 %s -triple=arm64ec-pc-windows-msvc -emit-llvm -fms-compatibility -o - | FileCheck %s

#pragma pack(push, 1)

struct __declspec(align(1)) s1 {
  char a[1];
};
s1 (*pfnstruct1)(s1 x);
s1 callstruct1(s1 x) { return pfnstruct1(x); };
struct __declspec(align(8)) s2 {
  char a[2];
};
s2 (*pfnstruct2)(s2 x);
s2 callstruct2(s2 x) { return pfnstruct2(x); };
struct __declspec(align(64)) s3 {
  char a[3];
};
s3 (*pfnstruct3)(s3 x);
s3 callstruct3(s3 x) { return pfnstruct3(x); };
struct __declspec(align(32)) s4 {
  char a[4];
};
s4 (*pfnstruct4)(s4 x);
s4 callstruct4(s4 x) { return pfnstruct4(x); };
struct __declspec(align(2)) s5 {
  char a[5];
};
s5 (*pfnstruct5)(s5 x);
s5 callstruct5(s5 x) { return pfnstruct5(x); };
struct __declspec(align(4)) s6 {
  char a[6];
};
s6 (*pfnstruct6)(s6 x);
s6 callstruct6(s6 x) { return pfnstruct6(x); };
struct __declspec(align(8)) s7 {
  char a[7];
};
s7 (*pfnstruct7)(s7 x);
s7 callstruct7(s7 x) { return pfnstruct7(x); };
struct __declspec(align(16)) s8 {
  char a[8];
};
s8 (*pfnstruct8)(s8 x);
s8 callstruct8(s8 x) { return pfnstruct8(x); };
struct __declspec(align(4)) s9 {
  char a[9];
};
s9 (*pfnstruct9)(s9 x);
s9 callstruct9(s9 x) { return pfnstruct9(x); };
struct __declspec(align(2)) s10 {
  char a[10];
};
s10 (*pfnstruct10)(s10 x);
s10 callstruct10(s10 x) { return pfnstruct10(x); };
struct __declspec(align(1)) s11 {
  char a[11];
};
s11 (*pfnstruct11)(s11 x);
s11 callstruct11(s11 x) { return pfnstruct11(x); };
struct __declspec(align(64)) s12 {
  char a[12];
};
s12 (*pfnstruct12)(s12 x);
s12 callstruct12(s12 x) { return pfnstruct12(x); };
struct __declspec(align(8)) s13 {
  char a[13];
};
s13 (*pfnstruct13)(s13 x);
s13 callstruct13(s13 x) { return pfnstruct13(x); };
struct __declspec(align(4)) s14 {
  char a[14];
};
s14 (*pfnstruct14)(s14 x);
s14 callstruct14(s14 x) { return pfnstruct14(x); };
struct __declspec(align(16)) s15 {
  char a[15];
};
s15 (*pfnstruct15)(s15 x);
s15 callstruct15(s15 x) { return pfnstruct15(x); };
struct __declspec(align(32)) s16 {
  char a[16];
};
s16 (*pfnstruct16)(s16 x);
s16 callstruct16(s16 x) { return pfnstruct16(x); };
struct __declspec(align(64)) s17 {
  char a[17];
};
s17 (*pfnstruct17)(s17 x);
s17 callstruct17(s17 x) { return pfnstruct17(x); };
struct __declspec(align(4)) s33 {
  char a[33];
};
s33 (*pfnstruct33)(s33 x);
s33 callstruct33(s33 x) { return pfnstruct33(x); };
struct __declspec(align(2)) s65 {
  char a[65];
};
s65 (*pfnstruct65)(s65 x);
s65 callstruct65(s65 x) { return pfnstruct65(x); };
struct __declspec(align(16)) s129 {
  char a[129];
};
s129 (*pfnstruct129)(s129 x);
s129 callstruct129(s129 x) { return pfnstruct129(x); };
struct __declspec(align(32)) s257 {
  char a[257];
};
s257 (*pfnstruct257)(s257 x);
s257 callstruct257(s257 x) { return pfnstruct257(x); };
struct __declspec(align(8)) f2 {
  float a[2];
};
f2 (*pfnstructf2)(f2 x);
f2 callstructf2(f2 x) { return pfnstructf2(x); };
struct __declspec(align(64)) f3 {
  float a[3];
};
f3 (*pfnstructf3)(f3 x);
f3 callstructf3(f3 x) { return pfnstructf3(x); };
struct __declspec(align(32)) f4 {
  float a[4];
};
f4 (*pfnstructf4)(f4 x);
f4 callstructf4(f4 x) { return pfnstructf4(x); };
struct __declspec(align(32)) f5 {
  float a[5];
};
f5 (*pfnstructf5)(f5 x);
f5 callstructf5(f5 x) { return pfnstructf5(x); };
struct __declspec(align(64))  d2 {
  double a[2];
};
d2 (*pfnstructd2)(d2 x);
d2 callstructd2(d2 x) { return pfnstructd2(x); };
struct __declspec(align(64)) d3 {
  double a[3];
};
d3 (*pfnstructd3)(d3 x);
d3 callstructd3(d3 x) { return pfnstructd3(x); };
struct __declspec(align(16)) d4 {
  double a[4];
};
d4 (*pfnstructd4)(d4 x);
d4 callstructd4(d4 x) { return pfnstructd4(x); };
struct __declspec(align(16)) d5 {
  double a[5];
};
d5 (*pfnstructd5)(d5 x);
d5 callstructd5(d5 x) { return pfnstructd5(x); };
#pragma pack(pop)

// CHECK: define dso_local arm64ec_argsize(1) i8 @"?callstruct1@@$$hYA?AUs1@@U1@@Z"(i64 arm64ec_argsize(1) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(8) i64 @"?callstruct2@@$$hYA?AUs2@@U1@@Z"(i64 arm64ec_argsize(8) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(64) void @"?callstruct3@@$$hYA?AUs3@@U1@@Z"(ptr noalias sret(%struct.s3) align 64 %agg.result, ptr noundef arm64ec_argsize(64) %x)
// CHECK: define dso_local arm64ec_argsize(32) void @"?callstruct4@@$$hYA?AUs4@@U1@@Z"(ptr noalias sret(%struct.s4) align 32 %agg.result, ptr noundef arm64ec_argsize(32) %x)
// CHECK: define dso_local arm64ec_argsize(6) i48 @"?callstruct5@@$$hYA?AUs5@@U1@@Z"(i64 arm64ec_argsize(6) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(8) i64 @"?callstruct6@@$$hYA?AUs6@@U1@@Z"(i64 arm64ec_argsize(8) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(8) i64 @"?callstruct7@@$$hYA?AUs7@@U1@@Z"(i64 arm64ec_argsize(8) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(16) i128 @"?callstruct8@@$$hYA?AUs8@@U1@@Z"(i128 arm64ec_argsize(16) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(12) [2 x i64] @"?callstruct9@@$$hYA?AUs9@@U1@@Z"([2 x i64] arm64ec_argsize(12) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(10) [2 x i64] @"?callstruct10@@$$hYA?AUs10@@U1@@Z"([2 x i64] arm64ec_argsize(10) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(11) [2 x i64] @"?callstruct11@@$$hYA?AUs11@@U1@@Z"([2 x i64] arm64ec_argsize(11) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(64) void @"?callstruct12@@$$hYA?AUs12@@U1@@Z"(ptr noalias sret(%struct.s12) align 64 %agg.result, ptr noundef arm64ec_argsize(64) %x)
// CHECK: define dso_local arm64ec_argsize(16) [2 x i64] @"?callstruct13@@$$hYA?AUs13@@U1@@Z"([2 x i64] arm64ec_argsize(16) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(16) [2 x i64] @"?callstruct14@@$$hYA?AUs14@@U1@@Z"([2 x i64] arm64ec_argsize(16) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(16) i128 @"?callstruct15@@$$hYA?AUs15@@U1@@Z"(i128 arm64ec_argsize(16) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(32) void @"?callstruct16@@$$hYA?AUs16@@U1@@Z"(ptr noalias sret(%struct.s16) align 32 %agg.result, ptr noundef arm64ec_argsize(32) %x)
// CHECK: define dso_local arm64ec_argsize(64) void @"?callstruct17@@$$hYA?AUs17@@U1@@Z"(ptr noalias sret(%struct.s17) align 64 %agg.result, ptr noundef arm64ec_argsize(64) %x)
// CHECK: define dso_local arm64ec_argsize(36) void @"?callstruct33@@$$hYA?AUs33@@U1@@Z"(ptr noalias sret(%struct.s33) align 4 %agg.result, ptr noundef arm64ec_argsize(36) %x)
// CHECK: define dso_local arm64ec_argsize(66) void @"?callstruct65@@$$hYA?AUs65@@U1@@Z"(ptr noalias sret(%struct.s65) align 2 %agg.result, ptr noundef arm64ec_argsize(66) %x)
// CHECK: define dso_local arm64ec_argsize(144) void @"?callstruct129@@$$hYA?AUs129@@U1@@Z"(ptr noalias sret(%struct.s129) align 16 %agg.result, ptr noundef arm64ec_argsize(144) %x)
// CHECK: define dso_local arm64ec_argsize(288) void @"?callstruct257@@$$hYA?AUs257@@U1@@Z"(ptr noalias sret(%struct.s257) align 32 %agg.result, ptr noundef arm64ec_argsize(288) %x)
// CHECK: define dso_local arm64ec_argsize(8) %struct.f2 @"?callstructf2@@$$hYA?AUf2@@U1@@Z"([2 x float] arm64ec_argsize(8) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(64) void @"?callstructf3@@$$hYA?AUf3@@U1@@Z"(ptr noalias sret(%struct.f3) align 64 %agg.result, ptr noundef arm64ec_argsize(64) %x)
// CHECK: define dso_local arm64ec_argsize(32) void @"?callstructf4@@$$hYA?AUf4@@U1@@Z"(ptr noalias sret(%struct.f4) align 32 %agg.result, ptr noundef arm64ec_argsize(32) %x)
// CHECK: define dso_local arm64ec_argsize(32) void @"?callstructf5@@$$hYA?AUf5@@U1@@Z"(ptr noalias sret(%struct.f5) align 32 %agg.result, ptr noundef arm64ec_argsize(32) %x)
// CHECK: define dso_local arm64ec_argsize(64) void @"?callstructd2@@$$hYA?AUd2@@U1@@Z"(ptr noalias sret(%struct.d2) align 64 %agg.result, ptr noundef arm64ec_argsize(64) %x)
// CHECK: define dso_local arm64ec_argsize(64) void @"?callstructd3@@$$hYA?AUd3@@U1@@Z"(ptr noalias sret(%struct.d3) align 64 %agg.result, ptr noundef arm64ec_argsize(64) %x)
// CHECK: define dso_local arm64ec_argsize(32) %struct.d4 @"?callstructd4@@$$hYA?AUd4@@U1@@Z"([4 x double] arm64ec_argsize(32) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(48) void @"?callstructd5@@$$hYA?AUd5@@U1@@Z"(ptr noalias sret(%struct.d5) align 16 %agg.result, ptr noundef arm64ec_argsize(48) %x)
