// RUN: %clang_cc1 %s -triple=arm64ec-pc-windows-msvc -emit-llvm -fms-compatibility -o - | FileCheck %s

#pragma pack(push, 1)
struct s1 {
  char a[1];
};
s1 (*pfnstruct1)(s1 x);
s1 callstruct1(s1 x) { return pfnstruct1(x); };
struct s2 {
  char a[2];
};
s2 (*pfnstruct2)(s2 x);
s2 callstruct2(s2 x) { return pfnstruct2(x); };
struct s3 {
  char a[3];
};
s3 (*pfnstruct3)(s3 x);
s3 callstruct3(s3 x) { return pfnstruct3(x); };
struct s4 {
  char a[4];
};
s4 (*pfnstruct4)(s4 x);
s4 callstruct4(s4 x) { return pfnstruct4(x); };
struct s5 {
  char a[5];
};
s5 (*pfnstruct5)(s5 x);
s5 callstruct5(s5 x) { return pfnstruct5(x); };
struct s6 {
  char a[6];
};
s6 (*pfnstruct6)(s6 x);
s6 callstruct6(s6 x) { return pfnstruct6(x); };
struct s7 {
  char a[7];
};
s7 (*pfnstruct7)(s7 x);
s7 callstruct7(s7 x) { return pfnstruct7(x); };
struct s8 {
  char a[8];
};
s8 (*pfnstruct8)(s8 x);
s8 callstruct8(s8 x) { return pfnstruct8(x); };
struct s9 {
  char a[9];
};
s9 (*pfnstruct9)(s9 x);
s9 callstruct9(s9 x) { return pfnstruct9(x); };
struct s10 {
  char a[10];
};
s10 (*pfnstruct10)(s10 x);
s10 callstruct10(s10 x) { return pfnstruct10(x); };
struct s11 {
  char a[11];
};
s11 (*pfnstruct11)(s11 x);
s11 callstruct11(s11 x) { return pfnstruct11(x); };
struct s12 {
  char a[12];
};
s12 (*pfnstruct12)(s12 x);
s12 callstruct12(s12 x) { return pfnstruct12(x); };
struct s13 {
  char a[13];
};
s13 (*pfnstruct13)(s13 x);
s13 callstruct13(s13 x) { return pfnstruct13(x); };
struct s14 {
  char a[14];
};
s14 (*pfnstruct14)(s14 x);
s14 callstruct14(s14 x) { return pfnstruct14(x); };
struct s15 {
  char a[15];
};
s15 (*pfnstruct15)(s15 x);
s15 callstruct15(s15 x) { return pfnstruct15(x); };
struct s16 {
  char a[16];
};
s16 (*pfnstruct16)(s16 x);
s16 callstruct16(s16 x) { return pfnstruct16(x); };
struct s17 {
  char a[17];
};
s17 (*pfnstruct17)(s17 x);
s17 callstruct17(s17 x) { return pfnstruct17(x); };
struct s32 {
  char a[32];
};
s32 (*pfnstruct32)(s32 x);
s32 callstruct32(s32 x) { return pfnstruct32(x); };
struct s33 {
  char a[33];
};
s33 (*pfnstruct33)(s33 x);
s33 callstruct33(s33 x) { return pfnstruct33(x); };
struct s64 {
  char a[64];
};
s64 (*pfnstruct64)(s64 x);
s64 callstruct64(s64 x) { return pfnstruct64(x); };
struct s65 {
  char a[65];
};
s65 (*pfnstruct65)(s65 x);
s65 callstruct65(s65 x) { return pfnstruct65(x); };
struct s128 {
  char a[128];
};
s128 (*pfnstruct128)(s128 x);
s128 callstruct128(s128 x) { return pfnstruct128(x); };
struct s133 {
  char a[133];
};
s133 (*pfnstruct133)(s133 x);
s133 callstruct133(s133 x) { return pfnstruct133(x); };
struct s192 {
  char a[192];
};
s192 (*pfnstruct192)(s192 x);
s192 callstruct192(s192 x) { return pfnstruct192(x); };
struct s223 {
  char a[223];
};
s223 (*pfnstruct223)(s223 x);
s223 callstruct223(s223 x) { return pfnstruct223(x); };
struct s256 {
  char a[256];
};
s256 (*pfnstruct256)(s256 x);
s256 callstruct256(s256 x) { return pfnstruct256(x); };
struct s257 {
  char a[257];
};
s257 (*pfnstruct257)(s257 x);
s257 callstruct257(s257 x) { return pfnstruct257(x); };
struct f2 {
  float a[2];
};
f2 (*pfnstructf2)(f2 x);
f2 callstructf2(f2 x) { return pfnstructf2(x); };
struct f3 {
  float a[3];
};
f3 (*pfnstructf3)(f3 x);
f3 callstructf3(f3 x) { return pfnstructf3(x); };
struct f4 {
  float a[4];
};
f4 (*pfnstructf4)(f4 x);
f4 callstructf4(f4 x) { return pfnstructf4(x); };
struct f5 {
  float a[5];
};
f5 (*pfnstructf5)(f5 x);
f5 callstructf5(f5 x) { return pfnstructf5(x); };
struct d2 {
  double a[2];
};
d2 (*pfnstructd2)(d2 x);
d2 callstructd2(d2 x) { return pfnstructd2(x); };
struct d3 {
  double a[3];
};
d3 (*pfnstructd3)(d3 x);
d3 callstructd3(d3 x) { return pfnstructd3(x); };
struct d4 {
  double a[4];
};
d4 (*pfnstructd4)(d4 x);
d4 callstructd4(d4 x) { return pfnstructd4(x); };
struct d5 {
  double a[5];
};
d5 (*pfnstructd5)(d5 x);
d5 callstructd5(d5 x) { return pfnstructd5(x); };
#pragma pack(pop)

// CHECK: define dso_local arm64ec_argsize(1) i8 @"?callstruct1@@$$hYA?AUs1@@U1@@Z"(i64 arm64ec_argsize(1) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(2) i16 @"?callstruct2@@$$hYA?AUs2@@U1@@Z"(i64 arm64ec_argsize(2) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(3) i24 @"?callstruct3@@$$hYA?AUs3@@U1@@Z"(i64 arm64ec_argsize(3) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(4) i32 @"?callstruct4@@$$hYA?AUs4@@U1@@Z"(i64 arm64ec_argsize(4) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(5) i40 @"?callstruct5@@$$hYA?AUs5@@U1@@Z"(i64 arm64ec_argsize(5) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(6) i48 @"?callstruct6@@$$hYA?AUs6@@U1@@Z"(i64 arm64ec_argsize(6) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(7) i56 @"?callstruct7@@$$hYA?AUs7@@U1@@Z"(i64 arm64ec_argsize(7) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(8) i64 @"?callstruct8@@$$hYA?AUs8@@U1@@Z"(i64 arm64ec_argsize(8) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(9) [2 x i64] @"?callstruct9@@$$hYA?AUs9@@U1@@Z"([2 x i64] arm64ec_argsize(9) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(10) [2 x i64] @"?callstruct10@@$$hYA?AUs10@@U1@@Z"([2 x i64] arm64ec_argsize(10) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(11) [2 x i64] @"?callstruct11@@$$hYA?AUs11@@U1@@Z"([2 x i64] arm64ec_argsize(11) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(12) [2 x i64] @"?callstruct12@@$$hYA?AUs12@@U1@@Z"([2 x i64] arm64ec_argsize(12) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(13) [2 x i64] @"?callstruct13@@$$hYA?AUs13@@U1@@Z"([2 x i64] arm64ec_argsize(13) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(14) [2 x i64] @"?callstruct14@@$$hYA?AUs14@@U1@@Z"([2 x i64] arm64ec_argsize(14) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(15) [2 x i64] @"?callstruct15@@$$hYA?AUs15@@U1@@Z"([2 x i64] arm64ec_argsize(15) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(16) [2 x i64] @"?callstruct16@@$$hYA?AUs16@@U1@@Z"([2 x i64] arm64ec_argsize(16) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(17) void @"?callstruct17@@$$hYA?AUs17@@U1@@Z"(ptr noalias sret(%struct.s17) align 1 %agg.result, ptr noundef arm64ec_argsize(17) %x)
// CHECK: define dso_local arm64ec_argsize(32) void @"?callstruct32@@$$hYA?AUs32@@U1@@Z"(ptr noalias sret(%struct.s32) align 1 %agg.result, ptr noundef arm64ec_argsize(32) %x)
// CHECK: define dso_local arm64ec_argsize(33) void @"?callstruct33@@$$hYA?AUs33@@U1@@Z"(ptr noalias sret(%struct.s33) align 1 %agg.result, ptr noundef arm64ec_argsize(33) %x)
// CHECK: define dso_local arm64ec_argsize(64) void @"?callstruct64@@$$hYA?AUs64@@U1@@Z"(ptr noalias sret(%struct.s64) align 1 %agg.result, ptr noundef arm64ec_argsize(64) %x)
// CHECK: define dso_local arm64ec_argsize(65) void @"?callstruct65@@$$hYA?AUs65@@U1@@Z"(ptr noalias sret(%struct.s65) align 1 %agg.result, ptr noundef arm64ec_argsize(65) %x)
// CHECK: define dso_local arm64ec_argsize(128) void @"?callstruct128@@$$hYA?AUs128@@U1@@Z"(ptr noalias sret(%struct.s128) align 1 %agg.result, ptr noundef arm64ec_argsize(128) %x)
// CHECK: define dso_local arm64ec_argsize(133) void @"?callstruct133@@$$hYA?AUs133@@U1@@Z"(ptr noalias sret(%struct.s133) align 1 %agg.result, ptr noundef arm64ec_argsize(133) %x)
// CHECK: define dso_local arm64ec_argsize(192) void @"?callstruct192@@$$hYA?AUs192@@U1@@Z"(ptr noalias sret(%struct.s192) align 1 %agg.result, ptr noundef arm64ec_argsize(192) %x)
// CHECK: define dso_local arm64ec_argsize(223) void @"?callstruct223@@$$hYA?AUs223@@U1@@Z"(ptr noalias sret(%struct.s223) align 1 %agg.result, ptr noundef arm64ec_argsize(223) %x)
// CHECK: define dso_local arm64ec_argsize(256) void @"?callstruct256@@$$hYA?AUs256@@U1@@Z"(ptr noalias sret(%struct.s256) align 1 %agg.result, ptr noundef arm64ec_argsize(256) %x)
// CHECK: define dso_local arm64ec_argsize(257) void @"?callstruct257@@$$hYA?AUs257@@U1@@Z"(ptr noalias sret(%struct.s257) align 1 %agg.result, ptr noundef arm64ec_argsize(257) %x)
// CHECK: define dso_local arm64ec_argsize(8) %struct.f2 @"?callstructf2@@$$hYA?AUf2@@U1@@Z"([2 x float] arm64ec_argsize(8) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(12) %struct.f3 @"?callstructf3@@$$hYA?AUf3@@U1@@Z"([3 x float] arm64ec_argsize(12) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(16) %struct.f4 @"?callstructf4@@$$hYA?AUf4@@U1@@Z"([4 x float] arm64ec_argsize(16) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(20) void @"?callstructf5@@$$hYA?AUf5@@U1@@Z"(ptr noalias sret(%struct.f5) align 1 %agg.result, ptr noundef arm64ec_argsize(20) %x)
// CHECK: define dso_local arm64ec_argsize(16) %struct.d2 @"?callstructd2@@$$hYA?AUd2@@U1@@Z"([2 x double] arm64ec_argsize(16) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(24) %struct.d3 @"?callstructd3@@$$hYA?AUd3@@U1@@Z"([3 x double] arm64ec_argsize(24) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(32) %struct.d4 @"?callstructd4@@$$hYA?AUd4@@U1@@Z"([4 x double] arm64ec_argsize(32) %x.coerce)
// CHECK: define dso_local arm64ec_argsize(40) void @"?callstructd5@@$$hYA?AUd5@@U1@@Z"(ptr noalias sret(%struct.d5) align 1 %agg.result, ptr noundef arm64ec_argsize(40) %x)
