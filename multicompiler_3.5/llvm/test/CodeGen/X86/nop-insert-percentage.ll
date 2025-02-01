; RUN: llc < %s -rng-seed=5 -nop-insertion -nop-insertion-percentage=10 \
; RUN:     | FileCheck %s --check-prefix=PERCENT10
; RUN: llc < %s -rng-seed=5 -nop-insertion -nop-insertion-percentage=50 \
; RUN:     | FileCheck %s --check-prefix=PERCENT50
; RUN: llc < %s -rng-seed=5 -nop-insertion -nop-insertion-percentage=100 \
; RUN:     | FileCheck %s --check-prefix=PERCENT100

; This test case tests NOP insertion at varying percentage levels.

define i32 @test(i32 %x, i32 %y, i32 %z) {
entry:
    %t1 = add i32 %x, %y
    %t2 = mul i32 %t1, %z
    %t3 = add i32 %t2, %x
    %t4 = mul i32 %t3, %z
    %t5 = add i32 %t4, %x
    %t6 = mul i32 %t5, %z
    %t7 = add i32 %t6, %x
    %t8 = mul i32 %t7, %z
    %t9 = add i32 %t8, %x
    %t10 = mul i32 %t9, %z
    %t11 = add i32 %t10, %x
    ret i32 %t11
}

; PERCENT10: leaq   (%rsi), %rsi

; PERCENT50: movq   %rbp, %rbp
; PERCENT50: nop
; PERCENT50: leaq   (%rsi), %rsi
; PERCENT50: leaq   (%rdi), %rdi
; PERCENT50: movq   %rbp, %rbp
; PERCENT50: movq   %rsp, %rsp

; PERCENT100: leaq  (%rdi), %rdi
; PERCENT100: leaq  (%rdi), %rdi
; PERCENT100: movq  %rsp, %rsp
; PERCENT100: movq  %rsp, %rsp
; PERCENT100: leaq  (%rdi), %rdi
; PERCENT100: leaq  (%rsi), %rsi
; PERCENT100: movq  %rbp, %rbp
; PERCENT100: movq  %rsp, %rsp
; PERCENT100: leaq  (%rsi), %rsi
; PERCENT100: nop
; PERCENT100: leaq  (%rsi), %rsi
