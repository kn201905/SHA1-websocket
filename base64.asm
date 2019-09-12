bits 64			; 64bit コードの指定
default rel		; デフォルトで RIP相対アドレシングを利用する

global  ASM_base64
global  ASM_base64_stub

; ========================================================
section .data align=16		; movdqa を利用するため

DQ_PSHUFB:
	DB  'a'-26, '0'-52, '0'-52, '0'-52, '0'-52, '0'-52, '0'-52, '0'-52
	DB  '0'-52, '0'-52, '0'-52, '+'-62, '/'-63, 'A', 0, 0

DQ_RET_VAL:
	times 16 DB 0


; ========================================================
section .text align=4096

; ////////////////////////////////////////////////////////

; C++ との連携をとるスタブコード
ASM_base64_stub:
	push	rbx
	push	rbp

	mov		rax, rdi	; 第１引数
	mov		rbx, rsi	; 第２引数


	call	ASM_base64


	movdqa	[DQ_RET_VAL], xmm0
	mov		rax, DQ_RET_VAL

	pop		rbp
	pop		rbx
	ret


; rax に最初の６文字、rbx に次の６文字を受け取って、xmm0 に結果を入れて返す
; 各レジスタには xxABCDEF の形でデータをストアしておくこと
ASM_base64:
	mov		rcx, 0x3f3f3f3f3f3f3f3f
	pdep	rdx, rax, rcx
	movq	xmm1, rdx

	pdep	rdx, rbx, rcx
	movq	xmm0, rdx
	punpcklqdq	xmm0, xmm1			; xmm0 に 6 bits x 16 のデータが設定された

	mov		eax, 51
	vmovd	xmm1, eax
	vpbroadcastb	xmm2, xmm1
	vpsubusb	xmm3, xmm0, xmm2	; xmm3 <- 0 - 12 の値となる

	mov		eax, 25
	vmovd	xmm1, eax
	vpbroadcastb	xmm2, xmm1
	vpcmpgtb	xmm4, xmm0, xmm2	; xmm4 <- 0 - 25 のところがゼロ

	mov		eax, 13
	vmovd	xmm1, eax
	vpbroadcastb	xmm2, xmm1
	vpandn		xmm5, xmm4, xmm2	; xmm5 <- 0 - 25 のところが 13

	por		xmm3, xmm5				; xmm3 =  0 - 25 -> 13
									;        25 - 51 -> 0
									;        52 - 63 -> 1 - 12
	movdqa	xmm1, [DQ_PSHUFB]
	pshufb	xmm1, xmm3
	paddb	xmm0, xmm1

	ret
