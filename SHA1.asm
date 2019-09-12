; https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1
; https://www.officedaytime.com/tips/simd.html

bits 64			; 64bit コードの指定
default rel		; デフォルトで RIP相対アドレシングを利用する

global  sha1_init_once
global  sha1_update_intel

%xdefine  A  ecx
%xdefine  B  esi
%xdefine  C  edi
%xdefine  D  ebp
%xdefine  E  edx
%xdefine  T1  eax
%xdefine  T2  ebx

%xdefine  A_64	rcx
%xdefine  B_64	rsi
%xdefine  C_64	rdi
%xdefine  D_64	rbp
%xdefine  E_64	rdx

%xdefine  FLG_2nd_BLK  r8		; =0 -> 1st loop, =1 -> 2nd loop
%xdefine  HASH_PTR  r9
%xdefine  BUFFER_PTR  r10
%xdefine  ADD_DEPO_W_TMP  r11d

%xdefine  W_TMP  xmm0
%xdefine  K_VAL_XMM  xmm9

%xdefine  XMM_SHUFB_BSWAP  xmm14	; W_PRECALC_00_15 でのみ利用
%xdefine  W_TMP2  xmm15				; W_PRECALC_16_31 でのみ利用


; -----------------------------------------
%macro  W_PRECALC_RESET  0
	%xdefine    W             xmm1
	%xdefine    W_minus_04    xmm2
	%xdefine    W_minus_08    xmm3
	%xdefine    W_minus_12    xmm4
	%xdefine    W_minus_16    xmm5
	%xdefine    W_minus_20    xmm6
	%xdefine    W_minus_24    xmm7
	%xdefine    W_minus_28    xmm8
	%xdefine    W_minus_32    W
%endmacro

%macro  W_PRECALC_ROTATE  0
	%xdefine    W_minus_32    W_minus_28
	%xdefine    W_minus_28    W_minus_24
	%xdefine    W_minus_24    W_minus_20
	%xdefine    W_minus_20    W_minus_16
	%xdefine    W_minus_16    W_minus_12
	%xdefine    W_minus_12    W_minus_08
	%xdefine    W_minus_08    W_minus_04
	%xdefine    W_minus_04    W
	%xdefine    W             W_minus_32
%endmacro


; -----------------------------------------
%define  XMM_(n)  xmm %+ n
%define  YMM_(n)  ymm %+ n
%xdefine  W_minus_8  W_minus_08
%xdefine  W_minus_4  W_minus_04

%macro  DEPO_W_INIT  0
	%assign  cnt_DEPO_W  0
	%assign  Yn  10

	; 以下は ADD_DEPO_W のみで使用するもの
	%assign  cnt_UP  52
	%assign  cnt_DOWN  32
%endmacro

%macro  DEPO_W  1		; 引数は、退避させたい xmm レジスタ
	%assign  cnt_DEPO_W  cnt_DEPO_W + 1

	%if (cnt_DEPO_W <= 12)
		%if ((cnt_DEPO_W & 1) == 1)
			movdqa		XMM_(Yn), %1
		%else
			vperm2i128	YMM_(Yn), YMM_(Yn), YMM_(Yn), 1
			movdqa		XMM_(Yn), %1
			vperm2i128	YMM_(Yn), YMM_(Yn), YMM_(Yn), 1
			%assign  Yn  Yn + 1
		%endif
	%endif
%endmacro


%define  W_MINUS_(n)  W_minus_ %+ n

%macro  ADD_DEPO_W  1	; 引数は、W + K を加算させる対象となる 32bit レジスタ
	%assign  cnt_DEPO_W  cnt_DEPO_W + 1

	%if (cnt_DEPO_W <= 48)
		movd	ADD_DEPO_W_TMP, XMM_(Yn)
		psrldq	XMM_(Yn), 4
		add		%1, ADD_DEPO_W_TMP

		%if ((cnt_DEPO_W & 3) == 0)
			%if ((cnt_DEPO_W & 7) == 0)
				%assign  Yn  Yn + 1
			%else
				vperm2i128	YMM_(Yn), YMM_(Yn), YMM_(Yn), 1
			%endif
		%endif
	
	%else
		movd	ADD_DEPO_W_TMP, W_MINUS_(cnt_DOWN)
		%if (cnt_DEPO_W < cnt_UP)
			psrldq	W_MINUS_(cnt_DOWN), 4
		%endif
		add		%1, ADD_DEPO_W_TMP

		%if (cnt_DEPO_W == cnt_UP)
			%assign  cnt_DOWN  cnt_DOWN - 4
			%assign  cnt_UP  cnt_UP + 4
		%endif

	%endif
%endmacro


; -----------------------------------------
%macro W_PRECALC_00_15  1
	movdqu	W, [BUFFER_PTR + %1]
	pshufb	W, XMM_SHUFB_BSWAP

	movdqa  W_TMP, W
	paddd	W_TMP, K_VAL_XMM
	DEPO_W	W_TMP

	W_PRECALC_ROTATE
%endmacro


%macro W_PRECALC_16_31  0
	movdqa  W, W_minus_12		; W = W_minus_12 = W7 W6 W5 W4
	palignr W, W_minus_16, 8	; W_minus_16 = W3 W2 W1 W0 -> W = W5 W4 W3 W2
	pxor    W, W_minus_08		; W_minus_08 = W11 W10 W9 W8 -> W = (W11 W10 W9 W8) ^ (W5 W4 W3 W2)

	movdqa  W_TMP, W_minus_04	; W_TMP = W_minus_04 = W15 W14 W13 W12
	psrldq  W_TMP, 4			; W_TMP = 0 W15 W14 W13
	pxor    W_TMP, W_minus_16	; W_TMP = (0 W15 W14 W13) ^ (W3 W2 W1 W0)
	pxor    W, W_TMP			; W = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)
	movdqa  W_TMP, W			; W_TMP = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)
	movdqa  W_TMP2, W			; W_TMP2 = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)

	pslld   W_TMP, 1
	psrld   W, 31
	por     W_TMP, W			; W_TMP = S^1((0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0))

	pslldq  W_TMP2, 12			; W_TMP2 = (W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0)
	movdqa  W, W_TMP2			; W = (W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0)
	pslld   W, 2
	psrld   W_TMP2, 30
	por		W, W_TMP2			; W = S^2((W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0))

	pxor	W, W_TMP			; W = S^2((W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0))
								;	^ (S^1((0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)))
								;   = (WW19 W18 W17 W16)
	movdqa  W_TMP, W
	paddd	W_TMP, K_VAL_XMM
	DEPO_W	W_TMP

	W_PRECALC_ROTATE
%endmacro


%macro W_PRECALC_32_47  0
;; in SHA-1 specification: w[i] = (w[i-3] ^ w[i-8]  ^ w[i-14] ^ w[i-16]) rol 1
;; instead we do equal:    w[i] = (w[i-6] ^ w[i-16] ^ w[i-28] ^ w[i-32]) rol 2

	movdqa  W_TMP, W_minus_04		; W_TMP = W31 W30 W29 W28
	palignr W_TMP, W_minus_08, 8	; W_TMP = W29 W28 W27 W26

	pxor    W, W_minus_28			; W = (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	pxor    W, W_minus_16			; W = (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	pxor    W, W_TMP				; W = (W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)

	movdqa  W_TMP, W
	psrld   W, 30
	pslld   W_TMP, 2
	por     W, W_TMP				; W = S^2((W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0))
									;   = W35 W34 W33 W32
	movdqa  W_TMP, W
	paddd	W_TMP, K_VAL_XMM
	DEPO_W	W_TMP

	W_PRECALC_ROTATE
%endmacro


%macro W_PRECALC_48_79  0
	movdqa  W_TMP, W_minus_04		; W_TMP = W31 W30 W29 W28
	palignr W_TMP, W_minus_08, 8	; W_TMP = W29 W28 W27 W26

	pxor    W, W_minus_28			; W = (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	pxor    W, W_minus_16			; W = (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	pxor    W, W_TMP				; W = (W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)

	movdqa  W_TMP, W
	psrld   W, 30
	pslld   W_TMP, 2
	por     W, W_TMP				; W = S^2((W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0))
									;   = W35 W34 W33 W32
	W_PRECALC_ROTATE
%endmacro


; -----------------------------------------
; 以下は、T1 = (%1 & %2) | (~%1 & %3) と等価
%macro F1 3
	mov T1,%2  ; T1 = eax
	xor T1,%3  ; T1 = %2 xor %3
	and T1,%1
	xor T1,%3
%endmacro

%macro F2 3
	mov T1,%3
	xor T1,%2
	xor T1,%1
%endmacro

; 以下は、(%1 & %2) | (%1 & %3) | (%2 & %3) と等価
%macro F3 3
	mov T1,%1
	or  T1,%2
	and T1,%3
	mov T2,%1
	and T2,%2
	or  T1,T2
%endmacro


; -----------------------------------------
%macro RR 5		;; RR does two rounds of SHA-1 back to back with W pre-calculation
	F    %2, %3, %4     ;; F returns result in T1

	ADD_DEPO_W  %5
	rol  %2, 30
	mov  T2, %1

	ADD_DEPO_W  %4
	rol  T2, 5
	add  %5, T1

	add  T2, %5
	mov  %5, T2
	rol  T2, 5
	add  %4, T2

	F    %1, %2, %3    ;; F returns result in T1
	add  %4, T1
	rol  %1, 30
%endmacro


; ========================================================
section .data align=16

	%xdefine K1 0x5a827999
	%xdefine K2 0x6ed9eba1
	%xdefine K3 0x8f1bbcdc
	%xdefine K4 0xca62c1d6

K_XMM_ARY:
	DD K1, K1, K1, K1
	DD K2, K2, K2, K2
	DD K3, K3, K3, K3
	DD K4, K4, K4, K4

bswap_shufb_ctl:
	DD 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f

SHA1_INIT_ONCE_W16_19:
	DD 0, 0, 0, 0x1e0	; 0x1e0 = 480(bits)

DB_WS_KEY_BUF:			; 64bytes
	DB "1234567890123456789012==258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 0x80, 0, 0, 0

; ========================================================
section .bss align=32	; vmovdqa を利用するため

	WK_VAL_BLK2  resb  320

; ========================================================
section .text align=4096

; ////////////////////////////////////////////////////////

sha1_init_once:			; ----- コード開始位置
	push	rbx
	push	rbp

	; 2nd block用の 64bytes のデータ生成
	vpxor	ymm0, ymm0, ymm0
	vmovdqa	[WK_VAL_BLK2], ymm0
	vmovdqa	[WK_VAL_BLK2 + 32], ymm0
	mov		ax, 0xe001
	mov		[WK_VAL_BLK2 + 62], ax	; 480 bits のデータがあることを書き込む

	mov		HASH_PTR, HASH_PTR		; HASH_PTR == NULL が sha1_init_once の目印
	mov		BUFFER_PTR, WK_VAL_BLK2;

	jmp		POS_CRT_WK_VAL

POS_RESTORE_init_once:
	mov			rax, WK_VAL_BLK2
	vmovdqa		[rax], ymm10
	add			rax, 32
	vmovdqa		[rax], ymm11
	add			rax, 32
	vmovdqa		[rax], ymm12
	add			rax, 32
	vmovdqa		[rax], ymm13
	add			rax, 32
	vmovdqa		[rax], ymm14
	add			rax, 32
	vmovdqa		[rax], ymm15
	add			rax, 32
	movdqa		[rax], xmm5
	add			rax, 16
	movdqa		[rax], xmm4
	add			rax, 16
	movdqa		[rax], xmm3
	add			rax, 16
	movdqa		[rax], xmm2
	add			rax, 16
	movdqa		[rax], xmm1
	add			rax, 16
	movdqa		[rax], xmm8
	add			rax, 16
	movdqa		[rax], xmm7
	add			rax, 16
	movdqa		[rax], xmm6

	pop		rbp
	pop		rbx
	ret


; ////////////////////////////////////////////////////////

sha1_update_intel:		; ----- コード開始位置
	push	rbx
	push	rbp

	mov     HASH_PTR, rdi		; 第１引数（hash）, 方向：out
;	mov     BUFFER_PTR, rsi		; 第２引数（buffer）, 方向：in


;--------------------------------------------
; 処理開始

	; 24 文字の WS-Key を DB_WS_KEY_BUF に転送
	movdqa		xmm0, [rsi]					; rsi 第２引数
	movdqa		[DB_WS_KEY_BUF], xmm0
	mov			rax, [rsi + 16]
	mov			[DB_WS_KEY_BUF + 16], rax

	xor			FLG_2nd_BLK, FLG_2nd_BLK	; FLG_2nd_BLK フラグのクリア


	; 1st block の WK値を生成
	mov			BUFFER_PTR, DB_WS_KEY_BUF	; BUFFER_PTR を設定

POS_CRT_WK_VAL:
	movdqa  XMM_SHUFB_BSWAP, [bswap_shufb_ctl]

	DEPO_W_INIT
	W_PRECALC_RESET

	movdqa  K_VAL_XMM, [K_XMM_ARY]
	W_PRECALC_00_15	 0
	W_PRECALC_00_15	 16
	W_PRECALC_00_15	 32
	W_PRECALC_00_15	 48

	W_PRECALC_16_31

	movdqa  K_VAL_XMM, [K_XMM_ARY + 16]
	%rep  3
		W_PRECALC_16_31
	%endrep

	W_PRECALC_32_47
	W_PRECALC_32_47

	movdqa  K_VAL_XMM, [K_XMM_ARY + 32]
	W_PRECALC_32_47
	W_PRECALC_32_47

	W_PRECALC_48_79
	W_PRECALC_48_79
	W_PRECALC_48_79

;	movdqa  K_VAL_XMM, [K_XMM_ARY + 48]
	%rep  5
		W_PRECALC_48_79
	%endrep

	%rep  3
		paddd	W, K_VAL_XMM
		W_PRECALC_ROTATE
	%endrep

	movdqa  K_VAL_XMM, [K_XMM_ARY + 48]
	%rep  5
		paddd	W, K_VAL_XMM
		W_PRECALC_ROTATE
	%endrep

	; sha1_init_once の判定
	or		HASH_PTR, HASH_PTR
	jz		POS_RESTORE_init_once


	; ハッシュ初期値
	mov		A, 0x67452301
	mov		B, 0xEFCDAB89
	mov		C, 0x98BADCFE
	mov		D, 0x10325476
	mov		E, 0xC3D2E1F0

POS_RR_START:
	DEPO_W_INIT

	%xdefine F F1

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B

	%xdefine F F2

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B

	%xdefine F F3

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B

	%xdefine F F2

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B

	RR A,B,C,D,E
	RR D,E,A,B,C
	RR B,C,D,E,A
	RR E,A,B,C,D
	RR C,D,E,A,B


	; 1st or 2nd block の分岐判定
	or		FLG_2nd_BLK, FLG_2nd_BLK
	jnz		POS_FINISH_2nd_BLK

	inc		FLG_2nd_BLK		; 2nd block のフラグON

	; 1st block のハッシュ値生成
	add		A, 0x67452301
	add		B, 0xEFCDAB89
	add		C, 0x98BADCFE
	add		D, 0x10325476
	add		E, 0xC3D2E1F0

	push	E_64
	push	D_64
	push	C_64
	push	B_64
	push	A_64

	; 2nd block の WK値の復帰（320 bytes）
	; eax は T1 の役割
	mov			rax, WK_VAL_BLK2
	vmovdqa		ymm10, [rax]
	add			rax, 32
	vmovdqa		ymm11, [rax]
	add			rax, 32
	vmovdqa		ymm12, [rax]
	add			rax, 32
	vmovdqa		ymm13, [rax]
	add			rax, 32
	vmovdqa		ymm14, [rax]
	add			rax, 32
	vmovdqa		ymm15, [rax]
	add			rax, 32
	movdqa		xmm5, [rax]
	add			rax, 16
	movdqa		xmm4, [rax]
	add			rax, 16
	movdqa		xmm3, [rax]
	add			rax, 16
	movdqa		xmm2, [rax]
	add			rax, 16
	movdqa		xmm1, [rax]
	add			rax, 16
	movdqa		xmm8, [rax]
	add			rax, 16
	movdqa		xmm7, [rax]
	add			rax, 16
	movdqa		xmm6, [rax]

	jmp			POS_RR_START


POS_FINISH_2nd_BLK:
	pop		rax
	add		eax, A
	mov		[HASH_PTR   ], eax

	pop		rax
	add		eax, B
	mov		[HASH_PTR+ 4], eax

	pop		rax
	add		eax, C
	mov		[HASH_PTR+ 8], eax

	pop		rax
	add		eax, D
	mov		[HASH_PTR+12], eax

	pop		rax
	add		eax, E
	mov		[HASH_PTR+16], eax

	pop		rbp
	pop		rbx
	ret

