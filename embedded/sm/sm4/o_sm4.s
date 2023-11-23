	AREA SM4_KEYGEN, CODE, READONLY, ALIGN=2
	EXPORT  keygen
keygen	PROC
        PUSH     {r2-r10}
		
		
		
		
        LDR      r2, =0xA3B1BAC6	 
		LDR      r3,[r0]
		REV	 	 r3, r3
        EOR		 r3, r2, r3
		
		LDR      r2, =0x56AA3350	
		LDR      r4,[r0, #4]
		REV	 	 r4, r4
        EOR		 r4, r2, r4
		
		LDR      r2, =0x677D9197	 
		LDR      r5,[r0, #8]
		REV	 	 r5, r5
        EOR		 r5, r2, r5
		
		LDR      r2, =0xB27022DC	
		LDR      r6,[r0, #12]
		REV	 	 r6, r6
        EOR		 r6, r2, r6
		
		LDR		 r8, = Sbox
		LDR		 r9, = CK
		MOV		 r10, #0

RoundKeyLoop
		;Round 1
		LDR      r2, [r9]
		EOR		 r7, r4, r5
		EOR		 r2, r2, r6
		EOR		 r2, r2, r7
		;;;Sbox[r2]
		UBFX	 r0, r2,#0,#8
		LDRB	 r7, [r8, r0]
		UBFX	 r0, r2,#8,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #8, #8
		UBFX	 r0, r2,#16,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #16, #8
		UBFX	 r0, r2,#24,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #24, #8
		;;; Linear transformation, 
		EOR		 r0, r7, r7, ROR #9
		EOR		 r0, r0, r7, ROR #19
		;;;Final step
		EOR		 r3, r0, r3
		REV		 r0, r3
		STR      r0, [r1]
		
		
        ;Round 2
		LDR      r2, [r9, #4]
		EOR		 r7, r5, r6
		EOR		 r2, r2, r3
		EOR		 r2, r2, r7
		UBFX	 r0, r2,#0,#8
		LDRB	 r7, [r8, r0]
		UBFX	 r0, r2,#8,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #8, #8
		UBFX	 r0, r2,#16,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #16, #8
		UBFX	 r0, r2,#24,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #24, #8
		EOR		 r0, r7, r7, ROR #9
		EOR		 r0, r0, r7, ROR #19
		EOR		 r4, r0, r4
		REV		 r0, r4
		STR      r0, [r1, #4]	
	
		;Round 3
		LDR      r2, [r9, #8]
		EOR		 r7, r4, r6
		EOR		 r2, r2, r3
		EOR		 r2, r2, r7
		UBFX	 r0, r2,#0,#8
		LDRB	 r7, [r8, r0]
		UBFX	 r0, r2,#8,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #8, #8
		UBFX	 r0, r2,#16,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #16, #8
		UBFX	 r0, r2,#24,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #24, #8
		EOR		 r0, r7, r7, ROR #9
		EOR		 r0, r0, r7, ROR #19
		EOR		 r5, r0, r5
		REV		 r0, r5
		STR      r0, [r1, #8]
		
		;Round 4
		LDR      r2, [r9, #12]
		EOR		 r7, r4, r5
		EOR		 r2, r2, r3
		EOR		 r2, r2, r7
		UBFX	 r0, r2,#0,#8
		LDRB	 r7, [r8, r0]
		UBFX	 r0, r2,#8,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #8, #8
		UBFX	 r0, r2,#16,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #16, #8
		UBFX	 r0, r2,#24,#8
		LDRB	 r0, [r8, r0]
		BFI	 	 r7, r0, #24, #8
		EOR		 r0, r7, r7, ROR #9
		EOR		 r0, r0, r7, ROR #19
		EOR		 r6, r0, r6
		REV		 r0, r6
		STR      r0, [r1, #12]
		
		
		ADD		 r10, #1
		CMP		 r10, #8
		
		BGE KeyExDone
		ADD		 r9, #16
		ADD		 r1, #16
		B	RoundKeyLoop
KeyExDone		
		POP      {r2-r10}
		BX       lr
	
		ENDP
		
		AREA CONSTS, DATA, READONLY
FK		DCD    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
	
CK		DCD    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269
		DCD    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9
		DCD    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249
		DCD    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9
		DCD    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229
		DCD    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299
		DCD    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209
		DCD    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
Sbox	DCB  0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28, 0xfb, 0x2c, 0x05 
        DCB  0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99
        DCB  0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62
        DCB  0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6
        DCB  0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8
        DCB  0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35
        DCB  0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87
        DCB  0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e
        DCB  0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1
        DCB  0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3
        DCB  0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f
        DCB  0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51
        DCB  0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8
        DCB  0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0
        DCB  0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84
        DCB  0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48

	AREA SM4_ENC, CODE, READONLY, ALIGN = 2
	EXPORT  enc
enc	PROC
        PUSH     {r3-r11}
		
		
		;VLD1 	 q0, [r0]
		;VST1      q0,[r2]
		
		;POP      {r2-r10}
		;BX       lr
		
		LDR      r3,[r0]
		REV	 	 r3, r3
		
		LDR      r4,[r0, #4]
		REV	 	 r4, r4
		
		LDR      r5,[r0, #8]
		REV	 	 r5, r5
		
		LDR      r6,[r0, #12]
		REV	 	 r6, r6
		
		
		LDR		 r8, = Sbox
		MOV		 r11, #0

EncLoop
		;Round 1
		LDR      r9, [r1]
		REV		 r9, r9
		
		EOR		 r7, r4, r5
		EOR		 r9, r6, r9
		EOR		 r9, r9, r7
		;;;r7=Sbox[r9]
		UBFX	 r10, r9,#0,#8
		LDRB	 r7, [r8, r10]
		UBFX	 r10, r9,#8,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #8, #8
		UBFX	 r10, r9,#16,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #16, #8
		UBFX	 r10, r9,#24,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #24, #8
		
		;;; Linear transformation, 
		EOR		 r10, r7, r7, ROR #30
		EOR		 r10, r10, r7, ROR #22
		EOR		 r10, r10, r7, ROR #14
		EOR		 r10, r10, r7, ROR #8
		;;;Final step
		EOR		 r3, r10, r3
		;REV		 r10, r3
		;STR      r10, [r2]
		
		
		;Round 2
		LDR      r9, [r1, #4]
		REV		 r9, r9
		EOR		 r7, r5, r6
		EOR		 r9, r3, r9
		EOR		 r9, r9, r7
		UBFX	 r10, r9,#0,#8
		LDRB	 r7, [r8, r10]
		UBFX	 r10, r9,#8,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #8, #8
		UBFX	 r10, r9,#16,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #16, #8
		UBFX	 r10, r9,#24,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #24, #8
		EOR		 r10, r7, r7, ROR #30
		EOR		 r10, r10, r7, ROR #22
		EOR		 r10, r10, r7, ROR #14
		EOR		 r10, r10, r7, ROR #8
		EOR		 r4, r10, r4
		;REV		 r10, r4
		;STR      r10, [r2, #4]
		
		;Round 3
		LDR      r9, [r1, #8]
		REV		 r9, r9
		EOR		 r7, r6, r3
		EOR		 r9, r4, r9
		EOR		 r9, r9, r7
		UBFX	 r10, r9,#0,#8
		LDRB	 r7, [r8, r10]
		UBFX	 r10, r9,#8,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #8, #8
		UBFX	 r10, r9,#16,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #16, #8
		UBFX	 r10, r9,#24,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #24, #8
		EOR		 r10, r7, r7, ROR #30
		EOR		 r10, r10, r7, ROR #22
		EOR		 r10, r10, r7, ROR #14
		EOR		 r10, r10, r7, ROR #8
		EOR		 r5, r10, r5
		;REV		 r10, r5
		;STR      r10, [r2, #8]
		
		;Round 4
		LDR      r9, [r1, #12]
		REV		 r9, r9
		EOR		 r7, r3, r4
		EOR		 r9, r5, r9
		EOR		 r9, r9, r7
		UBFX	 r10, r9,#0,#8
		LDRB	 r7, [r8, r10]
		UBFX	 r10, r9,#8,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #8, #8
		UBFX	 r10, r9,#16,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #16, #8
		UBFX	 r10, r9,#24,#8
		LDRB	 r10, [r8, r10]
		BFI	 	 r7, r10, #24, #8
		EOR		 r10, r7, r7, ROR #30
		EOR		 r10, r10, r7, ROR #22
		EOR		 r10, r10, r7, ROR #14
		EOR		 r10, r10, r7, ROR #8
		EOR		 r6, r10, r6

		
		ADD		 r1, #16
		ADD		 r11, #1
		CMP		 r11, #8
		BLT		 EncLoop
		
		
		REV		 r10, r3
		REV		 r9, r4
		REV		 r8, r5
		REV		 r7, r6
		STMIA	 r2, {r7-r10}
		
		POP      {r3-r11}
		BX       lr
		ENDP
		
		
	AREA SM4_DEC, CODE, READONLY, ALIGN = 2
	EXPORT  dec
dec PROC
		PUSH	 {lr}
		BL 		 enc
		POP	 	 {PC}
		;BX		 lr
		ENDP
		
	END