.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\advapi32.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc

includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\advapi32.lib

StrM MACRO data:VARARG                    
    LOCAL Buff
.data
    Buff db data, 0h
.code
    exitm <addr Buff>
ENDM
 
ByteToStr PROTO :DWORD, :DWORD, :DWORD

.const
	PKCS_7_ASN_ENCODING      	equ 	00010000h
	X509_ASN_ENCODING        	equ		00000001h

	ALG_SID_MD5              	equ    	00000003h
	ALG_SID_RC4				 	equ		00000001h  
	ALG_SID_RC2		 		 	equ		00000002h  
	
	PROV_RSA_FULL            	equ    00000001h
	HP_HASHVAL               	equ    00000002h
	
	ALG_CLASS_ANY            	equ    	00000000h
	ALG_CLASS_SIGNATURE      	equ    	00002000h  
	ALG_CLASS_MSG_ENCRYPT    	equ    	00004000h  
	ALG_CLASS_DATA_ENCRYPT   	equ    	00006000h  
	ALG_CLASS_HASH           	equ    	00008000h  
	ALG_CLASS_KEY_EXCHANGE   	equ    	0000A000h  
	
	ALG_TYPE_ANY             	equ    	00000000h 
	ALG_TYPE_DSS             	equ    	00000200h  
	ALG_TYPE_RSA             	equ    	00000400h  
	ALG_TYPE_BLOCK           	equ    	00000600h  
	ALG_TYPE_STREAM          	equ    	00000800h  
	ALG_TYPE_DH              	equ    	00000A00h  
	ALG_TYPE_SECURECHANNEL   	equ    	00000C00h  
	
	CRYPT_VERIFYCONTEXT      	equ 	0F0000000h  
	CRYPT_EXPORTABLE	 	 	equ 	00000001h  
	
	CALG_MD5                 	equ		ALG_CLASS_HASH OR ALG_TYPE_ANY OR ALG_SID_MD5
	CALG_RC4		 		 	equ 	ALG_CLASS_DATA_ENCRYPT OR ALG_TYPE_STREAM OR ALG_SID_RC4
	CALG_RC2		 		 	equ 	ALG_CLASS_DATA_ENCRYPT OR ALG_TYPE_BLOCK OR ALG_SID_RC2
	
	HCRYPTPROV  				TYPEDEF	DWORD
	HCRYPTKEY   				TYPEDEF DWORD
	HCRYPTHASH  				TYPEDEF DWORD
	
	NTE_BAD_LEN             	equ 	80090004h	
	NTE_BAD_DATA            	equ 	80090005h


.data
	LibName     	db "HashCrypt.dll", 0 	


.code

DllEntry proc hInstDLL:HINSTANCE, reason:DWORD, reserved1:DWORD
    mov eax, TRUE
    ret
DllEntry Endp

ShowMessage PROC uses eax ebx ecx edx esi edi lpMessage:DWORD	
	invoke MessageBox, 0, lpMessage, addr LibName, MB_OK
	ret
ShowMessage endp


HashCrypt proc uses esi edi ebx ecx edx lpstring1:DWORD, lpstring2:DWORD, dwLength:DWORD, flag:DWORD
	LOCAL hCryptProv: HCRYPTPROV 
	LOCAL hHash     : HCRYPTHASH 
	LOCAL hCryptKey : HCRYPTKEY		
	LOCAL dwi		: DWORD
	LOCAL sHash[512]: BYTE
		
	invoke CryptAcquireContext, ADDR hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
	.IF eax != 0
	 	invoke  CryptCreateHash, hCryptProv, CALG_MD5, 0, 0, ADDR hHash
	  	.IF eax != 0
	  		invoke lstrlen, lpstring1
	    	mov	dwi, eax
	    	invoke CryptHashData, hHash, lpstring1, dwi, 0
	    	.IF eax != 0
	      		.IF	flag == 0	
		      		mov	dwi, SIZEOF sHash
		      		invoke CryptGetHashParam, hHash, HP_HASHVAL, ADDR sHash, ADDR dwi, 0
		      		.IF eax != 0
		        		invoke ByteToStr, dwi, ADDR sHash, lpstring2 
		 	  			invoke CryptDestroyHash, hHash
		      		.ENDIF
				.ELSE	
					push dwLength
					pop dwi
		      		invoke CryptDeriveKey, hCryptProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, ADDR hCryptKey
		      		.IF eax != 0
		        		invoke  CryptDestroyHash, hHash								    					    				    		
		    			.IF flag==1
		      				invoke CryptEncrypt, hCryptKey, 0, TRUE, 0, lpstring2, ADDR dwi, dwi
		      				.if eax == 0
		      					invoke GetLastError
		      					.if eax == NTE_BAD_DATA
		      						invoke ShowMessage, StrM("Error NTE_BAD_DATA") 
		      					.elseif eax == NTE_BAD_LEN	
		      						invoke ShowMessage, StrM("Error NTE_BAD_LEN")	
		      								      							      						
		      					.endif	      	
		      				.endif		      				
		      			.ELSE		      				
		      				invoke CryptDecrypt, hCryptKey, 0, TRUE, 0, lpstring2, ADDR dwi
		      				.if eax == 0		      					
		      					invoke GetLastError
		      					.if eax == NTE_BAD_DATA
		      						invoke ShowMessage, StrM("Error NTE_BAD_DATA") 
		      					.elseif eax == NTE_BAD_LEN	
		      						invoke ShowMessage, StrM("Error NTE_BAD_LEN")	
		      							      						
		      					.endif	      					
		      				.endif		      				
		      			.ENDIF		      			
		      			invoke CryptDestroyKey, hCryptKey
		    		.ENDIF
				.ENDIF
				invoke CryptReleaseContext, hCryptProv, 0
	  	 	.ENDIF
	  	.ENDIF
	.ENDIF  
	mov eax, dwi
	ret
HashCrypt endp


ByteToStr PROC Len:DWORD, pArray:DWORD, pStr:DWORD
	mov	ecx, Len
	mov esi, pArray
	mov edi, pStr	
@@:
	mov al, byte ptr [esi]
	and al, 0F0h
	shr al, 4
	.IF al <= 9	
		add al, "0"
		mov	byte ptr [edi], al
	.ELSE
		sub	al, 10
		add al, "A"
		mov	byte ptr [edi], al
	.ENDIF
	inc	edi
	mov	al, byte ptr [esi]
	and	al, 0Fh
	.IF al <= 9	
		add al,"0"
		mov	byte ptr [edi], al
	.ELSE
		sub	al, 10
		add al, "A"
		mov	byte ptr [edi], al
	.ENDIF
	inc	edi
	inc	esi	
	dec	ecx
	cmp ecx, 0
	jnz @B	
	mov	byte ptr [edi], 0			
	xor	eax, eax
	ret	
ByteToStr ENDP

End DllEntry