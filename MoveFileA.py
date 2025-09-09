# This WIN32 API Function MoveFileA used for both cut and rename files.

import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    #"   int3                            ;"  # Remove in production
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff9f0           ;"  # Avoid NULL bytes

    # --- Original function resolution code (unchanged) ---
    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  # ESI = PEB
    "   mov   esi,[esi+0x0C]            ;"  # ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  # ESI = InInitOrder list
    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  # EBX = DLL base
    "   mov   edi, [esi+0x20]           ;"  # EDI = DLL name
    "   mov   esi, [esi]                ;"  # ESI = next module
    "   cmp   [edi+12*2], cx            ;"  # Check name length
    "   jne   next_module               ;"  #
    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #
    " find_function_ret:                 "  #
    "   pop esi                         ;"  #
    "   mov   [ebp+0x04], esi           ;"  # Save find_function
    "   jmp resolve_symbols             ;"  #
    " find_function_shorten_bnc:         "  #
    "   call find_function_ret          ;"  #
    " find_function:                     "  #
    "   pushad                          ;"  #
    "   mov   eax, [ebx+0x3c]           ;"  # PE header
    "   mov   edi, [ebx+eax+0x78]       ;"  # Export table
    "   add   edi, ebx                  ;"  #
    "   mov   ecx, [edi+0x18]           ;"  # NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  # AddressOfNames
    "   add   eax, ebx                  ;"  #
    "   mov   [ebp-4], eax              ;"  #
    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #
    "   dec   ecx                       ;"  #
    "   mov   eax, [ebp-4]              ;"  #
    "   mov   esi, [eax+ecx*4]          ;"  #
    "   add   esi, ebx                  ;"  #
    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #
    "   cdq                             ;"  #
    "   cld                             ;"  #
    " compute_hash_again:                "  #
    "   lodsb                           ;"  #
    "   test  al, al                    ;"  #
    "   jz    compute_hash_finished     ;"  #
    "   ror   edx, 0x0d                 ;"  #
    "   add   edx, eax                  ;"  #
    "   jmp   compute_hash_again        ;"  #
    " compute_hash_finished:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #
    "   jnz   find_function_loop        ;"  #
    "   mov   edx, [edi+0x24]           ;"  #
    "   add   edx, ebx                  ;"  #
    "   mov   cx,  [edx+2*ecx]          ;"  #
    "   mov   edx, [edi+0x1c]           ;"  #
    "   add   edx, ebx                  ;"  #
    "   mov   eax, [edx+4*ecx]          ;"  #
    "   add   eax, ebx                  ;"  #
    "   mov   [esp+0x1c], eax           ;"  #
    " find_function_finished:            "  #
    "   popad                           ;"  #
    "   ret                             ;"  #

    # --- Resolve MoveFileA ---
    " resolve_symbols:                   "
    "   push  0xa4048954                ;"  # MoveFileA hash 
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x10], eax           ;"  # Save MoveFileA address

    # --- Build original path (C:\Tools\123.txt) ---
    " build_original_path:               "
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # Null terminator
    "   push  0x7478742e                ;"  # '
    "   push  0x3332315c                ;"  # ' #CHANGE PATHS
    "   push  0x736c6f6f                ;"  #  #CHANGE PATHS
    "   push  0x545c3a43                ;"  # 
    "   mov   esi, esp                  ;"  # ESI = original path

    # --- Build new path (C:\Tools\1.txt) ---
    " build_new_path:                    "
    "   push  ecx                       ;"  # Null terminator
    "   push  0x7478742e                ;"  # '.txt'
    "   push  0x32315c72                ;"  # 
    "   push  0x6c73615c                ;"  #  #CHANGE PATHS
    "   push  0x736c6f6f                ;"  #  #CHANGE PATHS
    "   push  0x545c3a43                ;"  # ''
    "   mov   edi, esp                  ;"  # EDI = new path

    # --- Call MoveFileA ---
    " rename_file:                       "
    "   push  edi                       ;"  # lpNewFileName
    "   push  esi                       ;"  # lpExistingFileName
    "   call dword ptr [ebp+0x10]       ;"  # MoveFileA

    # --- Clean exit ---
    "   push  0x78b5b983                ;"  # TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #
    "   xor   ecx, ecx                  ;"  #
    "   push  ecx                       ;"  #
    "   push  -1                        ;"  #
    "   call  eax                       ;"  #
)


# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
