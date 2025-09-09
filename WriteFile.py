# This is used for creating a file then write content to it

import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    #"   int3                            ;"  # Remove in production
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff9f0           ;"  # Avoid NULL bytes

    # --- Original function resolution ---
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

    # --- Resolve APIs with YOUR hashes ---
    " resolve_symbols:                   "
    # CreateFileA (0x7C0017A5)
    "   mov   eax, 0x7D7D7D7D           ;"  # Non-null base
    "   sub   eax, 0x17D65D8            ;"  # 0x7D7D7D7D - 0x017D65D8 = 0x7C0017A5
    "   push  eax                       ;"  # Push hash
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x10], eax           ;"  # Save CreateFileA

    "   push  0xe80a791f                ;"  # WriteFile hash (your value)
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x14], eax           ;"  # Save WriteFile

    "   push  0x0ffd97fb                ;"  # CloseHandle hash (your value)
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x18], eax           ;"  # Save CloseHandle

    # --- Build file path (C:\Tools\output.txt) ---
    " build_path:                        "
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # Null terminator
    "   push  0x7478742e                ;"  # '.txt'
    "   push  0x3332315c                ;"  # '\123'
    "   push  0x736c6f6f                ;"  # 'ools'
    "   push  0x545c3a43                ;"  # 'C:\T'
    "   mov   esi, esp                  ;"  # ESI = file path

    # --- Prepare data to write ("123") ---
    " prepare_data:                           "
    "   lea   edi, [ebp-0x100]               ;"  # EDI = buffer
   #"   mov   dword ptr [edi], 0x333231      ;"  # '123' (no null terminator needed)
   #"   mov   byte ptr [edi+3], 0x0A         ;"  # Add newline (optional)
    "   mov   dword ptr [edi], 0x6c6c6548    ;"  # 'ello'
    "   mov   dword ptr [edi+4], 0x6f57206f  ;"  # 'rld!'
    "   mov   dword ptr [edi+8], 0x21646c72  ;"  # 'rld!'
    "   mov   byte ptr [edi+12], 0           ;"  # Null terminator

    # --- Call CreateFileA ---
    " create_file:                       "
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # hTemplateFile = NULL
    "   push  0x80                      ;"  # FILE_ATTRIBUTE_NORMAL
    "   push  0x2                       ;"  # CREATE_ALWAYS
    "   push  ecx                       ;"  # lpSecurityAttributes = NULL
    "   push  0x1                       ;"  # FILE_SHARE_READ
    
    # Generate GENERIC_WRITE (0x40000000)
    "   mov   eax, 0x3FFFFFFF           ;"  # 
    "   add   eax, 1                    ;"  # Becomes 0x40000000
    "   push  eax                       ;"  # Push GENERIC_WRITE
    
    "   push  esi                       ;"  # lpFileName
    "   call dword ptr [ebp+0x10]       ;"  # CreateFileA
    "   mov   [ebp-4], eax              ;"  # Save file handle

    # --- Call WriteFile ---
    " write_file:                        "
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # lpOverlapped = NULL
    "   lea   eax, [ebp-8]              ;"  # EAX = bytes written pointer
    "   push  eax                       ;"  # lpNumberOfBytesWritten
    "   push  0x20                      ;"  # nNumberOfBytesToWrite ("123\n")
    "   lea   eax, [ebp-0x100]          ;"  # EAX = buffer address
    "   push  eax                       ;"  # lpBuffer
    "   push  dword ptr [ebp-4]         ;"  # hFile
    "   call dword ptr [ebp+0x14]       ;"  # WriteFile

    # --- Call CloseHandle ---
    " close_file:                        "
    "   push  dword ptr [ebp-4]         ;"  # hFile
    "   call dword ptr [ebp+0x18]       ;"  # CloseHandle

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
