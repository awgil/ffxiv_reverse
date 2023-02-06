﻿namespace Netlog;

unsafe static class OpcodeMapBuilder
{
    public static OpcodeMap Build()
    {
        // look for an internal tracing function - it's a giant switch on opcode that calls virtual function corresponding to the opcode; we use vf indices as 'opcode index'
        // function starts with:
        // mov rax, [r8+10h]
        // mov r10, [rax+38h]
        // movzx eax, word ptr [r10+2]
        // add eax, -<min_case>
        // cmp eax, <max_case-min_case>
        // ja <default_off>
        // lea r11, <__ImageBase_off>
        // cdqe
        // mov r9d, ds::<jumptable_rva>[r11+rax*4]
        var func = (byte*)Service.SigScanner.ScanText("49 8B 40 10  4C 8B 50 38  41 0F B7 42 02  83 C0 ??  3D ?? ?? ?? ??  0F 87 ?? ?? ?? ??  4C 8D 1D ?? ?? ?? ??  48 98  45 8B 8C 83 ?? ?? ?? ??");
        var minCase = -*(sbyte*)(func + 15);
        var jumptableSize = *(int*)(func + 17) + 1;
        var defaultAddr = ReadRVA(func + 23);
        var imagebase = ReadRVA(func + 30);
        var jumptable = (int*)(imagebase + *(int*)(func + 40));
        OpcodeMap res = new();
        for (int i = 0; i < jumptableSize; ++i)
        {
            var bodyAddr = imagebase + jumptable[i];
            if (bodyAddr == defaultAddr)
                continue;

            var opcode = minCase + i;
            var index = ReadIndexForCaseBody(bodyAddr);
            if (index < 0)
                Service.LogWarn($"[OpcodeMap] Unexpected body for opcode {opcode}");
            else
                res.AddMapping(opcode, index);
        }
        return res;
    }

    private static byte* ReadRVA(byte* p) => p + 4 + *(int*)p;

    // assume each case has the following body:
    // mov rax, [rcx]
    // lea r9, [r10+10h]
    // jmp qword ptr [rax+<vfoff>]
    private static byte[] BodyPrefix = { 0x48, 0x8B, 0x01, 0x4D, 0x8D, 0x4A, 0x10, 0x48, 0xFF };
    private static int ReadIndexForCaseBody(byte* bodyAddr)
    {
        for (int i = 0; i < BodyPrefix.Length; ++i)
            if (bodyAddr[i] != BodyPrefix[i])
                return -1;
        var vtoff = bodyAddr[BodyPrefix.Length] switch
        {
            0x60 => *(bodyAddr + BodyPrefix.Length + 1),
            0xA0 => *(int*)(bodyAddr + BodyPrefix.Length + 1),
            _ => -1
        };
        if (vtoff < 0x10 || (vtoff & 7) != 0)
            return -1; // first two vfs are dtor and exec, vtable contains qwords
        return (vtoff >> 3) - 2;
    }
}
