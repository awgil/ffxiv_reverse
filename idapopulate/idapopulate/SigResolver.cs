using FFXIVClientStructs.Interop;
using System.Reflection.PortableExecutable;

namespace idapopulate;

internal class SigResolver
{
    private ulong _baseAddress;
    private nint _resolverBase;
    private SectionHeader _text;
    private SectionHeader _data;
    private SectionHeader _rdata;

    public unsafe SigResolver(string exePath, ulong baseAddress = 0x140000000)
    {
        _baseAddress = baseAddress;

        var contents = File.ReadAllBytes(exePath);
        var headers = new PEHeaders(new MemoryStream(contents));
        _text = headers.SectionHeaders.First(h => h.Name == ".text");
        _data = headers.SectionHeaders.First(h => h.Name == ".data");
        _rdata = headers.SectionHeaders.First(h => h.Name == ".rdata");
        fixed (byte* p = contents)
        {
            _resolverBase = (nint)p;
            Resolver.GetInstance.SetupSearchSpace(_resolverBase, contents.Length, _text.PointerToRawData, _text.SizeOfRawData, _data.PointerToRawData, _data.SizeOfRawData, _rdata.PointerToRawData, _rdata.SizeOfRawData);
            Resolver.GetInstance.Resolve();
        }
    }

    public ulong ToEA(Address address)
    {
        if (address.Value == 0)
            return 0;
        // note: looking at the resolver code, any found addresses are relative to text section
        return _baseAddress + (ulong)_text.VirtualAddress + (ulong)((nint)address.Value - _resolverBase - _text.PointerToRawData);
        //var rva = (nint)address.Value - _resolverBase;
        //return ToSectionEA(rva, _text) ?? ToSectionEA(rva, _data) ?? ToSectionEA(rva, _rdata) ?? throw new Exception("Weird resolved address");
    }

    //private ulong? ToSectionEA(nint rva, SectionHeader header) => rva >= header.PointerToRawData && rva < header.PointerToRawData + header.SizeOfRawData ? _baseAddress + (ulong)header.VirtualAddress + (ulong)(rva - header.PointerToRawData) : null;
}
