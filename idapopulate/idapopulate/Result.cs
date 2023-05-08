using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization;
using System.Diagnostics;

namespace idapopulate;

// assumption about vtables:
// - we don't support virtual bases (for now?)
// - trivial: a struct can have 0 vtables - if neither it nor its bases have virtual functions
// - trivial: a struct with virtual functions has a vptr at offset 0; a struct with a base has base at offset 0; vptr is also natually at offset 0
//   in IDA we model that as a 'baseclass' special field (and no vptr field) -or- explicit vptr field at offset 0
// - edge case: if a base has no virtual functions, but derived has - derived will have vptr at offset 0 and base at offset 8
//   I don't think IDA really supports this, so we model it as a field rather than a baseclass
// - trivial: any new vfuncs in derived are added to the vtable - we model that as derived-vtable having base-vtable as a base class
// - trivial: if there are several bases, these are in order
//   in IDA we model that as several 'baseclass' special fields ('baseclass_X', where X is offset)
// - tricky: any new vfuncs are added only to the main vtable (at offset 0); so we don't need to create extra types for vtables from secondary bases (these contain thunks)
internal class Result
{
    public class EnumValue
    {
        public string Name = "";
        public long Value;

        public override string ToString() => $"{Name} = 0x{Value:X}";
    }

    public class Enum
    {
        public bool IsBitfield;
        public bool IsSigned;
        public int Width;
        public List<EnumValue> Values = new(); // sorted by value

        public override string ToString() => $"{(IsSigned ? "signed" : "unsigned")} {Width}-byte-wide {(IsBitfield ? "bitfield" : "enum")}";
    }

    public class Address
    {
        public string Sig;
        public int SigOffset;

        public Address(string sig, int sigOffset = 0)
        {
            Sig = sig;
            SigOffset = sigOffset;
        }

        public override string ToString() => $"'{Sig}' +{SigOffset}";
    }

    public class FuncArg
    {
        public string Type = "";
        public string Name = "";

        public override string ToString() => $"{Type} {Name}";
    }

    public class FuncSig
    {
        public string RetType = "";
        public List<FuncArg> Arguments = new();

        public override string ToString() => $"({string.Join(", ", Arguments)}) -> {RetType}";
    }

    public class Function
    {
        public string Name = "";
        public Address? Address;
        public FuncSig? Signature;

        public override string ToString() => $"auto {Name}{Signature} @ {Address}";
    }

    public class VTable
    {
        public ulong Ea;
        public Address? Address;
        public SortedDictionary<uint, Function> VFuncs = new();

        public override string ToString() => $"0x{Ea:X} {Address}";
    }

    public class SecondaryVTable
    {
        public ulong Ea;
        public string Base = "";

        public override string ToString() => $"0x{Ea:X} {Base}";
    }

    public class StructBase
    {
        public string Type = "";
        public int Offset;
        public int Size;

        public override string ToString() => $"[0x{Offset:X}] {Type} (size=0x{Size:X})";
    }

    public class StructField
    {
        public string Name = "";
        public string Type = "";
        public bool IsStruct; // if true, type is another struct that has to be defined before this struct
        public int Offset;
        public int ArrayLength; // 0 if not an array
        public int Size;

        public override string ToString() => $"[0x{Offset:X}] {Type} {Name}{(ArrayLength > 0 ? $"[{ArrayLength}]" : "")}{(IsStruct ? " (struct)" : "")} (size=0x{Size:X})";
    }

    public class Struct
    {
        public int Size;
        public VTable? PrimaryVTable;
        public List<SecondaryVTable> SecondaryVTables = new();
        public List<StructBase> Bases = new(); // sorted by offset
        public List<StructField> Fields = new(); // sorted by offset, non overlapping with bases

        public override string ToString() => $"size=0x{Size:X}";
    }

    public class Global
    {
        public string Type = "";
        public string Name = "";
        public Address? Address;
        public int Size;

        public override string ToString() => $"{Type} {Name} (size=0x{Size:X}) @ {Address}";
    }

    public SortedDictionary<string, Enum> Enums = new();
    public SortedDictionary<string, Struct> Structs = new();
    public SortedDictionary<ulong, Global> Globals = new(); // key = ea
    public SortedDictionary<ulong, Function> Functions = new(); // key = ea

    public void Write(string path)
    {
        var data = new SerializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build().Serialize(this);
        File.WriteAllText(path, data);
    }

    public bool ValidateUniqueEaName()
    {
        Dictionary<ulong, string> uniqueEAs = new();
        Dictionary<string, string> uniqueNames = new();
        Func<ulong, string, string, bool> validate = (ea, name, text) =>
        {
            bool success = true;
            if (ea != 0 && !uniqueEAs.TryAdd(ea, text))
            {
                Debug.WriteLine($"Duplicate EA 0x{ea:X}: {text} and {uniqueEAs[ea]}");
                success = false;
            }
            if (name.Length > 0 && !uniqueNames.TryAdd(name, text))
            {
                Debug.WriteLine($"Duplicate name {name}: {text} and {uniqueNames[name]}");
                success = false;
            }
            return success;
        };

        bool success = true;
        foreach (var (ea, g) in Globals)
            success &= validate(ea, g.Name, $"global {g.Name}");
        foreach (var (ea, f) in Functions)
            success &= validate(ea, f.Name, $"function {f.Name}");
        foreach (var (name, s) in Structs)
        {
            if (s.PrimaryVTable != null)
                success &= validate(s.PrimaryVTable.Ea, $"vtbl_{name}", $"vtbl_{name}");
            foreach (var vt in s.SecondaryVTables)
                success &= validate(vt.Ea, $"vtbl_{name}__{vt.Base}", $"vtbl_{name}__{vt.Base}");
        }
        return success;
    }

    public bool ValidateLayout()
    {
        bool success = true;
        foreach (var (name, s) in Structs)
        {
            int minFieldOffset = 0;
            foreach (var b in s.Bases)
            {
                if (b.Offset != minFieldOffset)
                {
                    Debug.WriteLine($"Structure {name} has incorrect placement for base {b}");
                    success = false;
                }
                minFieldOffset = b.Offset + b.Size;
            }

            if (s.PrimaryVTable != null)
            {
                minFieldOffset = Math.Max(minFieldOffset, 8);
            }

            if (s.Fields.Count > 0 && s.Fields[0].Offset < minFieldOffset)
            {
                Debug.WriteLine($"Structure {name} has first field {s.Fields[0]} overlapping bases or vtable");
                success = false;
            }
        }
        return success;
    }
}
