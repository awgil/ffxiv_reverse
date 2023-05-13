using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Specialized;
using System.Xml.Linq;

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
        public string Name { get; set; } = "";
        public long Value { get; set; }

        public override string ToString() => $"{Name} = 0x{Value:X}";
    }

    public class Enum
    {
        public bool IsBitfield { get; set; }
        public bool IsSigned { get; set; }
        public int Width { get; set; }
        public List<EnumValue> Values { get; set; } = new(); // sorted by value

        public override string ToString() => $"{(IsSigned ? "signed" : "unsigned")} {Width}-byte-wide {(IsBitfield ? "bitfield" : "enum")}";
    }

    public class Address
    {
        public string Sig { get; set; }
        public int SigOffset { get; set; }

        public Address(string sig, int sigOffset = 0)
        {
            Sig = sig;
            SigOffset = sigOffset;
        }

        public override string ToString() => $"'{Sig}' +{SigOffset}";
    }

    public class Function
    {
        public const string Placeholder = "^";

        public List<string> Names { get; set; } = new(); // contains at least one element
        public string Type { get; set; } // has placeholder where cconv/name/pointer could be added
        public Address? Address { get; set; }

        public Function(string name, string type = "", Address? address = null)
        {
            Names.Add(name);
            Type = type;
            Address = address;
        }

        public override string ToString() => $"{Names.First()}: {Type} @ {Address}";
    }

    // instances of vtables used by derived classes via multiple inheritance - contain same functions as base class with custom implementations; this pointer is shifted
    public class SecondaryVTable
    {
        public ulong Ea { get; set; }
        public string Derived { get; set; } = "";
        public int Offset { get; set; } // <= 0 if unknown, otherwise >0 (offset of an (in)direct base class inside derived)

        public override string ToString() => $"0x{Ea:X} for {Derived} +0x{Offset:X}";
    }

    public class VTable
    {
        public string Base { get; set; } = ""; // empty if this is a root of the class hierarchy
        public ulong Ea { get; set; }
        public Address? Address { get; set; }
        public SortedDictionary<uint, Function> VFuncs { get; set; } = new();
        public List<SecondaryVTable> Secondary { get; set; } = new();

        public override string ToString() => $"0x{Ea:X} {Address}";
    }

    public class StructBase
    {
        public string Type { get; set; } = "";
        public int Offset { get; set; }
        public int Size { get; set; }

        public override string ToString() => $"[0x{Offset:X}] {Type} (size=0x{Size:X})";
    }

    public class StructField
    {
        public List<string> Names { get; set; } = new(); // contains at least one element
        public string Type { get; set; }
        public bool IsStruct { get; set; } // if true, type is another struct that has to be defined before this struct
        public int Offset { get; set; }
        public int ArrayLength { get; set; } // 0 if not an array
        public int Size { get; set; }

        public StructField(string name, string type, bool isStruct, int offset, int arrayLength, int size)
        {
            Names.Add(name);
            Type = type;
            IsStruct = isStruct;
            Offset = offset;
            ArrayLength = arrayLength;
            Size = size;
        }

        public override string ToString() => $"[0x{Offset:X}] {Type} {Names.First()}{(ArrayLength > 0 ? $"[{ArrayLength}]" : "")}{(IsStruct ? " (struct)" : "")} (size=0x{Size:X})";
    }

    public class Struct
    {
        public bool IsUnion { get; set; }
        public int Size { get; set; }
        public VTable? VTable { get; set; }
        public List<StructBase> Bases { get; set; } = new(); // sorted by offset
        public List<StructField> Fields { get; set; } = new(); // sorted by offset, non overlapping with bases

        public override string ToString() => $"{(IsUnion ? "union" : "struct")} size=0x{Size:X}";
    }

    public class Global
    {
        public List<string> Names { get; set; } = new(); // contains at least one element
        public string Type { get; set; }
        public int Size { get; set; }
        public Address? Address { get; set; }

        public Global(string name, string type, int size, Address? address = null)
        {
            Names.Add(name);
            Type = type;
            Size = size;
            Address = address;
        }

        public override string ToString() => $"{Type} {Names.First()} (size=0x{Size:X}) @ {Address}";
    }

    public SortedDictionary<string, Enum> Enums { get; set; } = new();
    public OrderedDictionary Structs { get; set; } = new(); // name -> Struct
    public SortedDictionary<ulong, Global> Globals { get; set; } = new(); // key = ea
    public SortedDictionary<ulong, Function> Functions { get; set; } = new(); // key = ea

    public Struct? GetStruct(string name) => (Struct?)Structs[name];
    public IEnumerable<(string Name, Struct Data)> EnumerateStructs()
    {
        var e = Structs.GetEnumerator();
        while (e.MoveNext())
            yield return ((string)e.Key, (Struct)e.Value!);
    }

    public void Normalize()
    {
        // sort structs in dependency order: ensure base classes or substructures are ordered before their users
        Dictionary<string, HashSet<string>> deps = new();
        Func<string, HashSet<string>> depsFor = n =>
        {
            if (!deps.TryGetValue(n, out var v))
                deps.Add(n, v = new());
            return v;
        };

        foreach (var (n, s) in EnumerateStructs())
        {
            var curDeps = depsFor(n);
            foreach (var b in s.Bases)
                curDeps.Add(b.Type);
            foreach (var f in s.Fields.Where(f => f.IsStruct))
                curDeps.Add(f.Type);
            if (s.VTable != null)
                foreach (var v in s.VTable.Secondary)
                    depsFor(v.Derived).Add(n);
        }

        OrderedDictionary reordered = new();
        foreach (var (n, _) in EnumerateStructs())
            NormalizeAddAfterSubstructs(reordered, deps, n);
        Structs = reordered;

        // calculate secondary base offsets
        foreach (var (n, s) in EnumerateStructs())
        {
            if (s.VTable == null)
                continue;
            foreach (var v in s.VTable.Secondary)
            {
                v.Offset = NormalizeCalculateBaseOffset(v.Derived, n);
                if (v.Offset <= 0)
                {
                    Debug.WriteLine($"Could not find {n} among secondary bases of {v.Derived}");
                }
            }
        }

        // ensure structures that have bases with vtables also have one
        foreach (var (n, s) in EnumerateStructs().Where(kv => kv.Data.Bases.Count > 0 && kv.Data.VTable == null && GetStruct(kv.Data.Bases[0].Type)!.VTable != null))
        {
            Debug.WriteLine($"Structure {n} has no vtable, but its base {s.Bases[0].Type} has one");
            s.VTable = new() { Base = s.Bases[0].Type };
            s.Size = Math.Max(s.Size, 8);
        }
    }

    private void NormalizeAddAfterSubstructs(OrderedDictionary reordered, Dictionary<string, HashSet<string>> deps, string name)
    {
        if (reordered.Contains(name))
            return;
        foreach (var dep in deps[name])
            NormalizeAddAfterSubstructs(reordered, deps, dep);
        reordered[name] = GetStruct(name);
    }

    private int NormalizeCalculateBaseOffset(string derivedType, string baseType)
    {
        if (derivedType == baseType)
            return 0;
        foreach (var b in GetStruct(derivedType)!.Bases)
        {
            var baseOff = NormalizeCalculateBaseOffset(b.Type, baseType);
            if (baseOff >= 0)
                return b.Offset + baseOff;
        }
        return -1;
    }

    public void Write(string path, bool useYaml)
    {
        var data = useYaml
            ? new SerializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build().Serialize(this)
            : JsonSerializer.Serialize(this, new JsonSerializerOptions() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true });
        File.WriteAllText(path, data);
    }

    public void DumpNestedUnions()
    {
        foreach (var (name, s) in EnumerateStructs().Where(kv => !kv.Data.IsUnion))
            foreach (var g in s.Fields.GroupBy(f => f.Offset))
                if (g.Count() > 1)
                    Debug.WriteLine($"Nested union found at {name}+0x{g.Key:X}: {string.Join(", ", g.Select(f => f.Names.First()))}");
    }

    public void DumpMultipleNames()
    {
        foreach (var (ea, g) in Globals.Where(g => g.Value.Names.Count > 1))
            Debug.WriteLine($"Multiple names for global @ 0x{ea:X}: {string.Join(", ", g.Names)}");
        foreach (var (ea, f) in Functions.Where(f => f.Value.Names.Count > 1))
            Debug.WriteLine($"Multiple names for function @ 0x{ea:X}: {string.Join(", ", f.Names)}");
        foreach (var (name, s) in EnumerateStructs())
        {
            foreach (var f in s.Fields.Where(f => f.Names.Count > 1))
                Debug.WriteLine($"Multiple names for {name} field +0x{f.Offset:X}: {string.Join(", ", f.Names)}");
            if (s.VTable != null)
                foreach (var (idx, vf) in s.VTable.VFuncs.Where(f => f.Value.Names.Count > 1))
                    Debug.WriteLine($"Multiple names for {name} vfunc #{idx}: {string.Join(", ", vf.Names)}");
        }
    }

    public bool ValidateUniqueEaName()
    {
        Dictionary<ulong, string> uniqueEAs = new();
        Dictionary<string, string> uniqueNames = new();
        Func<ulong, IEnumerable<string>, string, bool> validate = (ea, names, text) =>
        {
            bool success = true;
            if (ea != 0 && !uniqueEAs.TryAdd(ea, text))
            {
                Debug.WriteLine($"Duplicate EA 0x{ea:X}: {text} and {uniqueEAs[ea]}");
                success = false;
            }
            foreach (var name in names)
            {
                if (!uniqueNames.TryAdd(name, text))
                {
                    Debug.WriteLine($"Duplicate name {name}: {text} and {uniqueNames[name]}");
                    success = false;
                }
            }
            return success;
        };

        bool success = true;
        foreach (var (ea, g) in Globals)
            success &= validate(ea, g.Names, $"global {g.Names.FirstOrDefault()}");
        foreach (var (ea, f) in Functions)
            success &= validate(ea, f.Names, $"function {f.Names.FirstOrDefault()}");
        foreach (var (name, s) in EnumerateStructs())
        {
            if (s.VTable != null)
            {
                success &= validate(s.VTable.Ea, new[] { $"vtbl_{name}" }, $"vtbl_{name}");
                foreach (var vt in s.VTable.Secondary)
                    success &= validate(vt.Ea, new[] { $"vtbl_{vt.Derived}___{name}" }, $"vtbl_{vt.Derived}___{name}");
            }
        }
        return success;
    }

    public bool ValidateLayout()
    {
        bool success = true;
        foreach (var (name, s) in EnumerateStructs())
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

            if (s.VTable != null)
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
