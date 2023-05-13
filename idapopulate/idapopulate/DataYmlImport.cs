using System.Diagnostics;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace idapopulate;

internal class DataYmlImport
{
    private class DataYmlClassInstance
    {
        public ulong Ea = 0;
        public bool? Pointer = null;
        public string Name = "Instance";
    }

    private class DataYmlClassVtbl
    {
        public ulong Ea = 0;
        public string Base = "";
    }

    private class DataYmlClass
    {
        public List<DataYmlClassInstance> Instances = new();
        public List<DataYmlClassVtbl> Vtbls = new();
        public SortedDictionary<uint, string> Vfuncs = new(); // index -> name
        public SortedDictionary<ulong, string> Funcs = new(); // ea -> name
    }

    private class DataYml
    {
        public string Version = "";
        public SortedDictionary<ulong, string> Globals = new(); // ea -> name
        public SortedDictionary<ulong, string> Functions = new(); // ea -> name
        public SortedDictionary<string, DataYmlClass?> Classes = new(); // name -> data
    }

    public void Populate(Result res, FileInfo fi)
    {
        var data = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build().Deserialize<DataYml>(File.ReadAllText(fi.FullName));
        foreach (var (ea, name) in data.Globals)
            PopulateGlobal(res, ea, name, "", 0);
        foreach (var (ea, name) in data.Functions)
            PopulateFunction(res, ea, name);

        // we process classes in several passes:
        // 1. ensure all struct entries exist for each class defined in yml
        foreach (var name in data.Classes.Keys.Select(FixClassName))
            if (!res.Structs.Contains(name))
                res.Structs[name] = new Result.Struct();
        // 2. process class data
        foreach (var (name, cls) in data.Classes)
            PopulateClass(res, FixClassName(name), cls ?? new()); // note: some class entries are completely empty
    }


    private static string FixClassName(string name) => name.Replace('<', '$').Replace('>', '$').Replace(',', '$').Replace("*", "_ptr");

    private void PopulateGlobal(Result res, ulong ea, string name, string type, int size)
    {
        var match = res.Globals.GetValueOrDefault(ea);
        if (match != null)
        {
            // yaml name takes precedence (it's not bound by c# rules, could even be mangled)
            if (!match.Names.Contains(name))
                match.Names.Insert(0, name);
            // we assume that if CS defines a global, it always has known type & size; any conflicts between CS and yaml are resolved for CS
            if (type.Length > 0 && type != match.Type)
                Debug.WriteLine($"Type mismatch for global @ 0x{ea:X}: CS={match.Type}, yml={type}");
            if (size != 0 && size != match.Size)
                Debug.WriteLine($"Size mismatch for global @ 0x{ea:X}: CS={match.Size}, yml={size}");
        }
        else
        {
            res.Globals[ea] = new(name, type, size);
        }
    }

    private void PopulateFunction(Result res, ulong ea, string name)
    {
        var match = res.Functions.GetValueOrDefault(ea);
        if (match != null)
        {
            // yaml name takes precedence (it's not bound by c# rules, could even be mangled)
            if (!match.Names.Contains(name))
                match.Names.Insert(0, name);
        }
        else
        {
            res.Functions[ea] = new(name);
        }
    }

    private void PopulateClass(Result res, string name, DataYmlClass data)
    {
        var s = res.GetStruct(name)!;

        // add placeholder for missing bases
        foreach (var vt in data.Vtbls.Where(vt => vt.Base.Length > 0))
        {
            var baseName = FixClassName(vt.Base);
            if (!res.Structs.Contains(baseName))
            {
                Debug.WriteLine($"Base class {baseName} for {name} is not defined");
                res.Structs[baseName] = new Result.Struct() { Size = 8, VTable = new() }; // assume base also contains a vtable
            }
        }

        var primaryVT = data.Vtbls.FirstOrDefault();
        if (primaryVT != null)
        {
            if (s.VTable == null)
            {
                s.VTable = new() { Ea = primaryVT.Ea };
                s.Size = Math.Max(s.Size, 8);
            }
            else if (s.VTable.Ea == 0)
            {
                s.VTable.Ea = primaryVT.Ea;
            }
            else if (s.VTable.Ea != primaryVT.Ea)
            {
                Debug.WriteLine($"Primary VT address mismatch for {name}: CS=0x{s.VTable.Ea}, yml={primaryVT.Ea}");
            }

            if (primaryVT.Base.Length == 0)
            {
                // nothing to do here, yml doesn't define a base here, if CS defines one - so be it
            }
            else if (s.Bases.Count == 0)
            {
                // yml defines a base that CS doesn't know about - synthesize one
                var primaryBase = FixClassName(primaryVT.Base);
                s.VTable.Base = primaryBase;
                var sBase = res.GetStruct(primaryBase)!;
                sBase.VTable ??= new(); // assume base always has vtable too (this is not strictly correct?..)
                sBase.Size = Math.Max(sBase.Size, 8);
                s.Bases.Add(new() { Type = primaryBase, Size = sBase.Size });
                s.Size = Math.Max(s.Size, sBase.Size);
            }
            else if (FixClassName(primaryVT.Base) is var baseName && baseName != s.Bases[0].Type)
            {
                Debug.WriteLine($"Main base mismatch for {name}: CS={s.Bases[0].Type}, yml={baseName}");
            }
        }

        foreach (var secondaryVT in data.Vtbls.Skip(1))
        {
            if (secondaryVT.Base.Length == 0)
            {
                Debug.WriteLine($"Unexpected null secondary base name in yml for {name}");
            }
            else if (s.Bases.Count == 0)
            {
                Debug.WriteLine($"Class {name} has no known primary base, but has secondary base {secondaryVT.Base}");
            }
            else
            {
                var secondaryBase = res.GetStruct(FixClassName(secondaryVT.Base))!;
                secondaryBase.VTable ??= new();
                secondaryBase.VTable.Secondary.Add(new() { Ea = secondaryVT.Ea, Derived = name });
                secondaryBase.Size = Math.Max(secondaryBase.Size, 8);
            }
        }

        foreach (var (index, fname) in data.Vfuncs)
        {
            s.VTable ??= new();
            s.Size = Math.Max(s.Size, 8); // ensure we can fit vtable
            if (!s.VTable.VFuncs.ContainsKey(index))
                s.VTable.VFuncs[index] = new(fname);
            else if (s.VTable.VFuncs[index].Names is var names && !names.Contains(fname))
                names.Insert(0, fname); // yaml name takes precedence (it's not bound by c# rules, could even be mangled)
        }

        foreach (var (ea, fname) in data.Funcs)
            PopulateFunction(res, ea, fname.StartsWith('?') ? fname : $"{name}.{fname}");

        foreach (var inst in data.Instances)
        {
            if (inst.Pointer == null)
                Debug.WriteLine($"Class {name} has an instance @ 0x{inst.Ea:X} that is of unknown pointerness");
            var isPointer = inst.Pointer ?? true; // if unknown, assume pointer - if we're incorrect, at least we won't overwrite other globals
            PopulateGlobal(res, inst.Ea, inst.Name.StartsWith('?') ? inst.Name : $"g_{name}_{inst.Name}", isPointer ? name + "*" : name, isPointer ? 8 : s.Size);
        }
    }
}
