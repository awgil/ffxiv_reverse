using System.Diagnostics;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace idapopulate;

internal class DataYmlImport
{
    private class DataYmlClassInstance
    {
        public ulong Ea = 0;
        public bool Pointer = true; // not sure what is the correct default, but this at least is safer...
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
            if (!res.Structs.ContainsKey(name))
                res.Structs[name] = new();
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
            // we assume that if CS defines a global, it always has known type & size
            // any conflicts between CS and yaml are resolved for CS
            if (name != match.Name)
                Debug.WriteLine($"Name mismatch for global @ 0x{ea:X}: CS={match.Name}, yml={name}");
            if (type.Length > 0 && type != match.Type)
                Debug.WriteLine($"Type mismatch for global @ 0x{ea:X}: CS={match.Type}, yml={type}");
            if (size != 0 && size != match.Size)
                Debug.WriteLine($"Size mismatch for global @ 0x{ea:X}: CS={match.Size}, yml={size}");
        }
        else
        {
            res.Globals[ea] = new() { Type = type, Name = name, Size = size };
        }
    }

    private void PopulateFunction(Result res, ulong ea, string name)
    {
        var match = res.Functions.GetValueOrDefault(ea);
        if (match != null)
        {
            // any conflicts between CS and yaml are resolved for CS
            // TODO: consider overriding CS names if yml has mangled function name (starting from ?)
            if (name != match.Name)
                Debug.WriteLine($"Name mismatch for function @ 0x{ea:X}: CS={match.Name}, yml={name}");
        }
        else
        {
            res.Functions[ea] = new() { Name = name };
        }
    }

    private void PopulateClass(Result res, string name, DataYmlClass data)
    {
        var s = res.Structs[name];

        // add placeholder for missing bases
        foreach (var vt in data.Vtbls.Where(vt => vt.Base.Length > 0))
        {
            var baseName = FixClassName(vt.Base);
            if (!res.Structs.ContainsKey(baseName))
            {
                Debug.WriteLine($"Base class {baseName} for {name} is not defined");
                res.Structs[baseName] = new() { Size = 8, PrimaryVTable = new() }; // assume base also contains a vtable
            }
        }

        var primaryVT = data.Vtbls.FirstOrDefault();
        if (primaryVT != null)
        {
            if (s.PrimaryVTable == null)
            {
                s.PrimaryVTable = new() { Ea = primaryVT.Ea };
                s.Size = Math.Max(s.Size, 8);
            }
            else if (s.PrimaryVTable.Ea == 0)
            {
                s.PrimaryVTable.Ea = primaryVT.Ea;
            }
            else if (s.PrimaryVTable.Ea != primaryVT.Ea)
            {
                Debug.WriteLine($"Primary VT address mismatch for {name}: CS=0x{s.PrimaryVTable.Ea}, yml={primaryVT.Ea}");
            }

            if (primaryVT.Base.Length == 0)
            {
                // nothing to do here, yml doesn't define a base here, if CS defines one - so be it
            }
            else if (s.Bases.Count == 0)
            {
                // yml defines a base that CS doesn't know about - synthesize one
                var primaryBase = FixClassName(primaryVT.Base);
                s.Bases.Add(new() { Type = primaryBase, Size = res.Structs[primaryBase].Size });
            }
            else if (FixClassName(primaryVT.Base) is var baseName && baseName != s.Bases[0].Type)
            {
                Debug.WriteLine($"Main base mismatch for {name}: CS={s.Bases[0].Type}, yml={baseName}");
            }
        }

        foreach (var secondaryVT in data.Vtbls.Skip(1))
        {
            if (secondaryVT.Base.Length == 0)
                Debug.WriteLine($"Unexpected null secondary base name in yml for {name}");
            else if (s.Bases.Count == 0)
                Debug.WriteLine($"Class {name} has no known primary base, but has secondary base {secondaryVT.Base}");
            else
                s.SecondaryVTables.Add(new() { Ea = secondaryVT.Ea, Base = FixClassName(secondaryVT.Base) });
        }

        foreach (var (index, fname) in data.Vfuncs)
        {
            s.PrimaryVTable ??= new();
            s.Size = Math.Max(s.Size, 8); // ensure we can fit vtable
            if (!s.PrimaryVTable.VFuncs.ContainsKey(index))
                s.PrimaryVTable.VFuncs[index] = new() { Name = fname };
            else if (s.PrimaryVTable.VFuncs[index].Name != fname)
                Debug.WriteLine($"VF name mismatch for {name} #{index}: CS={s.PrimaryVTable.VFuncs[index].Name}, yml={fname}");
        }

        foreach (var (ea, fname) in data.Funcs)
            PopulateFunction(res, ea, fname.StartsWith('?') ? fname : $"{name}.{fname}");

        foreach (var inst in data.Instances)
            PopulateGlobal(res, inst.Ea, inst.Name.StartsWith('?') ? inst.Name : $"g_{name}_{inst.Name}", inst.Pointer ? name + "*" : name, inst.Pointer ? 8 : s.Size);
    }
}
