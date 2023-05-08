using idapopulate;
using System.Diagnostics;

var outDir = PathUtils.FindFileAmongParents("/idbtoolkit/populate_idb.py")?.Directory;
if (outDir == null)
{
    Debug.WriteLine("Failed to find output location");
    return;
}

var testRes = new Result();
var testEnum1 = new Result.Enum() { IsSigned = true, Width = 2 };
testEnum1.Values.Add(new() { Name = "E1V1", Value = 1 });
testEnum1.Values.Add(new() { Name = "E1V1dup", Value = 1 });
testEnum1.Values.Add(new() { Name = "E1V2", Value = 2 });
testEnum1.Values.Add(new() { Name = "E1V3", Value = 10 });
testRes.Enums["test::Enum1"] = testEnum1;
var testEnum2 = new Result.Enum() { IsBitfield = true, IsSigned = false, Width = 4 };
testEnum2.Values.Add(new() { Name = "E2V1", Value = 0x1 });
testEnum2.Values.Add(new() { Name = "E2V2", Value = 0x4 });
testRes.Enums["test::Enum2"] = testEnum2;
testRes.Enums["test::Enum3"] = new() { Width = 1 };
testRes.Write(outDir.FullName + "/test.yml");

var gameRoot = PathUtils.FindGameRoot();
var resolver = new SigResolver(gameRoot + "\\ffxiv_dx11.exe");

var res = new Result();
new CSImport().Populate(res, resolver);

var dataYml = PathUtils.FindFileAmongParents("/FFXIVClientStructs/ida/data.yml");
if (dataYml != null)
    new DataYmlImport().Populate(res, dataYml);
else
    Debug.WriteLine("Failed to find data.yml");

res.ValidateUniqueEaName();
res.ValidateLayout();
res.Write(outDir.FullName + "/info.yml");
