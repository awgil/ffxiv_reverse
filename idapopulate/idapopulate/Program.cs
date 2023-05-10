using idapopulate;
using System.Diagnostics;

var outDir = PathUtils.FindFileAmongParents("/idbtoolkit/populate_idb.py")?.Directory;
if (outDir == null)
{
    Debug.WriteLine("Failed to find output location");
    return;
}

var gameRoot = PathUtils.FindGameRoot();
var resolver = new SigResolver(gameRoot + "\\ffxiv_dx11.exe");

var res = new Result();
new CSImport().Populate(res, resolver);
res.DumpNestedUnions();

var dataYml = PathUtils.FindFileAmongParents("/FFXIVClientStructs/ida/data.yml");
if (dataYml != null)
    new DataYmlImport().Populate(res, dataYml);
else
    Debug.WriteLine("Failed to find data.yml");

res.ValidateUniqueEaName();
res.ValidateLayout();
res.Write(outDir.FullName + "/info.yml");
