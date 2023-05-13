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

var dataYml = PathUtils.FindFileAmongParents("/FFXIVClientStructs/ida/data.yml");
if (dataYml != null)
    new DataYmlImport().Populate(res, dataYml);
else
    Debug.WriteLine("Failed to find data.yml");

res.Normalize();

// TODO: validate that all referenced bases are really (in)direct bases
res.ValidateUniqueEaName();
res.ValidateLayout();

res.DumpNestedUnions();
res.DumpMultipleNames();

res.Write(outDir.FullName + "/info.json", false);
