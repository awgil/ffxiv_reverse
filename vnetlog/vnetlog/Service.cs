using Dalamud.Data;
using Dalamud.Game;
using Dalamud.Game.ClientState.Objects;
using Dalamud.IoC;
using Dalamud.Logging;

namespace Netlog;

class Service
{
    [PluginService] public static DataManager DataManager { get; private set; } = null!;
    [PluginService] public static ObjectTable ObjectTable { get; private set; } = null!;
    [PluginService] public static SigScanner SigScanner { get; private set; } = null!;

    public static Lumina.GameData? LuminaGameData => DataManager.GameData;
    public static T? LuminaRow<T>(uint row) where T : Lumina.Excel.ExcelRow => LuminaGameData?.GetExcelSheet<T>(Lumina.Data.Language.English)?.GetRow(row);

    public static void LogVerbose(string msg) => PluginLog.LogVerbose(msg);
    public static void LogDebug(string msg) => PluginLog.LogDebug(msg);
    public static void LogInfo(string msg) => PluginLog.LogInformation(msg);
    public static void LogWarn(string msg) => PluginLog.LogWarning(msg);
    public static void LogError(string msg) => PluginLog.LogError(msg);
}
