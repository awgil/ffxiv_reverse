using Dalamud.Game.Command;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Netlog;

public sealed class Plugin : IDalamudPlugin
{
    public string Name => "VNetlog";

    public DalamudPluginInterface Dalamud { get; init; }
    private CommandManager _cmdMgr;

    public WindowSystem WindowSystem = new("VNetlog");
    private MainWindow _wndMain;

    public Plugin(DalamudPluginInterface dalamud, CommandManager cmd)
    {
        dalamud.Create<Service>();

        Dalamud = dalamud;
        _cmdMgr = cmd;

        _wndMain = new();
        WindowSystem.AddWindow(_wndMain);

        Dalamud.UiBuilder.Draw += WindowSystem.Draw;
        Dalamud.UiBuilder.OpenConfigUi += () => _wndMain.IsOpen = true;
        _cmdMgr.AddHandler("/vnetlog", new((cmd, args) => _wndMain.IsOpen = true));
    }

    public void Dispose()
    {
        WindowSystem.RemoveAllWindows();
        _cmdMgr.RemoveHandler("/vnetlog");
    }
}
