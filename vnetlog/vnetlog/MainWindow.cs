using Dalamud.Interface.Windowing;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Text;

namespace Netlog;

class MainWindow : Window, IDisposable
{
    private UITree _tree = new();
    private PacketDecoder _decoder = new();
    private PacketInterceptor _interceptor;
    private HashSet<int> _hiddenPackets = new();
    private bool _showRecvTime;
    private bool _showPacketTarget;
    private bool _showUnknown = true;
    private DateTime _referenceTime;

    public MainWindow() : base("Netlog", ImGuiWindowFlags.None)
    {
        Namespace = "vnetlog";
        _interceptor = new(_decoder);
    }

    public void Dispose()
    {
        _interceptor?.Dispose();
    }

    public override void Draw()
    {
        if (ImGui.Button("Clear"))
            _interceptor.Output.Clear();
        ImGui.SameLine();
        if (ImGui.Button("Copy to clipboard"))
            ImGui.SetClipboardText(DumpFilteredPackets());
        ImGui.SameLine();
        if (ImGui.Button(_interceptor.Active ? "Stop" : "Start"))
        {
            if (_interceptor.Active)
                _interceptor.Disable();
            else
                _interceptor.Enable();
        }

        foreach (var n in _tree.Node("Packet id -> opcode"))
            for (int id = 0; id < _decoder.OpcodeMap.IDToOpcode.Count; ++id)
                if (_decoder.OpcodeMap.IDToOpcode[id] is var opcode && opcode >= 0)
                    _tree.LeafNode($"{(ServerIPC.PacketID)id} == 0x{opcode:X4}");
        foreach (var n in _tree.Node("Packet opcode -> id"))
            for (int opcode = 0; opcode < _decoder.OpcodeMap.OpcodeToID.Count; ++opcode)
                if (_decoder.OpcodeMap.OpcodeToID[opcode] is var id && id >= 0)
                    _tree.LeafNode($"Opcode 0x{opcode:X4} == {(ServerIPC.PacketID)id}");
        _tree.LeafNode($"ID scramble delta: {_decoder.NetScrambleDelta} (== {_decoder.NetOffsetAdjusted} - {_decoder.NetOffsetBaseFixed} - {_decoder.NetOffsetBaseChanging})");

        foreach (var n in _tree.Node($"Captured packets ({_interceptor.Output.Count})###packets", _interceptor.Output.Count == 0, 0xffffffff, ContextMenuCaptured))
        {
            foreach (var p in _tree.Nodes(FilteredCapturedPackets(), p => new($"{PacketTime(p.ts)} #{p.i}: {p.text}###{p.i}", (p.subnodes?.Count ?? 0) == 0), p => ContextMenuPacket(p.opcode), null, p => _referenceTime = p.ts))
            {
                DrawDecodedChildren(p.subnodes);
            }
        }
    }

    private IEnumerable<(int i, DateTime ts, int opcode, string text, List<TextNode>? subnodes)> FilteredCapturedPackets()
    {
        for (int i = 0; i < _interceptor.Output.Count; ++i)
        {
            var p = _interceptor.Output[i];
            if (!_showUnknown && !p.Decodable)
                continue;
            if (_hiddenPackets.Contains(p.Opcode))
                continue;

            var ts = _showRecvTime ? p.RecvTime : p.SendTime;
            var actors = _showPacketTarget ? $"{p.SourceString}->{p.TargetString}" : $"{p.SourceString}";
            var text = $"{_decoder.OpcodeMap.ID(p.Opcode)} (size={p.Payload.Length}, 0x{p.Opcode:X4} {actors}): {p.PayloadStrings.Text}";
            yield return (i, ts, p.Opcode, text, p.PayloadStrings.Children);
        }
    }

    private string PacketTime(DateTime ts) => ImGui.GetIO().KeyShift && _referenceTime != default ? $"{(ts - _referenceTime).TotalSeconds:f3}" : $"{ts:O}";

    private void ContextMenuCaptured()
    {
        ImGui.MenuItem("Show recv timestamp instead of send timestamp", "", ref _showRecvTime);
        ImGui.MenuItem("Show packet target (always player ID afaik)", "", ref _showPacketTarget);
        ImGui.MenuItem("Show unknown packets", "", ref _showUnknown);
    }

    private void ContextMenuPacket(int opcode)
    {
        if (ImGui.MenuItem("Clear filters"))
            _hiddenPackets.Clear();
        if (ImGui.MenuItem($"Hide packet {opcode:X4}"))
            _hiddenPackets.Add(opcode);
    }

    private void DrawDecodedChildren(List<TextNode>? list)
    {
        if (list != null)
            foreach (var n in _tree.Nodes(list, e => new(e.Text, (e.Children?.Count ?? 0) == 0)))
                DrawDecodedChildren(n.Children);
    }

    private string DumpFilteredPackets()
    {
        var res = new StringBuilder();
        foreach (var p in FilteredCapturedPackets())
        {
            res.AppendLine($"{PacketTime(p.ts)} #{p.i}: {p.text}");
            DumpNodeChildren(res, p.subnodes, "-");
        }
        return res.ToString();
    }

    private void DumpNodeChildren(StringBuilder sb, List<TextNode>? list, string prefix)
    {
        if (list == null)
            return;
        foreach (var n in list)
        {
            sb.AppendLine($"{prefix} {n.Text}");
            DumpNodeChildren(sb, n.Children, prefix + "-");
        }
    }
}
