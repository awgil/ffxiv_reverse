using System.Collections.Generic;
using System.Linq;

namespace Netlog;

// map from network message opcodes (which are randomized every build) to more-or-less stable indices
public class OpcodeMap
{
    private List<int> _opcodeToID = new();
    private List<int> _idToOpcode = new();

    public IReadOnlyList<int> OpcodeToID => _opcodeToID;
    public IReadOnlyList<int> IDToOpcode => _idToOpcode;

    public ServerIPC.PacketID ID(int opcode) => (ServerIPC.PacketID)(opcode >= 0 && opcode < _opcodeToID.Count ? _opcodeToID[opcode] : -1);
    public int Opcode(ServerIPC.PacketID id) => (int)id >= 0 && (int)id < _idToOpcode.Count ? _idToOpcode[(int)id] : -1;

    public void AddMapping(int opcode, int id)
    {
        if (!AddEntry(_opcodeToID, opcode, id))
            Service.LogWarn($"[OpcodeMap] Trying to define several mappings for opcode {opcode} ({ID(opcode)} and ({(ServerIPC.PacketID)id})");
        if (!AddEntry(_idToOpcode, id, opcode))
            Service.LogWarn($"[OpcodeMap] Trying to map multiple opcodes to same index {(ServerIPC.PacketID)id} ({_idToOpcode[id]} and {opcode})");
    }

    private static bool AddEntry(List<int> list, int index, int value)
    {
        if (list.Count <= index)
            list.AddRange(Enumerable.Repeat(-1, index + 1 - list.Count));
        if (list[index] != -1)
            return false;
        list[index] = value;
        return true;
    }
}
