using Dalamud.Hooking;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Netlog;

[StructLayout(LayoutKind.Explicit, Pack = 1)]
unsafe struct ReceivedIPCPacket
{
    [FieldOffset(0x20)] public uint SourceActor;
    [FieldOffset(0x24)] public uint TargetActor;
    [FieldOffset(0x30)] public ulong PacketSize;
    [FieldOffset(0x38)] public ServerIPC.IPCHeader* PacketData;
}

[StructLayout(LayoutKind.Explicit, Pack = 1)]
unsafe struct ReceivedPacket
{
    [FieldOffset(0x10)] public ReceivedIPCPacket* IPC;
    [FieldOffset(0x18)] public long SendTimestamp;
}

unsafe class PacketInterceptor : IDisposable
{
    public List<Packet> Output = new();

    private PacketDecoder _decoder;

    private delegate bool FetchReceivedPacketDelegate(void* self, ReceivedPacket* outData);
    private Hook<FetchReceivedPacketDelegate> _fetchHook;

    public PacketInterceptor(PacketDecoder decoder)
    {
        _decoder = decoder;

        var fetchAddress = Service.SigScanner.ScanText("E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 44 0F B6 64 24");
        Service.LogInfo($"Fetch address: 0x{fetchAddress:X}");
        _fetchHook = Hook<FetchReceivedPacketDelegate>.FromAddress(fetchAddress, FetchReceivedPacketDetour);
    }

    public bool Active => _fetchHook.IsEnabled;
    public void Enable() => _fetchHook.Enable();
    public void Disable() => _fetchHook.Disable();

    public void Dispose()
    {
        _fetchHook.Dispose();
    }

    private bool FetchReceivedPacketDetour(void* self, ReceivedPacket* outData)
    {
        var res = _fetchHook.Original(self, outData);
        if (outData->IPC != null)
        {
            var opcode = outData->IPC->PacketData->MessageType;
            var payloadStart = (byte*)(outData->IPC->PacketData + 1);
            var payloadSize = (int)outData->IPC->PacketSize - sizeof(ServerIPC.IPCHeader);
            var payload = new Span<byte>(payloadStart, payloadSize).ToArray();
            var decoded = _decoder.DecodePacket(opcode, payloadStart, payloadSize);
            Output.Add(new()
            {
                RecvTime = DateTime.UtcNow,
                SendTime = DateTimeOffset.FromUnixTimeMilliseconds(outData->SendTimestamp).DateTime,
                Source = outData->IPC->SourceActor,
                Target = outData->IPC->TargetActor,
                Opcode = opcode,
                Decodable = decoded != null,
                Payload = payload,
                SourceString = PacketDecoder.ObjStr(outData->IPC->SourceActor),
                TargetString = PacketDecoder.ObjStr(outData->IPC->TargetActor),
                PayloadStrings = decoded ?? new(PacketDecoder.ByteArrayStr(payloadStart, payloadSize))
            });

            // HACK for replacing sastasha's shortcut eobj with custom (eg wormholes), then open recommendations actor control with eobjanim
            //if (opcode == 0x02D1 && *(uint*)(payloadStart + 4) == 0x1EB0CF)
            //{
            //    Service.LogError($"foo doing rep {*(uint*)(payloadStart + 0x2C)}");
            //    *(uint*)(payloadStart + 4) = 0x1EA1E1;
            //    *(uint*)(payloadStart + 0x2C) = 0;
            //    _hackID = *(uint*)(payloadStart + 8);
            //}
            //if (opcode == 0x0256 && *(ushort*)payloadStart == 512 && _hackID != 0)
            //{
            //    Service.LogError($"replacing openrecs for {_hackID:X}");
            //    outData->IPC->SourceActor = _hackID;
            //    outData->IPC->TargetActor = _hackID;
            //    *(ushort*)payloadStart = 413;
            //    *(uint*)(payloadStart + 4) = 1;
            //    *(uint*)(payloadStart + 8) = 2;
            //    _hackID = 0;
            //}
        }
        return res;
    }
}
