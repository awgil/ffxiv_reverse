using FFXIVClientStructs.FFXIV.Client.Game;
using System;
using System.Numerics;
using Netlog.ServerIPC;
using System.Text;
using Dalamud.Memory;
using Dalamud.Utility;

namespace Netlog;

// utilities for decoding packets; passed to all decode functions
public unsafe class PacketDecoder
{
    private int* _netOffsetBaseFixed;
    private int* _netOffsetBaseChanging;
    private int* _netOffsetAdjusted;

    public OpcodeMap OpcodeMap;

    public int NetOffsetBaseFixed => *_netOffsetBaseFixed; // this is set to rand() % 256 + 14 on static init
    public int NetOffsetBaseChanging => *_netOffsetBaseChanging; // this is set to rand() % 255 + 1 on every zone change
    public int NetOffsetAdjusted => *_netOffsetAdjusted; // this is set to (rand() % base-sum) if id is not scrambled (so < base-sum) -or- to base-sum + delta calculated from packet data (if scrambled) on every zone change
    public int NetScrambleDelta => Math.Max(0, NetOffsetAdjusted - NetOffsetBaseFixed - NetOffsetBaseChanging); // if >0, this delta is added to some ids in packets sent by server

    public PacketDecoder()
    {
        var scrambleAddr = Service.SigScanner.GetStaticAddressFromSig("44 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 8B 05 ?? ?? ?? ?? 33 D2 44 03 05 ?? ?? ?? ?? 48 8B 5C 24");
        Service.LogInfo($"Scramble address = 0x{scrambleAddr:X}");
        _netOffsetBaseChanging = (int*)scrambleAddr;
        _netOffsetAdjusted = _netOffsetBaseChanging + 1;
        _netOffsetBaseFixed = _netOffsetBaseChanging + 3;

        OpcodeMap = OpcodeMapBuilder.Build();
    }

    public static string Vec3Str(Vector3 v) => $"[{v.X:f3}, {v.Y:f3}, {v.Z:f3}]";

    public static string ObjStr(ulong objID)
    {
        var obj = Service.ObjectTable.SearchById(objID);
        return obj != null ? $"{obj.DataId:X} '{obj.Name}' <{obj.ObjectId:X}>" : $"(not found) <{objID:X}>";
    }

    public static string LogMsgStr(uint id) => $"{id} '{Service.LuminaRow<Lumina.Excel.GeneratedSheets.LogMessage>(id)?.Text}'";

    public static string SpellStr(uint id) => Service.LuminaRow<Lumina.Excel.GeneratedSheets.Action>(id)?.Name ?? "<not found>";
    public static string ItemStr(uint id)
    {
        // see Dalamud.Game.Text.SeStringHandling.Payloads.GetAdjustedId
        // TODO: id > 500000 is "collectible", >2000000 is "event" ??
        bool isHQ = id > 1000000;
        string name = Service.LuminaRow<Lumina.Excel.GeneratedSheets.Item>(id % 1000000)?.Name ?? "<not found>";
        return $"{name}{(isHQ ? " (HQ)" : "")}";
    }

    public static string ActionNameStr(ActionType type, uint id) => type switch
    {
        ActionType.Spell => SpellStr(id),
        ActionType.Item => ItemStr(id),
        _ => $""
    };
    public static string ActionStr(ActionType type, uint id) => $"{type} {id} '{ActionNameStr(type, id)}'";

    public static string StatusStr(uint statusID) => $"{statusID} '{Service.LuminaRow<Lumina.Excel.GeneratedSheets.Status>(statusID)?.Name ?? "<not found>"}'";
    public static string ClassJobAbbrev(byte classJob) => Service.LuminaRow<Lumina.Excel.GeneratedSheets.ClassJob>(classJob)?.Abbreviation ?? "<unknown>";

    // coord: ((intCoord * 3.0518043) * 0.0099999998) - 1000.0 (0 => -1000, 65535 => +1000)
    public static Vector3 IntToFloatCoords(ushort x, ushort y, ushort z)
    {
        float fx = x * (2000.0f / 65535) - 1000;
        float fy = y * (2000.0f / 65535) - 1000;
        float fz = z * (2000.0f / 65535) - 1000;
        return new(fx, fy, fz);
    }

    // rotation: 0 -> -180, 65535 -> +180
    public static float IntToFloatAngleDeg(ushort rot)
    {
        return rot * (360.0f / 65535) - 180;
    }

    public static string ByteArrayStr(byte* p, int len)
    {
        var sb = new StringBuilder(len * 2 + 1);
        for (int i = 0; i < len; ++i)
            sb.Append($"{p[i]:X2}");
        return sb.ToString();
    }

    public void AddStatuses(TextNode res, ServerIPC.Status* list, int count, int offset = 0)
    {
        for (int i = 0; i < count; ++i)
        {
            var s = list + i;
            if (s->ID != 0)
                res.AddChild($"[{i + offset}] {StatusStr(s->ID)} {s->Extra:X4} {s->RemainingTime:f3}s left, from {ObjStr(s->SourceID)}");
        }
    }

    public TextNode DecodeStatusEffectList(StatusEffectList* p, string extra = "")
    {
        var res = new TextNode($"L{p->Level} {ClassJobAbbrev(p->ClassID)}, hp={p->CurHP}/{p->MaxHP}, mp={p->CurMP}/{p->MaxMP}, shield={p->ShieldValue}%{extra}, u={p->u2:X2} {p->u3:X2} {p->u12:X4} {p->u17C:X8}");
        AddStatuses(res, (ServerIPC.Status*)p->Statuses, 30);
        return res;
    }

    public TextNode DecodeStatusEffectListDouble(StatusEffectListDouble* p)
    {
        var res = DecodeStatusEffectList(&p->Data);
        AddStatuses(res, (ServerIPC.Status*)p->SecondSet, 30, 30);
        return res;
    }

    public TextNode DecodeStatusEffectListPlayer(StatusEffectListPlayer* p)
    {
        var res = new TextNode("");
        AddStatuses(res, (ServerIPC.Status*)p->Statuses, 30);
        return res;
    }

    public TextNode DecodeUpdateRecastTimes(UpdateRecastTimes* p)
    {
        var res = new TextNode("");
        for (int i = 0; i < 80; ++i)
            res.AddChild($"group {i}: {p->Elapsed[i]:f3}/{p->Total[i]:f3}s");
        return res;
    }

    public TextNode DecodeEffectResult(EffectResultEntry* entries, int count)
    {
        var res = new TextNode($"{count} entries, u={*(uint*)(entries + count):X8}");
        for (int i = 0; i < count; ++i)
        {
            var e = entries + i;
            var resEntry = res.AddChild($"[{i}] seq={e->RelatedActionSequence}/{e->RelatedTargetIndex}, actor={ObjStr(e->ActorID)}, class={ClassJobAbbrev(e->ClassID)}, hp={e->CurHP}/{e->MaxHP}, mp={e->CurMP}, shield={e->ShieldValue}, u={e->u16:X4}");
            var cnt = Math.Min(4, (int)e->EffectCount);
            var eff = (EffectResultEffect*)e->Effects;
            for (int j = 0; j < cnt; ++j)
            {
                resEntry.AddChild($"#{eff->EffectIndex}: id={StatusStr(eff->StatusID)}, extra={eff->Extra:X2}, dur={eff->Duration:f3}s, src={ObjStr(eff->SourceID)}, pad={eff->pad1:X2} {eff->pad2:X4}");
                ++eff;
            }
        }
        return res;
    }

    public TextNode DecodeEffectResultBasic(EffectResultBasicEntry* entries, int count)
    {
        var res = new TextNode($"{count} entries, u={*(uint*)(entries + count):X8}");
        for (int i = 0; i < count; ++i)
        {
            var e = entries + i;
            res.AddChild($"[{i}] seq={e->RelatedActionSequence}/{e->RelatedTargetIndex}, actor={ObjStr(e->ActorID)}, hp={e->CurHP}, u={e->uD:X2} {e->uE:X4}");
        }
        return res;
    }

    public TextNode DecodeActorControl(ActorControlCategory category, uint p1, uint p2, uint p3, uint p4, uint p5, uint p6, ulong targetID)
    {
        var details = category switch
        {
            ActorControlCategory.CancelCast => $"{ActionStr((ActionType)p2, p3)}, interrupted={p4 == 1}", // note: some successful boss casts have this message on completion, seen param1=param4=0, param2=1; param1 is related to cast time?..
            ActorControlCategory.RecastDetails => $"group {p1}: {p2 * 0.01f:f2}/{p3 * 0.01f:f2}s",
            ActorControlCategory.Cooldown => $"group {p1}: action={ActionStr(ActionType.Spell, p2)}, time={p3 * 0.01f:f2}s",
            ActorControlCategory.GainEffect => $"{StatusStr(p1)}: extra={p2:X4}",
            ActorControlCategory.LoseEffect => $"{StatusStr(p1)}: extra={p2:X4}, source={ObjStr(p3)}, unk-update={p4 != 0}",
            ActorControlCategory.UpdateEffect => $"#{p1} {StatusStr(p2)}: extra={p3:X4}",
            ActorControlCategory.TargetIcon => $"{p1 - NetScrambleDelta}",
            ActorControlCategory.Tether => $"#{p1}: {p2} -> {ObjStr(p3)} progress={p4}%",
            ActorControlCategory.TetherCancel => $"#{p1}: {p2}",
            ActorControlCategory.SetTarget => $"{ObjStr(targetID)}",
            ActorControlCategory.SetAnimationState => $"#{p1} = {p2}",
            ActorControlCategory.SetModelState => $"{p1}",
            ActorControlCategory.PlayActionTimeline => $"{p1:X4}",
            ActorControlCategory.EObjSetState => $"{p1:X4}, housing={(p3 != 0 ? p4 : null)}",
            ActorControlCategory.EObjAnimation => $"{p1:X4} {p2:X4}",
            ActorControlCategory.ActionRejected => $"{LogMsgStr(p1)}; action={ActionStr((ActionType)p2, p3)}, recast={p4 * 0.01f:f2}/{p5 * 0.01f:f2}, src-seq={p6}",
            ActorControlCategory.IncrementRecast => $"group {p1}: dt=dt={p2 * 0.01f:f2}s",
            _ => ""
        };
        return new TextNode($"{category} {details} ({p1:X8} {p2:X8} {p3:X8} {p4:X8} {p5:X8} {p6:X8} {ObjStr(targetID)})");
    }

    public TextNode DecodeActionEffect(ActionEffectHeader* data, ActionEffect* effects, ulong* targetIDs, uint maxTargets, Vector3 targetPos)
    {
        var rot = IntToFloatAngleDeg(data->rotation);
        var aid = (uint)(data->actionId - NetScrambleDelta);
        var res = new TextNode($"#{data->globalEffectCounter} ({data->SourceSequence}) {ActionStr(data->actionType, aid)} ({data->actionId}/{data->actionAnimationId}), animTarget={ObjStr(data->animationTargetId)}, animLock={data->animationLockTime:f3}, rot={rot:f2}, pos={Vec3Str(targetPos)}, var={data->variation}, someTarget={ObjStr(data->SomeTargetID)}, u={data->unknown20:X2} {data->padding21:X4}");
        res.Children = new();
        var targets = Math.Min(data->NumTargets, maxTargets);
        for (int i = 0; i < targets; ++i)
        {
            ulong targetId = targetIDs[i];
            if (targetId == 0)
                continue;
            var resTarget = res.AddChild($"target {i} == {ObjStr(targetId)}");
            for (int j = 0; j < 8; ++j)
            {
                ActionEffect* eff = effects + (i * 8) + j;
                if (eff->Type == ActionEffectType.Nothing)
                    continue;
                resTarget.AddChild($"effect {j} == {eff->Type}, params={eff->Param0:X2} {eff->Param1:X2} {eff->Param2:X2} {eff->Param3:X2} {eff->Param4:X2} {eff->Value:X4}");
            }
        }
        return res;
    }

    public TextNode DecodeActorCast(ActorCast* p)
    {
        uint aid = (uint)(p->ActionID - NetScrambleDelta);
        return new($"{ActionStr(p->ActionType, aid)} ({ActionStr(ActionType.Spell, p->SpellID)}) @ {ObjStr(p->TargetID)}, time={p->CastTime:f3} ({p->BaseCastTime100ms * 0.1f:f1}), rot={IntToFloatAngleDeg(p->Rotation):f2}, targetpos={Vec3Str(IntToFloatCoords(p->PosX, p->PosY, p->PosZ))}, interruptible={p->Interruptible}, u1={p->u1:X2}, u2={ObjStr(p->u2_objID)}, u3={p->u3:X4}");
    }

    public TextNode DecodeUpdateHate(UpdateHate* p)
    {
        var res = new TextNode($"{p->NumEntries} entries, pad={p->pad1:X2} {p->pad2:X4} {p->pad3:X8}");
        var e = (UpdateHateEntry*)p->Entries;
        for (int i = 0, cnt = Math.Min((int)p->NumEntries, 8); i < cnt; ++i, ++e)
            res.AddChild($"{ObjStr(e->ObjectID)} = {e->Enmity}%");
        return res;
    }

    public TextNode DecodeUpdateHater(UpdateHater* p)
    {
        var res = new TextNode($"{p->NumEntries} entries, pad={p->pad1:X2} {p->pad2:X4} {p->pad3:X8}");
        var e = (UpdateHateEntry*)p->Entries;
        for (int i = 0, cnt = Math.Min((int)p->NumEntries, 32); i < cnt; ++i, ++e)
            res.AddChild($"{ObjStr(e->ObjectID)} = {e->Enmity}%");
        return res;
    }

    public TextNode DecodeUpdateClassInfo(UpdateClassInfo* p, string extra = "") => new($"L{p->CurLevel}/{p->ClassLevel}/{p->SyncedLevel} {ClassJobAbbrev(p->ClassID)}, exp={p->CurExp}+{p->RestedExp}{extra}");

    public TextNode DecodeWaymarkPreset(WaymarkPreset* p)
    {
        var res = new TextNode($"pad={p->pad1:X2} {p->pad2:X4}");
        for (int i = 0; i < 8; ++i)
            res.AddChild($"{(WaymarkID)i}: {(p->Mask & (1 << i)) != 0} at {Vec3Str(new(p->PosX[i] * 0.001f, p->PosY[i] * 0.001f, p->PosZ[i] * 0.001f))}");
        return res;
    }
    public TextNode DecodeWaymark(Waymark* p) => new TextNode($"{p->ID}: {p->Active != 0} at {Vec3Str(new(p->PosX * 0.001f, p->PosY * 0.001f, p->PosZ * 0.001f))}, pad={p->pad2:X4}");

    public TextNode? DecodePacket(ushort opcode, byte* payload, int length) => OpcodeMap.ID(opcode) switch
    {
        PacketID.RSVData when (RSVData*)payload is var p => new($"{MemoryHelper.ReadStringNullTerminated((nint)p->Key)} = {MemoryHelper.ReadString((nint)p->Value, p->ValueLength)} [{p->ValueLength}]"),
        PacketID.Countdown when (Countdown*)payload is var p => new($"{p->Time}s from {ObjStr(p->SenderID)}{(p->FailedInCombat != 0 ? " fail-in-combat" : "")} '{MemoryHelper.ReadStringNullTerminated((nint)p->Text)}' u={p->u4:X4} {p->u9:X2} {p->u10:X2}"),
        PacketID.CountdownCancel when (CountdownCancel*)payload is var p => new($"from {ObjStr(p->SenderID)} '{MemoryHelper.ReadStringNullTerminated((nint)p->Text)}' u={p->u4:X4} {p->u6:X4}"),
        PacketID.StatusEffectList when (StatusEffectList*)payload is var p => DecodeStatusEffectList(p),
        PacketID.StatusEffectListEureka when (StatusEffectListEureka*)payload is var p => DecodeStatusEffectList(&p->Data, $", rank={p->Rank}/{p->Element}/{p->u2}, pad={p->pad3:X2}"),
        PacketID.StatusEffectListBozja when (StatusEffectListBozja*)payload is var p => DecodeStatusEffectList(&p->Data, $", rank={p->Rank}, pad={p->pad1:X2}{p->pad2:X4}"),
        PacketID.StatusEffectListDouble when (StatusEffectListDouble*)payload is var p => DecodeStatusEffectListDouble(p),
        PacketID.EffectResult1 when (EffectResultN*)payload is var p => DecodeEffectResult((EffectResultEntry*)p->Entries, Math.Min((int)p->NumEntries, 1)),
        PacketID.EffectResult4 when (EffectResultN*)payload is var p => DecodeEffectResult((EffectResultEntry*)p->Entries, Math.Min((int)p->NumEntries, 4)),
        PacketID.EffectResult8 when (EffectResultN*)payload is var p => DecodeEffectResult((EffectResultEntry*)p->Entries, Math.Min((int)p->NumEntries, 8)),
        PacketID.EffectResult16 when (EffectResultN*)payload is var p => DecodeEffectResult((EffectResultEntry*)p->Entries, Math.Min((int)p->NumEntries, 16)),
        PacketID.EffectResultBasic1 when (EffectResultBasicN*)payload is var p => DecodeEffectResultBasic((EffectResultBasicEntry*)p->Entries, Math.Min((int)p->NumEntries, 1)),
        PacketID.EffectResultBasic4 when (EffectResultBasicN*)payload is var p => DecodeEffectResultBasic((EffectResultBasicEntry*)p->Entries, Math.Min((int)p->NumEntries, 4)),
        PacketID.EffectResultBasic8 when (EffectResultBasicN*)payload is var p => DecodeEffectResultBasic((EffectResultBasicEntry*)p->Entries, Math.Min((int)p->NumEntries, 8)),
        PacketID.EffectResultBasic16 when (EffectResultBasicN*)payload is var p => DecodeEffectResultBasic((EffectResultBasicEntry*)p->Entries, Math.Min((int)p->NumEntries, 16)),
        PacketID.EffectResultBasic32 when (EffectResultBasicN*)payload is var p => DecodeEffectResultBasic((EffectResultBasicEntry*)p->Entries, Math.Min((int)p->NumEntries, 32)),
        PacketID.EffectResultBasic64 when (EffectResultBasicN*)payload is var p => DecodeEffectResultBasic((EffectResultBasicEntry*)p->Entries, Math.Min((int)p->NumEntries, 64)),
        PacketID.ActorControl when (ActorControl*)payload is var p => DecodeActorControl(p->category, p->param1, p->param2, p->param3, p->param4, 0, 0, 0xE0000000),
        PacketID.ActorControlSelf when (ActorControlSelf*)payload is var p => DecodeActorControl(p->category, p->param1, p->param2, p->param3, p->param4, p->param5, p->param6, 0xE0000000),
        PacketID.ActorControlTarget when (ActorControlTarget*)payload is var p => DecodeActorControl(p->category, p->param1, p->param2, p->param3, p->param4, 0, 0, p->TargetID),
        PacketID.UpdateHpMpTp when (UpdateHpMpTp*)payload is var p => new($"hp={p->HP}, mp={p->MP}, gp={p->GP}"),
        PacketID.ActionEffect1 when (ActionEffect1*)payload is var p => DecodeActionEffect(&p->Header, (ActionEffect*)p->Effects, p->TargetID, 1, new()),
        PacketID.ActionEffect8 when (ActionEffect8*)payload is var p => DecodeActionEffect(&p->Header, (ActionEffect*)p->Effects, p->TargetID, 8, IntToFloatCoords(p->TargetX, p->TargetY, p->TargetZ)),
        PacketID.ActionEffect16 when (ActionEffect16*)payload is var p => DecodeActionEffect(&p->Header, (ActionEffect*)p->Effects, p->TargetID, 16, IntToFloatCoords(p->TargetX, p->TargetY, p->TargetZ)),
        PacketID.ActionEffect24 when (ActionEffect24*)payload is var p => DecodeActionEffect(&p->Header, (ActionEffect*)p->Effects, p->TargetID, 24, IntToFloatCoords(p->TargetX, p->TargetY, p->TargetZ)),
        PacketID.ActionEffect32 when (ActionEffect32*)payload is var p => DecodeActionEffect(&p->Header, (ActionEffect*)p->Effects, p->TargetID, 32, IntToFloatCoords(p->TargetX, p->TargetY, p->TargetZ)),
        PacketID.StatusEffectListPlayer when (StatusEffectListPlayer*)payload is var p => DecodeStatusEffectListPlayer(p),
        PacketID.UpdateRecastTimes when (UpdateRecastTimes*)payload is var p => DecodeUpdateRecastTimes(p),
        PacketID.ActorMove when (ActorMove*)payload is var p => new($"{Vec3Str(IntToFloatCoords(p->X, p->Y, p->Z))} {IntToFloatAngleDeg(p->Rotation):f2}, anim={p->AnimationFlags:X4}/{p->AnimationSpeed}, u={p->UnknownRotation:X2} {p->Unknown:X8}"),
        PacketID.ActorSetPos when (ActorSetPos*)payload is var p => new($"{Vec3Str(new(p->X, p->Y, p->Z))} {IntToFloatAngleDeg(p->Rotation):f2}, u={p->u2:X2} {p->u3:X2} {p->u4:X8} {p->u14:X8}"),
        PacketID.ActorCast when (ActorCast*)payload is var p => DecodeActorCast(p),
        PacketID.UpdateHate when (UpdateHate*)payload is var p => DecodeUpdateHate(p),
        PacketID.UpdateHater when (UpdateHater*)payload is var p => DecodeUpdateHater(p),
        PacketID.UpdateClassInfo when (UpdateClassInfo*)payload is var p => DecodeUpdateClassInfo(p),
        PacketID.UpdateClassInfoEureka when (UpdateClassInfoEureka*)payload is var p => DecodeUpdateClassInfo(&p->Data, $", rank={p->Rank}/{p->Element}/{p->u2}, pad={p->pad3:X2}"),
        PacketID.UpdateClassInfoBozja when (UpdateClassInfoBozja*)payload is var p => DecodeUpdateClassInfo(&p->Data, $", rank={p->Rank}, pad={p->pad1:X2}{p->pad2:X4}"),
        PacketID.EnvControl when (EnvControl*)payload is var p => new($"{p->DirectorID:X8}.{p->Index} = {p->State1:X4} {p->State2:X4}, pad={p->pad9:X2} {p->padA:X4} {p->padC:X8}"),
        PacketID.WaymarkPreset when (WaymarkPreset*)payload is var p => DecodeWaymarkPreset(p),
        PacketID.Waymark when (Waymark*)payload is var p => DecodeWaymark(p),
        PacketID.ActorGauge when (ActorGauge*)payload is var p => new($"{ClassJobAbbrev(p->ClassJobID)} = {p->Payload:X16}"),
        _ => null
    };
}
