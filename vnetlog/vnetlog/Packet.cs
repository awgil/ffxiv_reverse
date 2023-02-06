using System;
using System.Collections.Generic;

namespace Netlog;

public class TextNode
{
    public string Text;
    public List<TextNode>? Children;

    public TextNode(string text)
    {
        Text = text;
    }

    public TextNode AddChild(string text)
    {
        var child = new TextNode(text);
        Children ??= new();
        Children.Add(child);
        return child;
    }
}

public struct Packet
{
    public DateTime RecvTime;
    public DateTime SendTime;
    public uint Source;
    public uint Target;
    public ushort Opcode;
    public bool Decodable;
    public byte[] Payload; // without ipc header!
    public string SourceString;
    public string TargetString;
    public TextNode PayloadStrings;
}
