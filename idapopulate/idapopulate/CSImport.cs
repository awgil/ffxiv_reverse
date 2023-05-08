using FFXIVClientStructs.Attributes;
using FFXIVClientStructs.Interop;
using FFXIVClientStructs.Interop.Attributes;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace idapopulate;

internal static class CSImportExt
{
    public static string WithoutPrefix(this string str, string prefix) => str.StartsWith(prefix) ? str.Substring(prefix.Length) : str;

    // if [FieldOffset] is not specified, assume sequential layout...
    public static int GetFieldOffset(this FieldInfo fi) => fi.GetCustomAttribute<FieldOffsetAttribute>()?.Value ?? Marshal.OffsetOf(fi.DeclaringType!, fi.Name).ToInt32();

    public static (Type?, int) GetFixedBufferInfo(this FieldInfo fi)
    {
        var attr = fi.GetCustomAttribute<FixedBufferAttribute>();
        return (attr?.ElementType, attr?.Length ?? 0);
    }

    public static (Type?, int) GetFixedArrayInfo(this FieldInfo fi)
    {
        var attr = fi.GetCustomAttribute(typeof(FixedSizeArrayAttribute<>));
        if (attr == null)
            return (null, 0);
        var len = (int?)attr.GetType().GetProperty("Count", BindingFlags.Instance | BindingFlags.Public)?.GetValue(attr) ?? 0;
        var t = attr.GetType().GetGenericArguments()[0];
        if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Pointer<>))
            t = t.GetGenericArguments()[0].MakePointerType();
        return (t, len);
    }
}

internal class CSImport
{
    private HashSet<Type> _processedTypes = new();

    public void Populate(Result res, SigResolver resolver)
    {
        var typesToProcess = GetAssemblyTypes("FFXIVClientStructs").Where(IsTypeExportable).ToList();
        for (int i = 0; i < typesToProcess.Count; i++) // note: more types could be added while processing types
        {
            PopulateType(typesToProcess[i], typesToProcess, res, resolver);
        }
    }

    private static IEnumerable<Type> GetAssemblyTypes(string assemblyName)
    {
        var assembly = AppDomain.CurrentDomain.Load(assemblyName);
        try
        {
            return assembly.DefinedTypes.Select(ti => ti.AsType());
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types.Cast<Type>();
        }
    }

    private static bool IsTypeExportable(Type type)
    {
        if (type.FullName == null)
            return false;
        if (!type.FullName.StartsWith("FFXIVClientStructs.FFXIV.") && !type.FullName.StartsWith("FFXIVClientStructs.Havok."))
            return false;
        if (type.DeclaringType != null && (type.Name is "Addresses" or "MemberFunctionPointers" or "StaticAddressPointers" || type.Name == type.DeclaringType.Name + "VTable"))
            return false;
        if (type.Name.EndsWith("e__FixedBuffer"))
            return false;
        return true;
    }

    private void QueueType(Type type, List<Type> queue)
    {
        while (DerefPointer(type) is var derefType && derefType != null)
            type = derefType;
        if (type.IsPrimitive || type == typeof(void))
            return; // void can appear as eg void* fields
        queue.Add(type);
    }

    private void PopulateType(Type type, List<Type> queue, Result res, SigResolver resolver)
    {
        if (!_processedTypes.Add(type))
            return; // already processed

        var tn = TypeName(type);
        if (type.IsEnum)
        {
            var (width, signed) = GetEnumSignWidth(type);
            var e = new Result.Enum() { IsBitfield = type.GetCustomAttribute<FlagsAttribute>() != null, IsSigned = signed, Width = width };
            foreach (var f in type.GetFields().Where(f => f.Name != "value__"))
                e.Values.Add(new() { Name = f.Name, Value = Convert.ToInt64(f.GetRawConstantValue()) });
            res.Enums.Add(tn, e);
        }
        else
        {
            if (type.IsGenericType && type.ContainsGenericParameters)
            {
                //Debug.WriteLine($"Skipping generic struct: {type}");
                return; // we don't care about unspecialized templates
            }

            var addresses = type.GetNestedType("Addresses");

            var s = new Result.Struct() { Size = SizeOf(type) };
            if ((type.StructLayoutAttribute?.Size ?? 0) is var layoutSize && layoutSize != 0 && layoutSize != s.Size)
                Debug.WriteLine($"Size mismatch for {type}: layout says 0x{layoutSize:X}, actual is 0x{s.Size:X}");

            // see whether there are any vtable definitions or virtual functions
            if (type.GetCustomAttribute<VTableAddressAttribute>() is var attrVTable && attrVTable != null)
            {
                if (attrVTable.IsPointer)
                    Debug.WriteLine($"VTable for {type} is stored as a pointer, wtf does it even mean?");
                s.PrimaryVTable = new() { Address = new(attrVTable.Signature, attrVTable.Offset), Ea = GetResolvedAddress(addresses, "VTable", resolver) };
            }

            // process methods (both virtual and non-virtual)
            foreach (var method in type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public))
            {
                if (method.GetCustomAttribute<VirtualFunctionAttribute>() is var vfAttr && vfAttr != null)
                {
                    s.PrimaryVTable ??= new();
                    s.PrimaryVTable.VFuncs.Add(vfAttr.Index, new() { Name = method.Name, Signature = ExtractFuncSig(method, tn) });
                }
                else if (method.GetCustomAttribute<MemberFunctionAttribute>() is var mfAttr && mfAttr != null)
                {
                    var ea = GetResolvedAddress(addresses, method.Name, resolver);
                    if (ea == 0)
                        Debug.WriteLine($"Failed to find method {type}.{method.Name}: sig={mfAttr.Signature}");
                    else if (res.Functions.ContainsKey(ea))
                        Debug.WriteLine($"Multiple functions resolve to same address 0x{ea:X}: {type}.{method.Name} sig={mfAttr.Signature} vs. {res.Functions[ea]}");
                    else
                        res.Functions[ea] = new() { Name = $"{tn}.{method.Name}", Address = new(mfAttr.Signature), Signature = ExtractFuncSig(method, method.IsStatic ? "" : tn) };
                }
                else if (method.GetCustomAttribute<StaticAddressAttribute>() is var saAttr && saAttr != null)
                {
                    var ea = GetResolvedAddress(addresses, method.Name, resolver);
                    if (ea == 0)
                        Debug.WriteLine($"Failed to find global {type}.{method.Name}: sig={saAttr.Signature}+0x{saAttr.Offset}");
                    else if (res.Globals.ContainsKey(ea))
                        Debug.WriteLine($"Multiple globals resolve to same address 0x{ea:X}: {type}.{method.Name} sig={saAttr.Signature}+0x{saAttr.Offset} vs. {res.Globals[ea]}");
                    else
                        res.Globals[ea] = new() { Type = saAttr.IsPointer ? tn + "*" : tn, Name = $"g_{tn}_{method.Name}", Address = new(saAttr.Signature, saAttr.Offset), Size = saAttr.IsPointer ? 8 : s.Size }; // note: name currently matches idarename
                }
            }

            var fields = type.GetFields().Where(f => !f.IsLiteral && !f.IsStatic && f.GetCustomAttribute<IDAIgnoreAttribute>() == null && f.GetCustomAttribute<ObsoleteAttribute>() == null);
            int nextOff = 0;
            int prevSize = 0;
            foreach (var (f, off) in fields.Select(f => (f, f.GetFieldOffset())).OrderBy(pair => pair.Item2))
            {
                if (off == 0 && f.Name == "VTable")
                {
                    // this is not a particularly interesting field - just mark struct as having a vtable (if it has neither known vtable address nor known virtual functions) and continue
                    s.PrimaryVTable ??= new();
                    continue;
                }

                if (off < nextOff && (s.Fields.Count == 0 || off != nextOff - prevSize)) // first check covers a situation where previous field is a base
                {
                    Debug.WriteLine($"Skipping field {type}.{f.Name} at offset 0x{off:X}: previous field ended at 0x{nextOff:X} (0x{nextOff - prevSize:X}+0x{prevSize:X})");
                    continue;
                }

                var ftype = f.FieldType;
                int fsize = 0;
                int arrLen = 0;

                var (fixedBufferElem, fixedBufferLength) = f.GetFixedBufferInfo();
                if (fixedBufferElem != null)
                {
                    fsize = SizeOf(fixedBufferElem) * fixedBufferLength;

                    var (fixedArrayElem, fixedArrayLength) = f.GetFixedArrayInfo();
                    if (fixedArrayElem != null)
                    {
                        QueueType(fixedArrayElem, queue);
                        var fixedArraySize = SizeOf(fixedArrayElem) * fixedArrayLength;
                        if (fixedArraySize != fsize)
                        {
                            Debug.WriteLine($"Array size mismatch for {type}.{f.Name}: raw is {fixedBufferElem}[{fixedBufferLength}] (0x{fsize:X}), typed is {fixedArrayElem}[{fixedArrayLength}] (0x{fixedArraySize:X})");
                            fsize = fixedArraySize;
                        }

                        ftype = fixedArrayElem;
                        arrLen = fixedArrayLength;
                    }
                    else
                    {
                        ftype = fixedBufferElem;
                        arrLen = fixedBufferLength;
                    }
                }
                else
                {
                    QueueType(ftype, queue);
                    fsize = SizeOf(f.FieldType);
                }
                bool isStruct = ftype.IsValueType && !ftype.IsPrimitive && !ftype.IsEnum && DerefPointer(ftype) == null;

                bool fieldCanBeBase = isStruct && s.Fields.Count == 0 && off == nextOff; // no gaps or fields between bases allowed
                bool isBaseClass = f.GetCustomAttribute<IDABaseClassAttribute>()?.IsBase ?? (fieldCanBeBase && off == 0 && ftype.Name == f.Name); // implicit base-class logic: single-inheritance, field name matches baseclass name
                if (isBaseClass && !fieldCanBeBase)
                {
                    Debug.WriteLine($"Field {type}.{f.Name} is marked as a base class, but can't be one");
                    isBaseClass = false;
                }

                if (isBaseClass)
                    s.Bases.Add(new() { Type = TypeName(ftype), Offset = off, Size = fsize });
                else
                    s.Fields.Add(new() { Name = f.Name, Type = TypeName(ftype), IsStruct = isStruct, Offset = off, ArrayLength = arrLen, Size = fsize });

                if (off >= nextOff)
                {
                    nextOff = off + fsize;
                    prevSize = fsize;
                }
                else
                {
                    nextOff = Math.Max(nextOff, off + fsize);
                    prevSize = Math.Max(prevSize, fsize);
                }
            }
            res.Structs.Add(tn, s);
        }
    }

    private string TypeName(Type type)
    {
        if (DerefPointer(type) is var derefType && derefType != null)
            return TypeName(derefType) + "*";
        else if (type == typeof(void))
            return "void";
        else if (type == typeof(bool))
            return "bool";
        else if (type == typeof(char))
            return "char"; // note: despite c# char being a wchar, CS seems to use it as a normal char, go figure...
        else if (type == typeof(sbyte))
            return "char";
        else if (type == typeof(byte))
            return "uchar";
        else if (type == typeof(short))
            return "short";
        else if (type == typeof(ushort))
            return "ushort";
        else if (type == typeof(int))
            return "int";
        else if (type == typeof(uint))
            return "uint";
        else if (type == typeof(long) || type == typeof(nint))
            return "__int64";
        else if (type == typeof(ulong) || type == typeof(nuint))
            return "unsigned __int64";
        else if (type == typeof(float))
            return "float";
        else if (type == typeof(double))
            return "double";
        else
            return TypeNameComplex(type);
    }

    private string TypeNameComplex(Type type)
    {
        var baseName = type.DeclaringType != null ? TypeNameComplex(type.DeclaringType) : type.Namespace?.WithoutPrefix("FFXIVClientStructs.").WithoutPrefix("FFXIV.").WithoutPrefix("Havok.").Replace(".", "::") ?? "";
        var leafName = type.Name;
        if (type.IsGenericType)
        {
            leafName = leafName.Split('`')[0];
            if (!type.ContainsGenericParameters)
            {
                leafName += $"${string.Join("$", type.GetGenericArguments().Select(arg => TypeName(arg).Replace("*", "_ptr")))}$";
            }
        }
        var fullName = baseName.Length > 0 ? $"{baseName}::{leafName}" : leafName;

        // hack for std
        if (fullName.StartsWith("STD::Std"))
        {
            fullName = fullName.WithoutPrefix("STD::Std");
            fullName = "std::"+ fullName.Substring(0, 1).ToLower() + fullName.Substring(1);
        }
        return fullName;
    }

    private int SizeOf(Type type)
    {
        if (DerefPointer(type) != null)
            return 8; // assume 64-bit
        // Marshal.SizeOf doesn't work correctly because the assembly is unmarshaled, and more specifically, it sets bools as 4 bytes long...
        return (int?)typeof(Unsafe).GetMethod("SizeOf")?.MakeGenericMethod(type).Invoke(null, null) ?? 0;
    }

    private (int, bool) GetEnumSignWidth(Type enumType)
    {
        var underlying = enumType.GetEnumUnderlyingType();
        if (underlying == typeof(sbyte))
            return (1, true);
        else if (underlying == typeof(byte))
            return (1, false);
        else if (underlying == typeof(short))
            return (2, true);
        else if (underlying == typeof(ushort))
            return (2, false);
        else if (underlying == typeof(int))
            return (4, true);
        else if (underlying == typeof(uint))
            return (4, false);
        else if (underlying == typeof(long))
            return (8, true);
        else if (underlying == typeof(ulong))
            return (8, false);
        else
            throw new Exception($"Unsupported underlying enum type {underlying} for {enumType}");
    }

    private Type? DerefPointer(Type type) => type.IsPointer ? type.GetElementType()! : type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Pointer<>) ? type.GetGenericArguments()[0] : null;

    private Result.FuncSig ExtractFuncSig(MethodInfo m, string thisType)
    {
        var res = new Result.FuncSig() { RetType = TypeName(m.ReturnType), Arguments = m.GetParameters().Select(p => new Result.FuncArg() { Type = TypeName(p.ParameterType), Name = p.Name ?? "" }).ToList() };
        if (thisType.Length > 0)
            res.Arguments.Insert(0, new() { Type = thisType + "*", Name = "this" });
        return res;
    }

    private ulong GetResolvedAddress(Type? addresses, string name, SigResolver resolver)
    {
        var addr = addresses?.GetField(name, BindingFlags.Static | BindingFlags.Public)?.GetValue(null) as Address;
        var res = addr != null ? resolver.ToEA(addr) : 0;
        if (res == 0)
            Debug.WriteLine($"Failed to resolve address for {addresses?.FullName}.{name}");
        return res;
    }
}
