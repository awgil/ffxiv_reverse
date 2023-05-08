# This is a wrapper for IDA API, it is quite inconvenient to use...
import idaapi
import ida_bytes
import ida_enum
import ida_funcs
import ida_lines
import ida_nalt
import ida_name
import ida_struct
import ida_typeinf
import ida_xref
import ida_ua
import datetime
from contextlib import contextmanager

# enumerate (ea, name) tuples for all global names in database
def enumerate_names():
	for i in range(ida_name.get_nlist_size()):
		yield (ida_name.get_nlist_ea(i), ida_name.get_nlist_name(i))

# find EA of a global name; return idaapi.BADADDR on failure
def find_global_name_ea(name):
	return ida_name.get_name_ea(idaapi.BADADDR, name)

# check whether we have a data offset at given EA
def ea_has_data_offset(ea):
	flags = ida_bytes.get_full_flags(ea)
	return (flags & ida_bytes.FF_DATA) != 0 and ida_bytes.is_off0(flags)

# get instruction at EA; return None or insn_t instance
def decode_instruction(ea):
	insn = ida_ua.insn_t()
	ilen = ida_ua.decode_insn(insn, ea)
	return insn if ilen > 0 else None

# get instruction's operand as immediate
def get_instruction_operand_immediate(ea, opIndex):
	insn = decode_instruction(ea)
	return insn.ops[opIndex].addr if insn else None

# given EA of a call instruction, return EAs of instructions setting arguments in proper order
def get_call_argument_assignment_eas(call_ea):
	return idaapi.get_arg_addrs(call_ea)

# enumerate xrefs to address
def enumerate_xrefs_to(ea):
	addr = ida_xref.get_first_cref_to(ea)
	while addr != idaapi.BADADDR:
		yield addr
		addr = ida_xref.get_next_cref_to(ea, addr)

# create typeinfo from cdecl; return None on failure
# cdecl should not have a trailing semicolon, it is added automatically
def parse_cdecl(cdecl):
	tif = ida_typeinf.tinfo_t()
	return tif if ida_typeinf.parse_decl(tif, None, cdecl + ';', 0) == '' else None

# speed up mass creation of enums or structs
@contextmanager
def mass_type_updater(utpFlag):
	print(f'{datetime.datetime.now()} Starting mass type updates: {utpFlag}')
	ida_typeinf.begin_type_updating(utpFlag)
	try:
		yield None
	finally:
		print(f'{datetime.datetime.now()} Comitting mass type updates: {utpFlag}')
		ida_typeinf.end_type_updating(utpFlag)
		print(f'{datetime.datetime.now()} Done with mass type updates: {utpFlag}')

# create enum type; returns idaapi.BADADDR on failure
def add_enum(name, bitfield, signed, width):
	# flags seem to be undocumented, here's what I found:
	# signed is 0x20000
	# hexa is FF_0NUMH | FF_1NUMH (0x1100000), decimal is FF_0NUMD | FF_1NUMD (0x2200000), octal is FF_0NUMO | FF_1NUMO (0x7700000), binary is FF_0NUMB | FF_1NUMB (0x6600000), character is FF_0CHAR | FF_1CHAR (0x3300000)
	flags = 0x1100000
	if signed:
		flags |= 0x20000
	eid = ida_enum.add_enum(idaapi.BADADDR, name, flags)
	if eid != idaapi.BADADDR:
		ida_enum.set_enum_bf(eid, bitfield)
		ida_enum.set_enum_width(eid, width)
	return eid

# get structure by name
def get_struct_by_name(name):
	return ida_struct.get_struc(ida_struct.get_struc_id(name))

# create struct type; returns struc_t or None on failure
def add_struct(name, isUnion = False):
	sid = ida_struct.add_struc(idaapi.BADADDR, name, isUnion)
	return ida_struct.get_struc(sid) if sid != idaapi.BADADDR else None

# create structure member of primitive types
def add_struct_member_primitive(s, offset, name, flag, size):
	return ida_struct.add_struc_member(s, name, offset, ida_bytes.FF_DATA | flag, None, size) == 0

def add_struct_member_byte(s, offset, name, arraySize = 1):
	return add_struct_member_primitive(s, offset, name, ida_bytes.FF_BYTE, arraySize)

def add_struct_member_word(s, offset, name, arraySize = 1):
	return add_struct_member_primitive(s, offset, name, ida_bytes.FF_WORD, arraySize * 2)

def add_struct_member_dword(s, offset, name, arraySize = 1):
	return add_struct_member_primitive(s, offset, name, ida_bytes.FF_DWORD, arraySize * 4)

def add_struct_member_qword(s, offset, name, arraySize = 1):
	return add_struct_member_primitive(s, offset, name, ida_bytes.FF_QWORD, arraySize * 8)

# create structure member of pointer type
def add_struct_member_ptr(s, offset, name, arraySize = 1):
	opinfo = ida_nalt.opinfo_t()
	opinfo.ri = ida_nalt.refinfo_t()
	opinfo.ri.base = opinfo.ri.target = idaapi.BADADDR
	opinfo.ri.flags = ida_nalt.REF_OFF64
	return ida_struct.add_struc_member(s, name, offset, ida_bytes.FF_DATA | ida_bytes.FF_QWORD | ida_bytes.FF_0OFF | ida_bytes.FF_1OFF, opinfo, arraySize * 8) == 0

# create structure member of enumeration type
def add_struct_member_enum(s, offset, name, type, arraySize = 1):
	opinfo = ida_nalt.opinfo_t()
	opinfo.tid = ida_enum.get_enum(type)
	if opinfo.tid == idaapi.BADADDR:
		return False
	w = ida_enum.get_enum_width(opinfo.tid)
	if w == 1:
		flag = ida_bytes.FF_BYTE
	elif w == 2:
		flag = ida_bytes.FF_WORD
	elif w == 8:
		flag = ida_bytes.FF_QWORD
	else:
		flag = ida_bytes.FF_DWORD # default
	return ida_struct.add_struc_member(s, name, offset, ida_bytes.FF_DATA | flag | ida_bytes.FF_0ENUM | ida_bytes.FF_1ENUM, opinfo, w * arraySize) == 0

# create structure member that is an instance of a different structure; returns success
def add_struct_member_substruct(s, offset, name, type, arraySize = 1):
	opinfo = ida_nalt.opinfo_t()
	opinfo.tid = ida_struct.get_struc_id(type)
	size = ida_struct.get_struc_size(opinfo.tid) if opinfo.tid != idaapi.BADADDR else 0
	if size == 0: # note: adding 0-sized struct field leads to problems
		return False
	return ida_struct.add_struc_member(s, name, offset, ida_bytes.FF_DATA | ida_bytes.FF_STRUCT, opinfo, size * arraySize) == 0

# create base class field for a structure
def add_struct_baseclass(s, type):
	offset = ida_struct.get_struc_size(s)
	success = add_struct_member_substruct(s, offset, f'baseclass_{hex(offset)[2:]}', type)
	if success:
		ida_struct.get_member(s, offset).props |= ida_struct.MF_BASECLASS
		# TODO: we might need to call save_struc here...
	return success

# create structure member of custom type
def add_struct_member_typed(s, offset, name, type):
	return add_struct_member_byte(s, offset, name) and set_struct_member_by_offset_type(s, offset, type)

def get_struct_member_tinfo(m):
	tif = ida_typeinf.tinfo_t()
	return tif if ida_struct.get_member_tinfo(tif, m) else None

# set structure member type info
def set_struct_member_tinfo(s, m, tif):
	# note: SET_MEMTI_* flags
	return ida_struct.set_member_tinfo(s, m, 0, tif, 0) > 0

# set structure member type from string
def set_struct_member_type(s, m, type):
	tif = parse_cdecl(type)
	return set_struct_member_tinfo(s, m, tif) if tif else False

# set structure member type
def set_struct_member_by_offset_type(s, offset, type):
	m = ida_struct.get_member(s, offset)
	return set_struct_member_type(s, m, type) if m else False

# add comment; if one already exists, append as new line (unless existing comment already contains what we're trying to add)
def add_comment_enum(id, comment, repeatable = False):
	existing = ida_enum.get_enum_cmt(id, repeatable)
	if not existing or comment not in existing:
		ida_enum.set_enum_cmt(id, f'{existing}\n{comment}' if existing else comment, repeatable)

def add_comment_func(func, comment, repeatable = False):
	existing = ida_funcs.get_func_cmt(func, repeatable)
	if not existing or comment not in existing:
		ida_funcs.set_func_cmt(func, f'{existing}\n{comment}' if existing else comment, repeatable)

def add_comment_inline(ea, comment, repeatable = False):
	existing = ida_bytes.get_cmt(ea, repeatable)
	if not existing or comment not in existing:
		ida_bytes.set_cmt(ea, f'{existing}\n{comment}' if existing else comment, repeatable)

def add_comment_outline(ea, comment, posterior = False):
	line = ida_lines.E_NEXT if posterior else ida_lines.E_PREV
	while True:
		existing = ida_lines.get_extra_cmt(ea, line)
		if not existing:
			ida_lines.add_extra_cmt(ea, not posterior, comment)
			return
		elif comment in existing:
			return
		else:
			line += 1

# func or outline
def add_comment_ea_auto(ea, comment):
	func = ida_funcs.get_func(ea)
	if func:
		add_comment_func(func, comment)
	else:
		add_comment_outline(ea, comment)
