import idaapi
import ida_kernwin
import ida_struct
import ida_funcs
import ida_name
from PyQt5 import QtCore, QtGui, QtWidgets

def functions():
	start_ea = 0
	while True:
		nextfn = ida_funcs.get_next_func(start_ea)
		if not nextfn:
			break
		start_ea = nextfn.start_ea
		yield start_ea

def names():
	for i in range(ida_name.get_nlist_size()):
		yield (ida_name.get_nlist_ea(i), ida_name.get_nlist_name(i))

class dialog(QtWidgets.QDialog):
	_layout = None

	def __init__(self, name):
		QtWidgets.QDialog.__init__(self)
		self.setWindowTitle(name)
		self._layout = QtWidgets.QVBoxLayout()
		self.setLayout(self._layout)

	def add_widget(self, widget):
		self._layout.addWidget(widget)
		return widget

	def add_layout(self, layout):
		self._layout.addLayout(layout)
		return layout

	def add_buttons(self, ok_name = 'OK'):
		buttons = self.add_layout(QtWidgets.QHBoxLayout())
		ok = QtWidgets.QPushButton(ok_name)
		ok.setDefault(True)
		ok.clicked.connect(self.accept)
		buttons.addWidget(ok)
		cancel = QtWidgets.QPushButton('Cancel')
		cancel.clicked.connect(self.reject)
		buttons.addWidget(cancel)

	def run(self, ok_name = 'OK'):
		self.add_buttons(ok_name)
		return self.exec()

class smart_rename(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		highlight = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
		struct = ida_struct.get_struc_id(highlight[0]) if highlight else idaapi.BADADDR
		if struct == idaapi.BADADDR:
			print('Select a structure to rename')
			return 0

		original_name = ida_struct.get_struc_name(struct)
		related_names = self._related_names(original_name)

		dlg = dialog('Rename class and members')
		dlg_rename = dlg.add_widget(QtWidgets.QLineEdit(original_name))

		dlg_items = dlg.add_widget(QtWidgets.QListWidget())
		dlg_items_list = []
		for ea, name in related_names:
			item = QtWidgets.QListWidgetItem(name, dlg_items)
			item.setData(QtCore.Qt.UserRole, ea)
			item.setCheckState(QtCore.Qt.Checked)
			dlg_items_list.append(item)

		if dlg.run('Rename') == 0:
			return 0

		new_name = dlg_rename.text()
		if new_name == original_name:
			print('Name is not changed, nothing to do...')
			return 0

		print(f'Renaming struct {original_name} to {new_name}')
		ida_struct.set_struc_name(struct, new_name)
		for item in dlg_items_list:
			if item.checkState() == QtCore.Qt.Checked:
				ea = item.data(QtCore.Qt.UserRole)
				rel_ori_name = item.text()
				rel_new_name = rel_ori_name.replace(original_name, new_name)
				print(f'Renaming related {rel_ori_name} to {rel_new_name}')
				ida_name.set_name(ea, rel_new_name)
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

	def _related_names(self, struct_name):
		return [(ea, name) for ea, name in names() if self._is_related_name(name, struct_name)]

	def _is_related_name(self, name, struct_name):
		adj_name = name[5:] if name.startswith('vtbl_') else name
		pos = adj_name.find(struct_name)
		if pos < 0:
			return False
		if pos > 0 and adj_name[pos-1] != ':' and adj_name[pos-1] != '.':
			return False
		pos += len(struct_name)
		if pos > len(adj_name):
			return False
		return pos == len(adj_name) or adj_name[pos] == ':' or adj_name[pos] == '.'

class vtable_sync(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		ea = ida_kernwin.get_screen_ea()
		name = ida_name.get_name(ea)
		if not name.startswith('vtbl_'):
			print('Place cursor at the beginning of a virtual table and make sure it is called vtbl_ClassName')
			return 0

		name = name[5:]
		vt_struct = ida_struct.get_struc_id(name + '_vtbl')
		if vt_struct != idaapi.BADADDR:
			return self._sync_vtable(ea, name, vt_struct)
		else:
			return self._create_vtable(ea, name)

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

	def _sync_vtable(self, ea, classname, vtstruct):
		print('todo')
		return 0

	def _create_vtable(self, ea, classname):
		next_ea = min([addr for addr, name in names() if addr > ea])
		size = int((next_ea - ea) / 8)

		dlg = dialog(f'Create vtable for {classname}')
		
		if dlg.run('Create') == 0:
			return 0

		print(f'creating: max {size} entries')
		return 0

class ffutil(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = 'A bunch of utilities to simplify reversing FF14'
	help = ''
	wanted_name = 'ffutil'
	wanted_hotkey = 'Ctrl+Alt+M'

	def init(self):
		print('ffutil init')
		self._register_action('smart_rename', 'Rename class and all methods', smart_rename(), 'Ctrl+Shift+N')
		self._register_action('vtable_sync', 'Sync vtable definitions and signatures', vtable_sync(), 'Ctrl+Shift+V')
		return idaapi.PLUGIN_KEEP

	def run(self, arg=None):
		print('ffutil run')

	def term(self):
		print('ffutil term')

	def _register_action(self, name, label, handler, shortcut):
		deco_name = 'ffutil:' + name
		idaapi.unregister_action(deco_name)
		idaapi.register_action(idaapi.action_desc_t(deco_name, label, handler, shortcut))

def PLUGIN_ENTRY():
	return ffutil()
