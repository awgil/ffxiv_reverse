import idaapi
import ida_ida
import ida_bytes
import ida_search

packet_names = {
	2: 'Ping', # note: could be +1
	3: 'Init', # note: could be +1
	8: 'Logout', # note: could be +1
	11: 'CFCancel', # note: could be +1
	13: 'CFDutyInfo', # note: could be +1
	14: 'CFNotify', # note: could be +1
	18: 'CFPreferredRole', # note: could be +1
	26: 'PartyFinderListing', # note: index packet 19 ~ 48 are UI related
	81: 'CrossWorldLinkshellList', # note: could be +1
	89: 'FellowshipList', # note: could be +1
	111: 'Playtime', # note: could be +1
	112: 'CFRegistered', # note: could be +1
	115: 'Chat', # note: could be +1
	122: 'RSVData',
	123: 'RSFData',
	124: 'SocialMessage',
	125: 'SocialMessage2',
	127: 'SocialList',
	128: 'SocialRequestResponse',
	129: 'ExamineSearchInfo',
	130: 'UpdateSearchInfo',
	131: 'InitSearchInfo',
	132: 'ExamineSearchComment',
	135: 'ServerNoticeShort',
	136: 'ServerNotice',
	137: 'SetOnlineStatus',
	138: 'LogMessage',
	142: 'Countdown',
	143: 'CountdownCancel',
	148: 'PartyMessage',
	150: 'PlayerAddedToBlacklist',
	151: 'PlayerRemovedFromBlacklist',
	152: 'BlackList',
	159: 'LinkshellList',
	159: 'MailDeleteRequest',
	164: 'MarketBoardItemListingCount',
	165: 'MarketBoardItemListing',
	167: 'MarketBoardPurchase',
	169: 'MarketBoardItemListingHistory',
	170: 'RetainerSaleHistory',
	172: 'MarketBoardSearchResult',
	174: 'FreeCompanyInfo',
	176: 'ExamineFreeCompanyInfo',
	177: 'FreeCompanyDialog',
	202: 'StatusEffectList',
	203: 'StatusEffectListEureka',
	204: 'StatusEffectListBozja',
	205: 'StatusEffectListDouble',
	207: 'EffectResult1',
	208: 'EffectResult4',
	209: 'EffectResult8',
	210: 'EffectResult16',
	212: 'EffectResultBasic1',
	213: 'EffectResultBasic4',
	214: 'EffectResultBasic8',
	215: 'EffectResultBasic16',
	216: 'EffectResultBasic32',
	217: 'EffectResultBasic64',
	218: 'ActorControl',
	219: 'ActorControlSelf',
	220: 'ActorControlTarget',
	221: 'UpdateHpMpTp',
	222: 'ActionEffect1',
	225: 'ActionEffect8',
	226: 'ActionEffect16',
	227: 'ActionEffect24',
	228: 'ActionEffect32',
	231: 'StatusEffectListPlayer',
	233: 'UpdateRecastTimes',
	235: 'UpdateAllianceNormal',
	236: 'UpdateAllianceSmall',
	237: 'UpdatePartyMemberPositions',
	238: 'UpdateAllianceNormalMemberPositions',
	239: 'UpdateAllianceSmallMemberPositions',
	241: 'GCAffiliation',
	260: 'SpawnPlayer',
	261: 'SpawnNPC',
	262: 'SpawnBoss',
	263: 'DespawnCharacter',
	264: 'ActorMove',
	266: 'Transfer',
	267: 'ActorSetPos',
	269: 'ActorCast',
	270: 'PlayerUpdateLook',
	271: 'UpdateParty',
	272: 'InitZone',
	273: 'ApplyIDScramble',
	274: 'UpdateHate',
	275: 'UpdateHater',
	276: 'SpawnObject',
	277: 'DespawnObject',
	278: 'UpdateClassInfo',
	279: 'UpdateClassInfoEureka',
	280: 'UpdateClassInfoBozja',
	281: 'PlayerSetup',
	282: 'PlayerStats',
	283: 'FirstAttack',
	284: 'PlayerStateFlags',
	285: 'PlayerClassInfo',
	287: 'ModelEquip',
	288: 'Examine',
	291: 'CharaNameReq',
	295: 'RetainerInformation',
	297: 'ItemMarketBoardInfo',
	299: 'ItemInfo',
	300: 'ContainerInfo',
	301: 'InventoryTransactionFinish',
	302: 'InventoryTransaction',
	303: 'CurrencyCrystalInfo',
	305: 'InventoryActionAck',
	306: 'UpdateInventorySlot',
	308: 'OpenTreasure',
	311: 'LootMessage',
	315: 'CreateTreasure',
	316: 'TreasureFadeOut',
	317: 'HuntingLogEntry',
	319: 'EventPlay',
	320: 'EventPlay4',
	321: 'EventPlay8',
	322: 'EventPlay16',
	323: 'EventPlay32',
	324: 'EventPlay64',
	325: 'EventPlay128',
	326: 'EventPlay255',
	328: 'EventStart',
	329: 'EventFinish',
	340: 'EventContinue',
	342: 'ResultDialog',
	343: 'DesynthResult',
	348: 'QuestActiveList',
	349: 'QuestUpdate',
	350: 'QuestCompleteList',
	351: 'QuestFinish',
	354: 'MSQTrackerComplete',
	366: 'QuestTracker',
	387: 'Mount',
	389: 'DirectorVars',
	390: 'ContentDirectorSync',
	392: 'EnvControl',
	398: 'SystemLogMessage1',
	399: 'SystemLogMessage2',
	400: 'SystemLogMessage4',
	401: 'SystemLogMessage8',
	402: 'SystemLogMessage16',
	404: 'BattleTalk2',
	405: 'BattleTalk4',
	406: 'BattleTalk8',
	408: 'MapUpdate',
	409: 'MapUpdate4',
	410: 'MapUpdate8',
	411: 'MapUpdate16',
	412: 'MapUpdate32',
	413: 'MapUpdate64',
	414: 'MapUpdate128',
	416: 'BalloonTalk2',
	417: 'BalloonTalk4',
	418: 'BalloonTalk8',
	420: 'WeatherChange',
	421: 'PlayerTitleList',
	422: 'Discovery',
	424: 'EorzeaTimeOffset',
	437: 'EquipDisplayFlags',
	438: 'NpcYell',
	443: 'FateInfo',
	457: 'LandSetInitialize',
	458: 'LandUpdate',
	459: 'YardObjectSpawn',
	460: 'HousingIndoorInitialize',
	461: 'LandAvailability',
	463: 'LandPriceUpdate',
	464: 'LandInfoSign',
	465: 'LandRename',
	466: 'HousingEstateGreeting',
	467: 'HousingUpdateLandFlagsSlot',
	468: 'HousingLandFlags',
	469: 'HousingShowEstateGuestAccess',
	471: 'HousingObjectInitialize',
	472: 'HousingInternalObjectSpawn',
	474: 'HousingWardInfo',
	475: 'HousingObjectMove',
	476: 'HousingObjectDye',
	488: 'SharedEstateSettingsResponse',
	500: 'DailyQuests',
	502: 'DailyQuestRepeatFlags',
	504: 'LandUpdateHouseName',
	515: 'AirshipTimers',
	518: 'PlaceMarker',
	519: 'WaymarkPreset',
	520: 'Waymark',
	523: 'UnMount', # note: could be up to -2
	526: 'CeremonySetActorAppearance', # note: could be up to -2
	532: 'AirshipStatusList', # note: could be up to -2
	533: 'AirshipStatus', # note: could be up to -2
	534: 'AirshipExplorationResult', # note: could be up to -2
	535: 'SubmarineStatusList', # note: could be up to -2
	536: 'SubmarineProgressionStatus', # note: could be up to -2
	537: 'SubmarineExplorationResult', # note: could be up to -2
	539: 'SubmarineTimers', # note: could be up to -2
	569: 'PrepareZoning', # note: could be up to -1
	570: 'ActorGauge',
	571: 'CharaVisualEffect',
	572: 'LandSetMap',
	573: 'Fall',
	622: 'PlayMotionSync',
	631: 'CEDirector',
	653: 'IslandWorkshopSupplyDemand',
}

def find_next_func_by_sig(ea, pattern):
	return ida_search.find_binary(ea, ida_ida.inf_get_max_ea(), pattern, 16, ida_search.SEARCH_DOWN)

def find_single_func_by_sig(pattern):
	ea_first = find_next_func_by_sig(ida_ida.inf_get_min_ea(), pattern)
	if ea_first == idaapi.BADADDR:
		print(f'Could not find function by pattern {pattern}')
		return 0
	if find_next_func_by_sig(ea_first + 1, pattern) != idaapi.BADADDR:
		print(f'Multiple functions match pattern {pattern}')
		return 0
	return ea_first

def read_signed_byte(ea):
	v = ida_bytes.get_byte(ea)
	return v - 0x100 if v & 0x80 else v

def read_signed_dword(ea):
	v = ida_bytes.get_dword(ea)
	return v - 0x100000000 if v & 0x80000000 else v

def read_rva(ea):
	return ea + 4 + read_signed_dword(ea)

def get_vfoff_for_body(body):
	# assume each case has the following body:
	# mov rax, [rcx]
	# lea r9, [r10+10h]
	# jmp qword ptr [rax+<vfoff>]
	if ida_bytes.get_byte(body) != 0x48 or ida_bytes.get_byte(body + 1) != 0x8B or ida_bytes.get_byte(body + 2) != 0x01:
		return -1
	if ida_bytes.get_byte(body + 3) != 0x4D or ida_bytes.get_byte(body + 4) != 0x8D or ida_bytes.get_byte(body + 5) != 0x4A or ida_bytes.get_byte(body + 6) != 0x10:
		return -1
	if ida_bytes.get_byte(body + 7) != 0x48 or ida_bytes.get_byte(body + 8) != 0xFF:
		return -1
	sz = ida_bytes.get_byte(body + 9)
	if sz == 0x60:
		return read_signed_byte(body + 10)
	elif sz == 0xA0:
		return read_signed_dword(body + 10)
	else:
		return -1

def vfoff_to_index(vfoff):
	if vfoff < 0x10:
		return -1 # first two vfs are dtor and exec
	if (vfoff & 7) != 0:
		return -1 # vf contains qwords
	return (vfoff >> 3) - 2

class ffnetwork(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = 'Build opcode map'
	help = ''
	wanted_name = 'ffnetwork'
	wanted_hotkey = ''

	_unknown_in_output = False

	def init(self):
		return idaapi.PLUGIN_OK

	def run(self, arg=None):
		# assume func starts with:
		# mov rax, [r8+10h]
		# mov r10, [rax+38h]
		# movzx eax, word ptr [r10+2]
		# add eax, -<min_case>
		# cmp eax, <max_case-min_case>
		# ja <default_off>
		# lea r11, <__ImageBase_off>
		# cdqe
		# mov r9d, ds::<jumptable_rva>[r11+rax*4]
		func = find_single_func_by_sig('49 8B 40 10  4C 8B 50 38  41 0F B7 42 02  83 C0 ??  3D ?? ?? ?? ??  0F 87 ?? ?? ?? ??  4C 8D 1D ?? ?? ?? ??  48 98  45 8B 8C 83 ?? ?? ?? ??')
		if func == 0:
			return
		min_case = -read_signed_byte(func + 15) # this is a negative
		jumptable_size = read_signed_dword(func + 17) + 1
		def_addr = read_rva(func + 23)
		imagebase = read_rva(func + 30)
		jumptable = imagebase + read_signed_dword(func + 40)
		opcodemap = {}
		for i in range(jumptable_size):
			body = imagebase + read_signed_dword(jumptable + 4 * i)
			if body == def_addr:
				continue
			case = i + min_case
			voff = get_vfoff_for_body(body)
			index = vfoff_to_index(voff)
			if index < 0:
				print(f'Unexpected body for case {case}')
				continue
			if index in opcodemap:
				print(f'Multiple opcodes map to single operation {index}: {hex(opcodemap[index])} and {hex(case)}')
				continue
			opcodemap[index] = case
		for k, v in sorted(opcodemap.items()):
			if k in packet_names:
				print(f'{packet_names[k]} = 0x{v:0{4}X},')
			elif self._unknown_in_output:
				print(f'Packet{k} = 0x{v:0{4}X},')

	def term(self):
		pass

def PLUGIN_ENTRY():
	return ffnetwork()

