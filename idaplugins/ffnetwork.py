import idaapi
import ida_ida
import ida_bytes
import ida_search

packet_names = {
	2: 'Ping',
	3: 'Init',
	8: 'Logout',
	11: 'CFCancel',
	13: 'CFDutyInfo',
	14: 'CFNotify',
	18: 'CFPreferredRole',
	81: 'CrossWorldLinkshellList',
	89: 'FellowshipList',
	111: 'Playtime',
	112: 'CFRegistered',
	115: 'Chat',
	121: 'RSVData',
	122: 'RSFData',
	123: 'SocialMessage',
	124: 'SocialMessage2',
	126: 'SocialList',
	127: 'SocialRequestResponse',
	128: 'ExamineSearchInfo',
	129: 'UpdateSearchInfo',
	130: 'InitSearchInfo',
	131: 'ExamineSearchComment',
	134: 'ServerNoticeShort',
	135: 'ServerNotice',
	136: 'SetOnlineStatus',
	137: 'LogMessage',
	141: 'Countdown',
	142: 'CountdownCancel',
	147: 'PartyMessage',
	149: 'PlayerAddedToBlacklist',
	150: 'PlayerRemovedFromBlacklist',
	151: 'BlackList',
	158: 'LinkshellList',
	158: 'MailDeleteRequest',
	163: 'MarketBoardItemListingCount',
	164: 'MarketBoardItemListing',
	166: 'MarketBoardPurchase',
	168: 'MarketBoardItemListingHistory',
	169: 'RetainerSaleHistory',
	171: 'MarketBoardSearchResult',
	173: 'FreeCompanyInfo',
	175: 'ExamineFreeCompanyInfo',
	176: 'FreeCompanyDialog',
	201: 'StatusEffectList',
	202: 'StatusEffectListEureka',
	203: 'StatusEffectListBozja',
	204: 'StatusEffectListDouble',
	206: 'EffectResult1',
	207: 'EffectResult4',
	208: 'EffectResult8',
	209: 'EffectResult16',
	211: 'EffectResultBasic1',
	212: 'EffectResultBasic4',
	213: 'EffectResultBasic8',
	214: 'EffectResultBasic16',
	215: 'EffectResultBasic32',
	216: 'EffectResultBasic64',
	217: 'ActorControl',
	218: 'ActorControlSelf',
	219: 'ActorControlTarget',
	220: 'UpdateHpMpTp',
	221: 'ActionEffect1',
	224: 'ActionEffect8',
	225: 'ActionEffect16',
	226: 'ActionEffect24',
	227: 'ActionEffect32',
	230: 'StatusEffectListPlayer',
	232: 'UpdateRecastTimes',
	234: 'UpdateAllianceNormal',
	235: 'UpdateAllianceSmall',
	236: 'UpdatePartyMemberPositions',
	237: 'UpdateAllianceNormalMemberPositions',
	238: 'UpdateAllianceSmallMemberPositions',
	240: 'GCAffiliation',
	259: 'SpawnPlayer',
	260: 'SpawnNPC',
	261: 'SpawnBoss',
	262: 'DespawnCharacter',
	263: 'ActorMove',
	265: 'Transfer',
	266: 'ActorSetPos',
	268: 'ActorCast',
	269: 'PlayerUpdateLook',
	270: 'UpdateParty',
	271: 'InitZone',
	272: 'ApplyIDScramble',
	273: 'UpdateHate',
	274: 'UpdateHater',
	275: 'SpawnObject',
	276: 'DespawnObject',
	277: 'UpdateClassInfo',
	278: 'UpdateClassInfoEureka',
	279: 'UpdateClassInfoBozja',
	280: 'PlayerSetup',
	281: 'PlayerStats',
	282: 'FirstAttack',
	283: 'PlayerStateFlags',
	284: 'PlayerClassInfo',
	286: 'ModelEquip',
	287: 'Examine',
	290: 'CharaNameReq',
	294: 'RetainerInformation',
	296: 'ItemMarketBoardInfo',
	298: 'ItemInfo',
	299: 'ContainerInfo',
	300: 'InventoryTransactionFinish',
	301: 'InventoryTransaction',
	302: 'CurrencyCrystalInfo',
	304: 'InventoryActionAck',
	305: 'UpdateInventorySlot',
	307: 'OpenTreasure',
	310: 'LootMessage',
	314: 'CreateTreasure',
	315: 'TreasureFadeOut',
	316: 'HuntingLogEntry',
	318: 'EventPlay',
	319: 'EventPlay4',
	320: 'EventPlay8',
	321: 'EventPlay16',
	322: 'EventPlay32',
	323: 'EventPlay64',
	324: 'EventPlay128',
	325: 'EventPlay255',
	327: 'EventStart',
	328: 'EventFinish',
	339: 'EventContinue',
	341: 'ResultDialog',
	342: 'DesynthResult',
	347: 'QuestActiveList',
	348: 'QuestUpdate',
	349: 'QuestCompleteList',
	350: 'QuestFinish',
	353: 'MSQTrackerComplete',
	365: 'QuestTracker',
	386: 'Mount',
	388: 'DirectorVars',
	389: 'ContentDirectorSync',
	391: 'EnvControl',
	397: 'SystemLogMessage1',
	398: 'SystemLogMessage2',
	399: 'SystemLogMessage4',
	400: 'SystemLogMessage8',
	401: 'SystemLogMessage16',
	403: 'BattleTalk2',
	404: 'BattleTalk4',
	405: 'BattleTalk8',
	407: 'MapUpdate',
	408: 'MapUpdate4',
	409: 'MapUpdate8',
	410: 'MapUpdate16',
	411: 'MapUpdate32',
	412: 'MapUpdate64',
	413: 'MapUpdate128',
	415: 'BalloonTalk2',
	416: 'BalloonTalk4',
	417: 'BalloonTalk8',
	419: 'WeatherChange',
	420: 'PlayerTitleList',
	421: 'Discovery',
	423: 'EorzeaTimeOffset',
	436: 'EquipDisplayFlags',
	437: 'NpcYell',
	442: 'FateInfo',
	456: 'LandSetInitialize',
	457: 'LandUpdate',
	458: 'YardObjectSpawn',
	459: 'HousingIndoorInitialize',
	460: 'LandAvailability',
	462: 'LandPriceUpdate',
	463: 'LandInfoSign',
	464: 'LandRename',
	465: 'HousingEstateGreeting',
	466: 'HousingUpdateLandFlagsSlot',
	467: 'HousingLandFlags',
	468: 'HousingShowEstateGuestAccess',
	470: 'HousingObjectInitialize',
	471: 'HousingInternalObjectSpawn',
	473: 'HousingWardInfo',
	474: 'HousingObjectMove',
	475: 'HousingObjectDye',
	487: 'SharedEstateSettingsResponse',
	499: 'DailyQuests',
	501: 'DailyQuestRepeatFlags',
	503: 'LandUpdateHouseName',
	514: 'AirshipTimers',
	517: 'PlaceMarker',
	518: 'WaymarkPreset',
	519: 'Waymark',
	522: 'UnMount',
	525: 'CeremonySetActorAppearance',
	531: 'AirshipStatusList',
	532: 'AirshipStatus',
	533: 'AirshipExplorationResult',
	534: 'SubmarineStatusList',
	535: 'SubmarineProgressionStatus',
	536: 'SubmarineExplorationResult',
	538: 'SubmarineTimers',
	570: 'PrepareZoning',
	571: 'ActorGauge',
	572: 'CharaVisualEffect',
	573: 'LandSetMap',
	574: 'Fall',
	623: 'PlayMotionSync',
	632: 'CEDirector',
	654: 'IslandWorkshopSupplyDemand',
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
			name = packet_names[k] if k in packet_names else f'Packet{k}'
			print(f'{name} = {hex(v)}')

	def term(self):
		pass

def PLUGIN_ENTRY():
	return ffnetwork()

