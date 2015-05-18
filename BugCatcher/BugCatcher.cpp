//
//
// IDA Pro Auto Detect Bugs Plugin
// Suche alle Funktionen.
// Für jede Funktion hole die XREFs.
// Überprüfe die Funktion ob sie folgendes(Beispiel) macht:
//	xor eax, eax
//	retn
//
//	Danach überprüfe ob direkt nach dem Funktionsaufruf folgender Befehl vorkommt :
//		mov x, [eax + 0x04] oder sonstiges
//	Falls ja, dann ist das ein Bug!
// 
//
// ida pro reference: http://www.openrce.org/reference_library/ida_sdk
// 
//


#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <typeinf.hpp>
#include <funcs.hpp>

#include <algorithm>

int idaapi init(void)
{
	if (ph.id != PLFM_386)
	{
		return PLUGIN_SKIP;
	}

	return PLUGIN_OK;
}

std::string GetFunctionName(ea_t ea)
{
	qstring funcName;
	get_func_name2(&funcName, ea);

	return funcName.c_str();
}

bool Disasm(ea_t address, qstring& res)
{
	char szLine[64] = { 0 };

	//
	// search for:
	// xor eax, eax
	// ret
	//
	// get the disassembly and remove the color tags
	//
	res = "";

	if (generate_disasm_line(address, szLine, sizeof(szLine)-1, GENDSM_MULTI_LINE))
	{
		tag_remove(szLine, szLine, sizeof(szLine)-1);
		res.cat_sprnt("%s - %x",  szLine, address);
		//res = szLine;
		return true;
	}

	return false;
}

ea_t getJumpAddress(ea_t address)
{
	unsigned char buf1[8] = { 0 };
	ea_t res = BADADDR;
	if (get_many_bytes(address, buf1, sizeof(buf1)))
	{
		if (buf1[0] == 0xEB)
		{
			// jmp short
			res = (address + (unsigned)buf1[1]);
		}
		else if (buf1[0] == 0xE9 )
		{
			// jmp <dword>
			res = (address + *(uint32*)&buf1[1]);
		}
		else if (buf1[0] == 0xFF)
		{
			//
			// oh god multi byte opcodes..support only call ds:uint32
			//
			if (buf1[1] == 0x25)
			{
				res = (*(uint32*)&buf1[1]);
			}

		}
		else
		{
			msg("unknown: %u\n", buf1[0]);
		}
	}
	return res;
}

bool findCommand(qstring &str, const char* szStr1)
{
	if (strstr(str.c_str(), szStr1) > 0)
		return true;
	return false;
}

bool findCommand(qstring &str, const char* szStr1, const char* szStr2)
{
	if (strstr(str.c_str(), szStr1) > 0 && strstr(str.c_str(), szStr2) > 0)
		return true;
	return false;
}

bool findXorEaxRetn(ea_t address, ea_t endaddress, qstring &disasm)
{
	//
	// search for:
	// xor eax, eax
	// ret
	//
	// get the disassembly and remove the color tags
	//
	bool fResult = false;
	ea_t address2;
	qstring disasm2;

	disasm = "";

	unsigned char buf1[8] = { 0 };
	unsigned char buf2[8] = { 0 };

	int nInstructions = 0;

	while (address != BADADDR && address < endaddress && !fResult)
	{
		if (get_many_bytes(address, buf1, sizeof(buf1)))
		{
			// xor eax, eax = 0x33 0xC0
			if (buf1[0] == 0x33 && buf1[1] == 0xC0)
			{
				Disasm(address, disasm);

				address2 = get_item_end(address);

				//
				// search in next 5 instructions for a RET
				//
				nInstructions = 0;
				while ((address2 != BADADDR && address2 != address) && nInstructions < 5 && !fResult)
				{
					Disasm(address2, disasm2);
					disasm += "\n";
					disasm += disasm2;

					if (get_many_bytes(address2, buf2, sizeof(buf2)))
					{
						//
						// find mov eax, 0 and ignore this one because this manipulates our eax
						//
						if (findCommand(disasm2, "pop", "eax") ||
							findCommand(disasm2, "lea", "eax,") ||
							findCommand(disasm2, "mov", "eax,") ||
							findCommand(disasm2, "xor", "eax,") ||
							findCommand(disasm2, "test", "eax") ||
							findCommand(disasm2, "call"))
						{
							break;
						}


						if (buf2[0] == 0xC3 || buf2[0] == 0xC2)
						{
							//msg("found: %a: \n%s", address, disasm);
							fResult = true;
							break;
						}
					}
					nInstructions++;
					address2 = get_item_end(address2);
				}
			}
		} 
		address = get_item_end(address);

	}

	return fResult;
}

void idaapi run(int)
{
	if (!autoIsOk() && askyn_c(ASKBTN_CANCEL, "HIDECANCEL\nThe autoanalysis has not finished yet.\nThe result might be incomplete. Do you want to continue?") < ASKBTN_NO)
	{
		return;
	}

	msg("bug checker started.\n");

	func_t* pFunction = nullptr;
	std::string FunctionName;

	for (size_t n = 0; n < get_func_qty(); n++)
	{
		pFunction = getn_func(n);
		if (pFunction == nullptr || !pFunction->does_return())
			continue;

		FunctionName = GetFunctionName(pFunction->startEA);
	
		//
		// get all references to the function
		// xref.from contains the address where we have pFunction referenced
		//

		xrefblk_t xref;
		int nCounter = 1;
		qstring disasm, disasm_xoreax;
		for (bool fOk = xref.first_to(pFunction->startEA, XREF_ALL); fOk; fOk = xref.next_to(), nCounter++)
		{
			//
			// get the disassembly and remove the color tags
			// then check if the reference is a call
			//
			Disasm(xref.from, disasm);

			if (strnicmp(disasm.c_str(), "call ", 5) == 0)
			{

				func_t* pCall = get_func(xref.from);
				if (pCall != nullptr)
				{
					//msg("found call: %u, %a - %a: %s\n", nCounter, xref.from, pCall->startEA, disasm.c_str());

					if (findXorEaxRetn(pCall->startEA, pCall->endEA, disasm_xoreax))
					{
						//msg("function: %s is returning with NULL ptr.\n", FunctionName.c_str());

						//
						// now try to to check next instruction of xref.from if it does something like:
						// mov x, [eax + 0x04]
						// 
						//
						ea_t newaddr = get_item_end(xref.from);

						int x = 0;

						while (x < 10)
						{
							if (!Disasm(newaddr, disasm))
								break;
							
							//
							// find mov eax, 0 and ignore this one because this manipulates our eax
							//
							if (findCommand(disasm, "pop", "eax") ||
								findCommand(disasm, "lea", "eax,") ||
								findCommand(disasm, "mov", "eax,") ||
								findCommand(disasm, "xor", "eax,") ||
								findCommand(disasm, "test", "eax") ||
								findCommand(disasm, "call"))
							{
								break;
							}

							if (findCommand(disasm, "jmp"))
							{
								//msg("following jump at %a\n", newaddr);

								//
								// follow the jump and reset the counter for search (uh uh, this is ugly)
								//
								ea_t jmpaddress = getJumpAddress(newaddr);
								if (jmpaddress != BADADDR)
								{
									newaddr = jmpaddress;
									x = 0;
									continue;
								}
								//
								// didnt worked, stop analyzing this function
								//
								break;
							}

							//
							// find some instructions which use eax
							// 
							if (findCommand(disasm, "[eax +") ||
								findCommand(disasm, "push", "eax"))
							{
								msg("* function: %s ( %a ) is returning with NULL ptr:\n%s\n", FunctionName.c_str(), pFunction->startEA, disasm_xoreax.c_str());
								msg("* eax usage at: %a\n\n", newaddr);
							
							}

							newaddr = get_item_end(newaddr);

							x++;
						}
					}
				}
			}
		}
	}

	msg("bug checker finished.\n");

}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_FIX,           // plugin flags
	init,                 // initialize
	NULL,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	"Trying to catch bugs in x86 applications",                 // long comment about the plugin
	"Trying to catch bugs in x86 applications",                 // multiline help about the plugin
	"Bug Catcher",        // the preferred short name of the plugin
	"ALT+F5"              // the preferred hotkey to run the plugin
};

