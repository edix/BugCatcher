#include <Windows.h>

struct my_info
{
	char szInformationText[64];
	DWORD dwInfo;
	DWORD dwInfo2;
	DWORD dwInfo3;
	DWORD dwInfo4;
};

my_info* __stdcall GenerateSomethingStupid(int nNum)
{
	my_info* tmp = new my_info;
	if (nNum <= 100)
	{
		tmp->dwInfo = 1 * nNum;
		tmp->dwInfo2 = 1;
		tmp->dwInfo3 = 2;
		tmp->dwInfo4 = 3;
		lstrcpyA(tmp->szInformationText, "ok");
	}
	else
	{
		delete tmp;
		tmp = nullptr;
	}
	return tmp;
}


int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPev, LPSTR lpCmdLine, int nShowCmd)
{
	my_info* pinfo;
	//for (int x = 0; x < 2; x++)
	//{
	//	pinfo = GenerateSomethingStupid(x);
	//	char szTemp[100];
	//	wsprintfA(szTemp, "info: %u, info2: %u, text: %s\n", pinfo->dwInfo, pinfo->dwInfo2, pinfo->szInformationText);
	//	MessageBoxA(0, szTemp, "information", 0);
	//}

	const char* szTitle = "info";
	__asm
	{
		push 101
		call GenerateSomethingStupid
		push 0
		push dword ptr [szTitle]
		push eax
		push 0
		call MessageBoxA

	}

	return 0;
}