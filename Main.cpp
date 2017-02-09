#include <Windows.h>
#include <iostream>
using namespace std;

typedef int (WINAPI *tMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
tMessageBoxW Original_MessageBoxW;

static int WINAPI Hook_MessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	__asm pushad

	LPCWSTR lpcwMsg = L"Hooked";
	LPCWSTR lpcwTitle = L"Hooked";
	Original_MessageBoxW(NULL, lpcwMsg, lpcwTitle, MB_OK);
	__asm popad

	return Original_MessageBoxW(hWnd, lpText, lpCaption, uType);
}

int main()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL); // Grab our base address
	if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
	{
		cout << "[+] Found DOS Signature" << endl;

		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(DWORD(pDos) /*Base address*/ + DWORD(pDos->e_lfanew) /*RVA*/);
		if (pNt->Signature == IMAGE_NT_SIGNATURE)
		{
			cout << "[+] Found NT Signature" << endl;
			if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
			{
				cout << "[+] Parsing Import Address Table..." << endl;

				PIMAGE_IMPORT_DESCRIPTOR pImpDes = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(DWORD(pDos) + DWORD(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
				LPCSTR lpcszDllName;
				while (pImpDes->Name != NULL)
				{
					lpcszDllName = LPCSTR(DWORD(pDos) + pImpDes->Name);

					if(!strcmp("USER32.dll", lpcszDllName))
					{
						cout << "[+] Found Dll File" << endl;

						PIMAGE_THUNK_DATA pOrdThuk = (PIMAGE_THUNK_DATA)(DWORD(pDos) + pImpDes->OriginalFirstThunk);
						PIMAGE_THUNK_DATA pThuk = (PIMAGE_THUNK_DATA)(DWORD(pDos) + pImpDes->FirstThunk);
						PIMAGE_IMPORT_BY_NAME pOrdImpByName;

						while (pOrdThuk->u1.AddressOfData != NULL)
						{
							pOrdImpByName = (PIMAGE_IMPORT_BY_NAME)(DWORD(pDos) + pOrdThuk->u1.AddressOfData);

							cout << (LPCSTR)pOrdImpByName->Name << endl;

							if (!strcmp("MessageBoxW",  (LPCSTR)pOrdImpByName->Name))
							{
								cout << "[+] Found Hookee Address" << endl;

								cout << "Before Hook - API Name: " << pOrdImpByName->Name << " Original Address: " << hex << pThuk->u1.Function << " Hook Address: " << hex << Hook_MessageBox << endl;
								
								// Save old address for trampoline
								cout << "[+] Setting up trampoline" << endl;
								Original_MessageBoxW = (tMessageBoxW)pThuk->u1.Function;
								cout << "Original: " << Original_MessageBoxW << endl;

								DWORD dwOldProt;

								if(!VirtualProtect(reinterpret_cast<LPVOID>(&pThuk->u1.Function), sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProt))
									cout << "Error" << endl;

								pThuk->u1.Function = (DWORD)Hook_MessageBox;

								if(!VirtualProtect(reinterpret_cast<LPVOID>(&pThuk->u1.Function), sizeof(DWORD), dwOldProt, &dwOldProt))
									cout << "Error" << endl;

								FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPVOID>(pThuk->u1.Function), sizeof(DWORD));
								cout << "After Hook - API Name: " << pOrdImpByName->Name << " Original Address: " << hex << pThuk->u1.Function << " Hook Address: " << hex << Hook_MessageBox << endl;
							}
							pThuk++;
							pOrdThuk++;
						}
					}
					pImpDes++;
				};
				
			}
			else
				cout << "[-] File does not contain any import addresses" << endl;
		}
		else
			cout << "[-] Invalid NT Signature" << endl;
	}
	else
		cout << "[-] Invalid DOS Signature" << endl;

	MessageBoxW(NULL, L"Done!", L"Done", MB_OK);

	cin.ignore();
	return 0;
}