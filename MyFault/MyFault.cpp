// MyFault.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <conio.h>
#include "MyDriver.h"
#include "MyFault.h"

//============================== class CDriverDevice ==============================
CDriverDevice::CDriverDevice(WCHAR *wzSysName)
{
    m_hDevice = INVALID_HANDLE_VALUE;
    wmemset(m_wzSysName, 0, _countof(m_wzSysName));
    wcscpy_s(m_wzSysName, _countof(m_wzSysName), wzSysName);
}

CDriverDevice::~CDriverDevice()
{
}

DWORD CDriverDevice::SendCommand(MY_IOCTL_COMMAND &Command)
{
    DWORD dwReturn = ERROR_INVALID_FUNCTION;
    //Access specified driver device as FILE.
    //You have to treat it as a normal driver.
    //The only difference is : using DeviceIoControl() to replace ReadFile() / WriteFile()
    
    dwReturn = OpenDriverDevice(m_hDevice, m_wzSysName);
    if(ERROR_SUCCESS == dwReturn)
    {
        //NTSTATUS    status;
        DeviceIoControl(m_hDevice, 
                        Command.dwIoctlCode,
                        Command.pInBuffer, Command.dwInSize,
                        Command.pOutBuffer, Command.dwOutSize,
                        &Command.dwReturn, 
                        NULL);
        dwReturn = GetLastError();
        CloseDriverDevice(m_hDevice);
    }

    return dwReturn;
}

DWORD CDriverDevice::OpenDriverDevice(HANDLE &hDevice, WCHAR *wzSysName)
{
    WCHAR   wzDeviceFullName[MAX_PATH] = {0};

    //The device name format is "\\\\.\\Global\\%Name%"
    //example : \\\\.\\Global\\mydriver"
    wsprintf(wzDeviceFullName, DEVICE_FULLNAME_TEMPLATE, wzSysName);
    hDevice = CreateFile( wzDeviceFullName,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

    if(INVALID_HANDLE_VALUE == hDevice)
        return GetLastError();

    return ERROR_SUCCESS;
}

void CDriverDevice::CloseDriverDevice(HANDLE &hDevice)
{
    if(INVALID_HANDLE_VALUE != hDevice)
        CloseHandle(hDevice);
}

//=================================================================================

WCHAR   g_wzLogFile[MAX_PATH] = {0};

void PrintUsage()
{
    _tprintf(_T("Usage: MyFault.exe -act=<option>\n"));
    _tprintf(_T("Option:\n"));
    _tprintf(_T("  1   : Causing BlueScreen\n"));
    _tprintf(_T("  2   : Generate a log file in folder with MyFault.exe\n"));
    _tprintf(_T("  3   : enable filter driver debug log with MyFault.exe\n"));
    _tprintf(_T("  4   : disable filter driver debug log with MyFault.exe\n"));
      
    _tprintf(_T("Example: MyFault.exe -act=1 \n"));
    _tprintf(_T("Example: MyFault.exe -act=2 \n"));
    _tprintf(_T("Example: MyFault.exe -act=3 <LogFileName> \n"));
    _tprintf(_T("Example: MyFault.exe -act=4 \n"));
    _tprintf(_T("\n"));
}

BOOL ParseCommand(CMD_TYPE &nCmd, int argc, _TCHAR* argv[])
{
    BOOL bReturn = FALSE;
    size_t nArgLen = 0;
    _tprintf(_T("Parsing Command...\n"));

    if(argc < 2)
    {
        _tprintf(_T("Invalid argument: MyFault.exe should be invoked with 1 argument at least.\n\n"));
        return bReturn;
    }

    nArgLen = _tcslen(_T("-act="));
    if(0==_tcsnicmp(_T("-act="), argv[1], nArgLen))
    {
        TCHAR   szArg = argv[1][nArgLen];
        _tprintf(_T("Input Command = %c\n"), szArg);
        switch (szArg)
        {
        case _T('1'):
            nCmd = CMD_BSOD;
            _tprintf(_T("Input Command = 1, prepare to cause BlueScreen\n"));
            bReturn = TRUE;
            break;
        case _T('2'):
            nCmd = CMD_LOG;
            _tprintf(_T("Input Command = 2, prepare generate file\n"));
            _tcscat_s(g_wzLogFile, MAX_PATH, MY_LOG_FILENAME);
            bReturn = TRUE;
            break;
        case _T('3'):
            nCmd = CMD_ENABLE_DEBUG_LOG;
            _tprintf(_T("Input Command = 3, enable minifilter driver debug log\n"));

            if((argc==3) && (_tcslen(argv[2]) > 0))
                _tcscat_s(g_wzLogFile, MAX_PATH, argv[2]);
            else
                _tcscat_s(g_wzLogFile, MAX_PATH, MY_DEBUG_LOG_NAME);

            bReturn = TRUE;
            break;
        case _T('4'):
            nCmd = CMD_DISABLE_DEBUG_LOG;
            _tprintf(_T("Input Command = 4, disable minifilter driver debug log\n"));
            bReturn = TRUE;
            break;
        default:
            _tprintf(_T("Undefined Command.\n\n"));
            break;
        }
    }
    else
    {
        _tprintf(_T("Undefined Command.\n\n"));
    }    

    return bReturn;    
}

BOOL ExecuteCommand(CMD_TYPE nCmd)
{
    _tprintf(_T("Executing Command...\n"));
    CDriverDevice       device(MY_SYSNAME);
    DWORD               dwBugcheckCode = MY_BUGCHECK_CODE;
    MY_IOCTL_COMMAND    iocmd = {0};
    WCHAR wszOutputBuf[MAX_PATH] = {0};

    switch(nCmd)
    {
    case CMD_BSOD:
        _tprintf(_T("Command = CMD_BSOD, prepare to cause BlueScreen. BugCheckCode=0x%X\n"), MY_BUGCHECK_CODE);
        iocmd.dwIoctlCode = IOCTL_FUNC_BSOD;
        iocmd.pInBuffer = &dwBugcheckCode;
        iocmd.dwInSize = sizeof(dwBugcheckCode);
        break;

    case CMD_LOG:
        _tprintf(_T("Command = CMD_LOG, prepare generate file [%s] \n"), g_wzLogFile);
        iocmd.dwIoctlCode = IOCTL_FUNC_LOG_TEST;
        iocmd.pInBuffer = g_wzLogFile;
        iocmd.dwInSize = sizeof(g_wzLogFile);
        iocmd.pOutBuffer = wszOutputBuf;
        iocmd.dwOutSize = sizeof(wszOutputBuf);
        break;

    case CMD_ENABLE_DEBUG_LOG:
        _tprintf(_T("Command = CMD_ENABLE_DEBUG_LOG, enable minifilter driver debug log \n"));
        iocmd.dwIoctlCode = IOCTL_FUNC_LOG_ENABLE;
        iocmd.pInBuffer = g_wzLogFile;
        iocmd.dwInSize = sizeof(g_wzLogFile);
        break;

    case CMD_DISABLE_DEBUG_LOG:
        _tprintf(_T("Command = CMD_DISABLE_DEBUG_LOG, disable minifilter driver debug log \n"));
        iocmd.dwIoctlCode = IOCTL_FUNC_LOG_DISABLE;
        break;
    default:
        _tprintf(_T("Undefined Command. Aborting command execution.\n\n"));
        return FALSE;
    }

    DWORD   dwLastError = device.SendCommand(iocmd);
    if(ERROR_SUCCESS != dwLastError)
    {
        _tprintf(_T("IOCTL command execution failed! Error=%d\n\n"), dwLastError);
        return FALSE;
    }
    else if(nCmd == CMD_LOG)
    {
        _tprintf(_T("%s \n"), wszOutputBuf);
    }
    
    return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
    CMD_TYPE nCmd = CMD_UNKNOWN;
    TCHAR *szFind = NULL;

    GetModuleFileNameEx(GetCurrentProcess(), NULL, g_wzLogFile, MAX_PATH);
    //Prepare the log fullpath. It is used for Log Command.
    szFind = _tcsrchr(g_wzLogFile, _T('\\'));
    *(++szFind) = _T('\0');

    if(!ParseCommand(nCmd, argc, argv))
    {
        PrintUsage();
        return -1;
    }

    ExecuteCommand(nCmd);

	return 0;
}

