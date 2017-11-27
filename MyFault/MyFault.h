#ifndef         _MYFAULT_DEFINITIONS_H_
#define         _MYFAULT_DEFINITIONS_H_

#define     MY_LOG_FILENAME    _T("MyFault.log")
#define     MY_DEBUG_LOG_NAME  _T("MyFilter.log")
#define     MY_BUGCHECK_CODE   0x28825252
#define     DEVICE_FULLNAME_TEMPLATE    L"\\\\.\\Global\\%s"
//define share structure
enum CMD_TYPE{
    CMD_UNKNOWN = 0,
    CMD_BSOD,
    CMD_LOG,
    CMD_ENABLE_DEBUG_LOG,
    CMD_DISABLE_DEBUG_LOG,
    
    CMD_MAX = 0xFFFFFFFF
};

typedef struct _MY_IOCTL_COMMAND
{
    DWORD   dwIoctlCode;
    LPVOID  pInBuffer;
    DWORD   dwInSize;       //size of pInBuffer, in Bytes.
    LPVOID  pOutBuffer;
    DWORD   dwOutSize;      //size of pOutBuffer, in Bytes.
    DWORD   dwReturn;
}MY_IOCTL_COMMAND;

class CDriverDevice{
public:
    CDriverDevice(WCHAR *wzSysName);
    ~CDriverDevice();

    DWORD SendCommand(MY_IOCTL_COMMAND &Command);
protected:
    DWORD OpenDriverDevice(HANDLE &hDevice, WCHAR *wzDeviceName);
    void CloseDriverDevice(HANDLE &hDevice);

    HANDLE  m_hDevice;
    WCHAR   m_wzSysName[64];                //SYSName is the service name of driver. Full Device Name = L"\\\\.\\Global\\<%wzSysName%>"
};


#endif          _MYFAULT_DEFINITIONS_H_