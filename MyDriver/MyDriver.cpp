#ifdef __cplusplus
extern "C" {
#endif
//#include <ntddk.h>
//#include <ntstatus.h>
//#include <wdm.h>
//#include <windef.h>
//#include <string.h>
#include <stdio.h>
//#include <ntstrsafe.h>
#include <fltkernel.h>
#ifdef __cplusplus
}; // extern "C"
#endif

//C runtime string library (i.e. wcscpy) are deprecated in kernel.
//You can still use it but have to disable warning. Or Fre build will be failed.
#pragma warning(disable : 4995)
#include "MyDriver.h"

//********** Defines **********//
#define     MY_POOL_TAG             'TSET'      //This name will become 'TEST' in windbg because little endian
#define     FILE_SYMLINK_PREFIX     L"\\??\\"   //The dosname of file should has this prefix. i.e. "\\\\??\\C:\\windows\\win.ini"
#define     MY_LOG_CONTENT          L"This is test log written by MyDriver.sys\r\n"
#define     MY_LOG_CONTENT_SIZE     (wcslen(MY_LOG_CONTENT)*sizeof(WCHAR))
#define     DEVICE_PREFIX           L"\\Device\\"
#define     DEVICE_SYMLINK_PREFIX   L"\\DosDevices\\"
#define     DEFAULT_LOG_PATH        L"C:\\MyLog.log"
#define     BUFFER_SIZE             1024

#define     VERSION_VISTA    (NTDDI_VERSION >= NTDDI_VISTA)

typedef PCHAR (*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
typedef NTSTATUS (*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength);



//********** Function Prototypes **********//
NTSTATUS FilterUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS  FltObjects, FLT_INSTANCE_SETUP_FLAGS  Flags, DEVICE_TYPE  VolumeDeviceType, FLT_FILESYSTEM_TYPE  VolumeFilesystemType);

FLT_POSTOP_CALLBACK_STATUS PostCreateAction(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreWriteAction(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS PreCloseAction(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);

bool GetFullProcessName(PEPROCESS eProcess, PUNICODE_STRING pusImageFileName);

//********** Global Variables **********//
bool g_bEnableLog = false;
UNICODE_STRING  g_strDeviceName = {0};
UNICODE_STRING  g_strSymbolicName = {0};
UNICODE_STRING  g_strLogFile = {0};


//Register interested event callback
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      NULL,
      PostCreateAction },
    { IRP_MJ_CLOSE,
      0,
      PreCloseAction,
      NULL },
    { IRP_MJ_WRITE,
      0,
      PreWriteAction,
      NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version
    0,                                      //  Flags
    NULL,                                   //  Context
    Callbacks,                              //  Operation callbacks
    FilterUnload,                           //  FilterUnload
    FilterSetup,                            //  InstanceSetup
    NULL,                                   //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete
    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
#if VERSION_VISTA
    ,
    NULL                                    //  KTM notification callback
#endif // VERSION_VISTA
};

typedef struct _MY_FILTER_DATA {
    PDRIVER_OBJECT pDriverObject;
    PFLT_FILTER pFilterHandle;
    PFLT_INSTANCE pFltInstance;
    FAST_MUTEX FastMutex;
    GET_PROCESS_IMAGE_NAME GetProcessImageFileName;
    QUERY_INFO_PROCESS ZwQueryInformationProcess;
    bool bGetFullProcessPathName;
} MY_FILTER_DATA, *PMY_FILTER_DATA;

MY_FILTER_DATA MyFilterData;

//********** Function **********//
bool GetFullProcessName(PEPROCESS eProcess, PUNICODE_STRING pusImageFileName)
{
    if((eProcess==NULL) || (pusImageFileName==NULL))
        return false;

    NTSTATUS status = STATUS_ACCESS_DENIED;
    HANDLE hProcessHandle = NULL;
    ULONG returnedLength = 0;

    //Open process object
    status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcessHandle);
    if((!NT_SUCCESS(status)) || (!hProcessHandle))
	{
		ObDereferenceObject(eProcess);
		return false;
	}

    //Find out name of process
    status = MyFilterData.ZwQueryInformationProcess(hProcessHandle, ProcessImageFileName, pusImageFileName->Buffer, pusImageFileName->MaximumLength, &returnedLength);

    if(NT_SUCCESS(status))
    {
        pusImageFileName->Length = wcslen(pusImageFileName->Buffer)*sizeof(WCHAR);
    }
    else
    {
        DbgPrint("ZwQueryInformationProcess failed. ReturnLength=%d, status=0x%X\n", returnedLength, status);
    }

    ZwClose(hProcessHandle);
    ObDereferenceObject(eProcess);

    return true;
}

NTSTATUS WriteLogFile(UNICODE_STRING &strFile)
{
    OBJECT_ATTRIBUTES ObjectAttributes = {0};
    IO_STATUS_BLOCK IoStatusBlock = {0};
    HANDLE      hFile;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    //KdBreakPoint();
    InitializeObjectAttributes(&ObjectAttributes, &strFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(  &hFile,
                            FILE_APPEND_DATA | SYNCHRONIZE,
                            &ObjectAttributes,
                            &IoStatusBlock,
                            0,
                            FILE_ATTRIBUTE_NORMAL, 
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN_IF,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0); 
                            
    if(NT_SUCCESS(status))
    {
        status = ZwWriteFile(   hFile,
                                NULL,
                                NULL,
                                NULL,
                                &IoStatusBlock,
                                MY_LOG_CONTENT,
                                MY_LOG_CONTENT_SIZE,
                                NULL,
                                NULL);
        DbgPrint("ZwWriteFile() invoked. status=0x%X\n", status);

        ZwClose(hFile);
    }
    else
        DbgPrint("Open File Failed. status=0x%X\n", status);

    return status;
}

void WriteLog(WCHAR *wszLog)
{
    if((g_bEnableLog == false) || (wszLog == NULL))
        return;

    ExAcquireFastMutex(&MyFilterData.FastMutex);

    OBJECT_ATTRIBUTES   ObjectAttributes = {0};
    IO_STATUS_BLOCK     IoStatusBlock = {0};
    HANDLE              hFile;
    PVOID               pFileObject;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    ULONG               uByteWritten = 0;
    LARGE_INTEGER       offset;

    //KdBreakPoint();
    InitializeObjectAttributes(&ObjectAttributes, &g_strLogFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = FltCreateFile( MyFilterData.pFilterHandle,
                            MyFilterData.pFltInstance,
                            &hFile,
                            FILE_APPEND_DATA | SYNCHRONIZE,
                            &ObjectAttributes,
                            &IoStatusBlock,
                            0,
                            FILE_ATTRIBUTE_NORMAL, 
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN_IF,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0,
                            0); 
                            
    //Transfer Handle to FileObject
    if(NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(hFile, 0, NULL, KernelMode, &pFileObject, NULL);
        if(NT_SUCCESS(status))
        {
            offset.HighPart = -1;
            offset.LowPart = FILE_WRITE_TO_END_OF_FILE;
            status = FltWriteFile(  MyFilterData.pFltInstance,
                                    (PFILE_OBJECT)pFileObject,
                                    &offset,
                                    wcslen(wszLog)*sizeof(WCHAR),
                                    wszLog,
                                    FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                                    &uByteWritten,
                                    NULL,
                                    NULL);
            
            DbgPrint("FltWriteFile() invoked. status=0x%X\n", status);
        }
        else
		{
			DbgPrint("ObReferenceObjectByHandle - FAILED - %08x\n", status);
		}

        FltClose(hFile);
    }
    else
        DbgPrint("Open File Failed. status=0x%X\n", status);

    ExReleaseFastMutex(&MyFilterData.FastMutex);
}

NTSTATUS IrpDispatchDefault( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
    PIO_STACK_LOCATION      iostack;
    NTSTATUS                status;     //Kernel only uses NTSTATUS. There is no Win32 error code / HRESULT.

    //We are going to handle this IRP. Related I/O information are stored in IO_STACK_LOCATION array.
    //So pick current location(current element of this array) then prepare to parse it.
    iostack = IoGetCurrentIrpStackLocation (Irp);

    status = STATUS_INVALID_DEVICE_REQUEST;

    //Remember to set this status code.
    //This status code will return back to caller.
    //Win32 subsystem will translate status code to Win32 Error Code.    
    Irp->IoStatus.Status = status;

    //This request is handled and no necessary to pass to other driver.
    //So we have to tell IoManager : "this I/O request finished. Please feedback to caller and clean up the irp"
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return status;
}


NTSTATUS IrpDispatchDeviceIoControl( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
    PIO_STACK_LOCATION      iostack;
    PVOID                   pInBuffer;
    PVOID                   pOutBuffer;
    ULONG                   nInSize;
    ULONG                   nOutSize;
    ULONG                   nIoctlCode;

    NTSTATUS                status;     //Kernel only uses NTSTATUS. There is no Win32 error code / HRESULT.

    //We are going to handle this IRP. Related I/O information are stored in IO_STACK_LOCATION array.
    //So pick current location(current element of this array) then prepare to parse it.
    iostack = IoGetCurrentIrpStackLocation (Irp);

    //Parse the input data from IRP and IO_STACK_LOCATION
    pInBuffer           = iostack->Parameters.DeviceIoControl.Type3InputBuffer;
    nInSize             = iostack->Parameters.DeviceIoControl.InputBufferLength;
    pOutBuffer          = Irp->UserBuffer;
    nOutSize            = iostack->Parameters.DeviceIoControl.OutputBufferLength;
    nIoctlCode          = iostack->Parameters.DeviceIoControl.IoControlCode;

    switch(nIoctlCode)
    {
    case IOCTL_FUNC_BSOD:
        {
            ULONG *nBugcheckCode = (ULONG *)pInBuffer;
            KeBugCheckEx(*nBugcheckCode, 3, 3, 2, 3);
        }
        break;
    case IOCTL_FUNC_LOG_TEST:
        {
            //Prepare filename string.
            //In kernel, it's better handle strings with UNICODE_STRING and ANSI_STRING structure.
            UNICODE_STRING strFile;
            //DbgBreakPoint();

            WCHAR *wzFile = (WCHAR *)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, MY_POOL_TAG);
            RtlZeroMemory(wzFile, PAGE_SIZE);
            wcsncpy(wzFile, FILE_SYMLINK_PREFIX, wcslen(FILE_SYMLINK_PREFIX));
            wcscat(wzFile, (WCHAR*)pInBuffer);

            //This API helps to set wzFile to strFile.Buffer, and calculate strFile.Length.
            //Notice: strFile.Length is "Size in Bytes", not wcslen() ......
            RtlInitUnicodeString(&strFile, wzFile);
            //remember to fill this field. Lots of kernel APIs use this field to determine buffer length.
            strFile.MaximumLength = PAGE_SIZE;

            status = WriteLogFile(strFile);
            status = WriteLogFile(strFile);

            //RtlFreeUnicodeString() and RtlFreeAnsiString() will free buffer in structure.
            RtlFreeUnicodeString(&strFile);
            //ExFreePoolWithTag(wzFile, MY_POOL_TAG);

            wcsncpy((WCHAR*)pOutBuffer, (WCHAR*)pInBuffer, wcslen((WCHAR*)pInBuffer));
            wcscat((WCHAR*)pOutBuffer, L" is generated by MyDriver.sys");
        }
        break;
    case IOCTL_FUNC_LOG_ENABLE:
        {
            g_bEnableLog = true;

            RtlZeroMemory(g_strLogFile.Buffer, BUFFER_SIZE);
            wcsncpy(g_strLogFile.Buffer, FILE_SYMLINK_PREFIX, wcslen(FILE_SYMLINK_PREFIX));

            if(wcslen((WCHAR*)pInBuffer) > 0)
            {
                wcscat(g_strLogFile.Buffer, (WCHAR*)pInBuffer);
                g_strLogFile.Length = (wcslen(FILE_SYMLINK_PREFIX)+wcslen((WCHAR*)pInBuffer)) * sizeof(WCHAR);
            }
            else
            {
                wcscat(g_strLogFile.Buffer, DEFAULT_LOG_PATH);
                g_strLogFile.Length = (wcslen(FILE_SYMLINK_PREFIX)+wcslen(DEFAULT_LOG_PATH)) * sizeof(WCHAR);
            }
                    
            WriteLog(L"MiniFilter driver debug log enabled\r\n");
            status = STATUS_SUCCESS;
        }
        break;
    case IOCTL_FUNC_LOG_DISABLE:
        {
            WriteLog(L"MiniFilter driver debug log disabled\r\n");
            g_bEnableLog = false;
            status = STATUS_SUCCESS;
        }
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }


    //Remember to set this status code.
    //This status code will return back to caller.
    //Win32 subsystem will translate status code to Win32 Error Code.    
    Irp->IoStatus.Status = status;

    //This request is handled and no necessary to pass to other driver.
    //So we have to tell IoManager : "this I/O request finished. Please feedback to caller and clean up the irp"
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return status;
}


NTSTATUS IrpDispatchCreateClose( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	PIO_STACK_LOCATION      iostack;
	NTSTATUS                status;     //Kernel only uses NTSTATUS. There is no Win32 error code / HRESULT.

    //We are going to handle this IRP. Related I/O information are stored in IO_STACK_LOCATION array.
    //So pick current location(current element of this array) then prepare to parse it.
    iostack = IoGetCurrentIrpStackLocation (Irp);
    
    switch (iostack->MajorFunction) 
    {
    //IRP_MJ_CREATE will be called by CreateFile();
    //IRP_MJ_CLOSE will be called by CloseHandle();
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        status = STATUS_SUCCESS;
		break;
    }

    //Remember to set this status code.
    //This status code will return back to caller.
    //Win32 subsystem will translate status code to Win32 Error Code.    
    Irp->IoStatus.Status = status;

    //This request is handled and no necessary to pass to other driver.
    //So we have to tell IoManager : "this I/O request finished. Please feedback to caller and clean up the irp"
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}



VOID Driver_Unload(PDRIVER_OBJECT   pDriverObject)
{
    IoDeleteSymbolicLink(&g_strSymbolicName);

    //Remember delete your device object before driver unloaded.
    //Or your driver will be NEVER unloaded or can't be loaded twice.
    IoDeleteDevice(pDriverObject->DeviceObject);

    RtlFreeUnicodeString(&g_strSymbolicName);
    RtlFreeUnicodeString(&g_strDeviceName);
}

NTSTATUS FilterUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
    g_bEnableLog = false;
    RtlFreeUnicodeString(&g_strLogFile);

    IoDeleteSymbolicLink(&g_strSymbolicName);
    IoDeleteDevice(MyFilterData.pDriverObject->DeviceObject);

    RtlFreeUnicodeString(&g_strSymbolicName);
    RtlFreeUnicodeString(&g_strDeviceName);

    FltUnregisterFilter(MyFilterData.pFilterHandle);

    return STATUS_SUCCESS;
}

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS  FltObjects, FLT_INSTANCE_SETUP_FLAGS  Flags, DEVICE_TYPE  VolumeDeviceType, FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{
    //KdBreakPoint();
    if((VolumeDeviceType==FILE_DEVICE_DISK_FILE_SYSTEM) && (VolumeFilesystemType==FLT_FSTYPE_NTFS))
    {
        MyFilterData.pFltInstance = FltObjects->Instance;
    }
    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS PostCreateAction(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{   
    FLT_POSTOP_CALLBACK_STATUS  returnStatus = FLT_POSTOP_FINISHED_PROCESSING;
    NTSTATUS                    status;

    if(KeGetCurrentIrql() > PASSIVE_LEVEL)
        return returnStatus;

    if (Data->Iopb->TargetFileObject != NULL)
    {
        PFILE_ALL_INFORMATION pFileAllInfo = (PFILE_ALL_INFORMATION)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_ALL_INFORMATION)+PAGE_SIZE, MY_POOL_TAG);
    
        RtlZeroMemory(pFileAllInfo, sizeof(FILE_ALL_INFORMATION)+PAGE_SIZE);
        pFileAllInfo->NameInformation.FileNameLength = PAGE_SIZE;
        status = FltQueryInformationFile(MyFilterData.pFltInstance, Data->Iopb->TargetFileObject, pFileAllInfo, sizeof(FILE_ALL_INFORMATION)+PAGE_SIZE, FileAllInformation, NULL);
        
        //Only handle file case
        if(NT_SUCCESS(status) && (pFileAllInfo->StandardInformation.Directory == 0))
        {
            PEPROCESS objCurProcess = IoThreadToProcess(Data->Thread);
            UNICODE_STRING strProcessName = {0};

            strProcessName.MaximumLength = BUFFER_SIZE;
            strProcessName.Buffer = (WCHAR *)ExAllocatePoolWithTag(PagedPool, BUFFER_SIZE, MY_POOL_TAG);
            RtlZeroMemory(strProcessName.Buffer, BUFFER_SIZE);
            
            if(MyFilterData.bGetFullProcessPathName == true)
            {
                if(MyFilterData.ZwQueryInformationProcess != NULL)
                {
                    if(GetFullProcessName(objCurProcess, &strProcessName) == false)
                    {
                        DbgPrint("GetFullProcessName failed");
                    }
                }
            }
            else
            {
                if(MyFilterData.GetProcessImageFileName != NULL)
                {
                    ANSI_STRING strProcNameOnly = {0};
                    PCHAR pszProcessName = NULL;
                    pszProcessName = MyFilterData.GetProcessImageFileName(objCurProcess);
                    RtlInitAnsiString(&strProcNameOnly, pszProcessName);
                    RtlAnsiStringToUnicodeString(&strProcessName, &strProcNameOnly, FALSE);
                }
            }

            POBJECT_NAME_INFORMATION pwcFilePath;
            status = IoQueryFileDosDeviceName(Data->Iopb->TargetFileObject,&pwcFilePath);

            if (NT_SUCCESS(status))
            {
                WCHAR *wzLog = (WCHAR *)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, MY_POOL_TAG);
                RtlZeroMemory(wzLog, PAGE_SIZE);

                _snwprintf(wzLog, PAGE_SIZE, L"[Create] %wZ is opened/created by %wZ\r\n", &pwcFilePath->Name, &strProcessName);
                WriteLog(wzLog);
                //KdBreakPoint();
                ExFreePoolWithTag(wzLog, MY_POOL_TAG);
                ExFreePool(pwcFilePath);
            }

            RtlFreeUnicodeString(&strProcessName);
        }

        ExFreePoolWithTag(pFileAllInfo, MY_POOL_TAG);
    }

    return returnStatus;
}

FLT_PREOP_CALLBACK_STATUS PreWriteAction(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    FLT_PREOP_CALLBACK_STATUS   returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    NTSTATUS                    status;

    if(KeGetCurrentIrql() > PASSIVE_LEVEL)
        return returnStatus;

    if (Data->Iopb->TargetFileObject != NULL)
    {
        PFILE_STANDARD_INFORMATION pFileStandardInfo = (PFILE_STANDARD_INFORMATION)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_STANDARD_INFORMATION), MY_POOL_TAG);
    
        RtlZeroMemory(pFileStandardInfo, sizeof(FILE_STANDARD_INFORMATION));
        status = FltQueryInformationFile(MyFilterData.pFltInstance, Data->Iopb->TargetFileObject, pFileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);
         
        //Only handle file case
        if(NT_SUCCESS(status) && (pFileStandardInfo->Directory == 0))
        {
            POBJECT_NAME_INFORMATION pwcFilePath = NULL;
            status = IoQueryFileDosDeviceName(Data->Iopb->TargetFileObject,&pwcFilePath);

            if (NT_SUCCESS(status))
            {
                WCHAR *wzLog = (WCHAR *)ExAllocatePoolWithTag(PagedPool, BUFFER_SIZE, MY_POOL_TAG);
                RtlZeroMemory(wzLog, BUFFER_SIZE);

                _snwprintf(wzLog, BUFFER_SIZE, L"[Write] %d bytes is written to %wZ\r\n", Data->Iopb->Parameters.Write.Length, &pwcFilePath->Name);
                WriteLog(wzLog);
                //KdBreakPoint();
                ExFreePoolWithTag(wzLog, MY_POOL_TAG);
                ExFreePool(pwcFilePath);
            }
        }

        ExFreePoolWithTag(pFileStandardInfo, MY_POOL_TAG);
    }

    return returnStatus;
}

FLT_PREOP_CALLBACK_STATUS PreCloseAction(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    FLT_PREOP_CALLBACK_STATUS   returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    NTSTATUS                    status;

    if(KeGetCurrentIrql() > PASSIVE_LEVEL)
        return returnStatus;

    if (Data->Iopb->TargetFileObject != NULL)
    {
        PFILE_STANDARD_INFORMATION pFileStandardInfo = (PFILE_STANDARD_INFORMATION)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_STANDARD_INFORMATION), MY_POOL_TAG);
    
        RtlZeroMemory(pFileStandardInfo, sizeof(FILE_STANDARD_INFORMATION));
        status = FltQueryInformationFile(MyFilterData.pFltInstance, Data->Iopb->TargetFileObject, pFileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);
        
        //Only handle file case
        if(NT_SUCCESS(status) && (pFileStandardInfo->Directory == 0) && (Data->Iopb->TargetFileObject->FileName.Length>0))
        {
            /*
                Issue: We can't call IoQueryFileDosDeviceName twice over here as we do at PostCreateAction and PreWriteAction or the OS will crash.
                       The reason is not clear right now. It seems the FileObject will be released twice.
                       The workaround is to copy Data->Iopb->TargetFileObject to a local buffer, assign to IoQueryFileDosDeviceName and free the buffer after 
                       IoQueryFileDosDeviceName return then everything looks fine when windbg is attached or the OS still crash.
             */
            /*
            PFILE_OBJECT pFileObject = (PFILE_OBJECT)ExAllocatePoolWithTag(PagedPool, Data->Iopb->TargetFileObject->Size, MY_POOL_TAG);
            RtlZeroMemory(pFileObject, Data->Iopb->TargetFileObject->Size);
            RtlCopyMemory(pFileObject, Data->Iopb->TargetFileObject, Data->Iopb->TargetFileObject->Size);
            POBJECT_NAME_INFORMATION pwcFilePath = NULL;
            status = IoQueryFileDosDeviceName(pFileObject,&pwcFilePath);

            if (NT_SUCCESS(status))
            {*/
                WCHAR *wzLog = (WCHAR *)ExAllocatePoolWithTag(PagedPool, BUFFER_SIZE, MY_POOL_TAG);
                RtlZeroMemory(wzLog, BUFFER_SIZE);

                _snwprintf(wzLog, BUFFER_SIZE, L"[Close] %wZ\r\n", &Data->Iopb->TargetFileObject->FileName);
                WriteLog(wzLog);
                //KdBreakPoint();
                ExFreePoolWithTag(wzLog, MY_POOL_TAG);
                /*ExFreePool(pwcFilePath);
            }

            ExFreePoolWithTag(pFileObject, MY_POOL_TAG);*/
        }
        ExFreePoolWithTag(pFileStandardInfo, MY_POOL_TAG);
    }

    return returnStatus;
}

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS DriverEntry( IN OUT PDRIVER_OBJECT   pDriverObject, IN PUNICODE_STRING  pstrRegistryPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDEVICE_OBJECT  pMyDeviceObject = NULL;
    WCHAR *wzName = NULL;

    for(int i =0; i <IRP_MJ_MAXIMUM_FUNCTION; i++)
        pDriverObject->MajorFunction[i] = IrpDispatchDefault;

    //Create Device and SymbolicName
    g_strDeviceName.MaximumLength = PAGE_SIZE;
    wzName = (WCHAR*) ExAllocatePoolWithTag(PagedPool, g_strDeviceName.MaximumLength, MY_POOL_TAG);
    RtlZeroMemory(wzName, g_strDeviceName.MaximumLength);
    wcscpy(wzName, DEVICE_PREFIX);
    wcscat(wzName, MY_SYSNAME);

    RtlInitUnicodeString(&g_strDeviceName, wzName);
    status = IoCreateDevice ( pDriverObject,
                            0,              //no device extension
                            &g_strDeviceName,
                            MY_DRIVER_FILEDEVICE,
                            0,
                            TRUE,           //exclusive load, there is no duplicated allowed
                            &pMyDeviceObject );

    if (NT_SUCCESS(status))
    {
        g_strSymbolicName.MaximumLength = PAGE_SIZE;
        wzName = (WCHAR*) ExAllocatePoolWithTag(PagedPool, g_strSymbolicName.MaximumLength, MY_POOL_TAG);
        RtlZeroMemory(wzName, g_strSymbolicName.MaximumLength);
        wcscpy(wzName, DEVICE_SYMLINK_PREFIX);
        wcscat(wzName, MY_SYSNAME);

        RtlInitUnicodeString(&g_strSymbolicName, wzName);
        status = IoCreateSymbolicLink (&g_strSymbolicName, &g_strDeviceName);
    }

    if (!NT_SUCCESS(status))
    {
        if(pMyDeviceObject)
            IoDeleteDevice(pMyDeviceObject);

        return STATUS_UNSUCCESSFUL;
    }

    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDispatchDeviceIoControl;
    //pDriverObject->DriverUnload = Driver_Unload;

    //These two IRP_MJ code should be handled because CreateFile() and CloseHandle().
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = IrpDispatchCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpDispatchCreateClose;

    //For Fliter Driver
    MyFilterData.pDriverObject = pDriverObject;
    status = FltRegisterFilter(pDriverObject, &FilterRegistration, &MyFilterData.pFilterHandle);

    if(NT_SUCCESS(status))
    {
        status = FltStartFiltering(MyFilterData.pFilterHandle);

        //KdBreakPoint();
        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(MyFilterData.pFilterHandle);
        }
    }

    g_strLogFile.MaximumLength = BUFFER_SIZE;
    g_strLogFile.Buffer = (PWSTR)ExAllocatePool(PagedPool, BUFFER_SIZE);
    g_strLogFile.Length = 0;

    ExInitializeFastMutex(&MyFilterData.FastMutex);
    
    MyFilterData.bGetFullProcessPathName = false;
    MyFilterData.GetProcessImageFileName = NULL;
    MyFilterData.ZwQueryInformationProcess = NULL;

    if(MyFilterData.bGetFullProcessPathName == true)
    {
        //Init For ZwQueryInformationProcess API
        //Currently, it will return in hj-???/<ImageDeviceName> format, not sure why there is hj-??? at the head
        UNICODE_STRING sZwQueryInformationProcess = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess" );
        MyFilterData.ZwQueryInformationProcess = (QUERY_INFO_PROCESS) MmGetSystemRoutineAddress(&sZwQueryInformationProcess);
    }
    else
    {
        //Init For PsGetProcessImageFileName API
        UNICODE_STRING sPsGetProcessImageFileName = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName" );
        MyFilterData.GetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&sPsGetProcessImageFileName);
    }

    return STATUS_SUCCESS;
}

#ifdef __cplusplus
}; //extern "C"
#endif