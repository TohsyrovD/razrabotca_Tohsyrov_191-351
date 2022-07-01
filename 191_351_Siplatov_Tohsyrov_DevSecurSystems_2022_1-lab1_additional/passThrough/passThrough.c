/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

    passThrough.c

Abstract:

    This is the main module of the passThrough miniFilter driver.
    This filter hooks all IO operations for both pre and post operation
    callbacks.  The filter passes through the operations.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include <string.h>
//#include <wchar.h>

#include <stdlib.h>
#include "aes.h"


#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_PORT port = NULL;
PFLT_PORT ClientPort = NULL;

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

int global_file_extensions_flag = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
PtInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
PtInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
PtInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
PtUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
PtInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
PtOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = { // Содержит структуру данных системных событий
    /*{IRP_MJ_CREATE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CLOSE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },*/

    { IRP_MJ_READ, //TODO comment
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

      /*{IRP_MJ_QUERY_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_EA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_EA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },*/

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    /*{IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SHUTDOWN,
      0,
      PtPreOperationNoPostOperationPassThrough,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CLEANUP,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_SECURITY,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_SECURITY,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_QUOTA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_QUOTA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_PNP,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_READ,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },*/

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    PtUnload,                           //  MiniFilterUnload

    PtInstanceSetup,                    //  InstanceSetup
    PtInstanceQueryTeardown,            //  InstanceQueryTeardown
    PtInstanceTeardownStart,            //  InstanceTeardownStart
    PtInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
PtInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are alwasys created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
PtInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
PtInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceTeardownStart: Entered\n") );
}


VOID
PtInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.
        c
    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceTeardownComplete: Entered\n") );
}

NTSTATUS MiniConnect(PFLT_PORT clientport, PVOID serverportcookie, ULONG size, PVOID Connectioncookie) 
{
    ClientPort = clientport;
    //DbgPrint("connect \r\n");
    DbgPrint("connect");
    return STATUS_SUCCESS;
}

VOID MiniDisconnect(PVOID connectioncookie)
{
    //DbgPrint("disconnect \r\n");
    DbgPrint("disconnect");
    FltCloseClientPort(gFilterHandle, &ClientPort);
}

//UNICODE_STRING global_required_extension; 

//DbgPrint(("global_file_extensions"));
//DbgPrint(global_file_extensions);
//wchar_t buff[1024] = { 0 };//массив строк, нужно строку
UNICODE_STRING global_required_extension = RTL_CONSTANT_STRING(L"tohsyrov");
wchar_t global_file_extensions[64];
//wchar_t * global_file_extensions;


NTSTATUS MiniSendRec(PVOID portcookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG RetLenth)
{
    PCHAR msg = "extension changed successfully";//"kernel msg"
    DbgPrint(("user msg is : %s \r\n"), (PCHAR)InputBuffer);
    DbgPrint(InputBuffer);

//    //if ((PCHAR)InputBuffer != NULL) {
//        //global_extension_str
////        WCHAR* wbuffer = InputBuffer;
//        //strcpy_s(global_extension_str, CStringA(str).GetString());
//        //PCWSTR t;
    //wchar_t* x = (wchar_t*)InputBuffer;
    //UNICODE_STRING local_str = RTL_CONSTANT_STRING(L"siplatov");

//RtlCopyUnicodeString(&global_required_extension, &local_str);
//        //TODO global str
//        //check unicode, unicode const,
//        //check str вместе unicode
//
//        //RtlInitAnsiString(&AnsiString, SourceString);

//       метод копирование - попробуем ещё раз
        //RtlAnsiStringToUnicodeString(&global_required_extension, InputBuffer, TRUE);

//
//        DbgPrint("global_required_extension");
//        //DbgPrint((PCHAR)global_required_extension);
//        DbgPrint(("Unicode string: %wZ\n", &global_required_extension));
//
//    //}

    wchar_t wbuffer[64];// = (wchar_t*)InputBuffer;
    DbgPrint(("inp"));
    DbgPrint((wchar_t*)InputBuffer);

    //dont work
    /*wchar_t* wbuffer2 = (wchar_t)InputBuffer;
    DbgPrint(("wbuffer2"));
    DbgPrint(wbuffer2);*/


    //PCSZ wbuffer = InputBuffer;


    ////strcpy_s(global_extension_str, CStringA(str).GetString());
    ////PCWSTR t;

    //crash
    //global_file_extensions = wbuffer;
    //crash
    //global_file_extensions = (wchar_t*)InputBuffer;
    //wcscpy_s(global_file_extensions, 1024, wbuffer);
    //memcpy(/*(void*)*/global_file_extensions, /*(void*)*/ InputBuffer, 64);
    //memcpy((void*) global_file_extensions, (void*)InputBuffer, 64);

    //try to local copy
    memcpy(/*(void*)*/wbuffer, /*(void*)*/ InputBuffer, 64);

    DbgPrint(("wbuffer"));
    DbgPrint(wbuffer); 

    //memcpy(/*(void*)*/global_file_extensions, /*(void*)*/ InputBuffer, 64);
    mbstowcs(global_file_extensions, InputBuffer, 64);

    DbgPrint(("global_file_extensions"));
    DbgPrint(global_file_extensions);
    global_file_extensions_flag = 1;

    wcscat(global_file_extensions, L" ");

    strcpy((PCHAR)OutputBuffer, msg);
    return STATUS_SUCCESS;
}

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    DbgPrint(("driver unload"));
    FltCloseCommunicationPort(port);
    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\mf");

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("PassThrough!DriverEntry: Entered\n"));

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

    if (NT_SUCCESS(status)) {
        
        InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(gFilterHandle, &port, &oa, NULL, MiniConnect, MiniDisconnect, MiniSendRec, 1);
        FltFreeSecurityDescriptor(sd);
        
        if (NT_SUCCESS(status)) {

            //  Start filtering i/o
            status = FltStartFiltering(gFilterHandle);

            if (NT_SUCCESS(status)) { //TODO !
                return status;
            }
            FltCloseCommunicationPort(port);
        }
        FltUnregisterFilter(gFilterHandle);//отменяем регистрацию фильтра в случае "неудачной регистрации"
    }

    return status;
}

NTSTATUS
PtUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unloaded indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns the final status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}



/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is the main pre-operation dispatch routine for this
    miniFilter. Since this is just a simple passThrough miniFilter it
    does not do anything with the callbackData but rather return
    FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
    miniFilter in the chain.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtPreOperationPassThrough: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (PtDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    PtOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }


    //DbgPrint("Driver-Filter, filename %wZ ", Data->Iopb->TargetFileObject->FileName.Buffer); //  Вывод имени файла (FileName в UNICODE_STRING)
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    status = FltGetFileNameInformation(
        Data, 
        FLT_FILE_NAME_NORMALIZED |
        FLT_FILE_NAME_QUERY_DEFAULT, 
        &NameInfo);

    //UNICODE_STRING RecuiredFileExtension = RTL_CONSTANT_STRING(L"testlabextension"); // Перевод расширения в UNICODE_STRING

    if (!NT_SUCCESS(status)) {

        // Ничего не выводим, чтобы не загружать оперативную память, DebugView
        //DbgPrint("[-] PassThrough, FltGetFileNameInformation failed, FileName = %wZ\n", 
        //    Data->Iopb->TargetFileObject->FileName);
    }

    //status =  (NameInfo); // Лог слишком большой, загружает ВМ
    //if (!NT_SUCCESS(status)) {

    //    DbgPrint("[-] PassThrough, FltParseFileNameInformation failed, FileName = %wZ\n", 
    //        Data->Iopb->TargetFileObject->FileName);
    //}

    /*else if ( // Проверка на совпадение расширения с нашим шаблоном
        RtlEqualUnicodeString(
            &RecuiredFileExtension,
            &NameInfo->Extension, \
            FALSE)) {

        DbgPrint("[+] PRE: FileName = %wZ, extention: %wZ, parentDir: %wZ, volume: %wZ\n",
            NameInfo->Name,
            NameInfo->Extension,
            NameInfo->ParentDir,
            NameInfo->Volume);

        if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
            DbgPrint("PRE: IRP_MJ_READ");
            DbgPrint("PRE: ReadBuffer = %s\n", (char*)Data->Iopb->Parameters.Read.ReadBuffer);
            //DbgPrint("PRE: ReadBuffer address = %x\n", &(Data->Iopb->Parameters.Read.ReadBuffer));
        }
        else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
            DbgPrint("PRE: IRP_MJ_WRITE");
            DbgPrint("PRE: WriteBuffer = %s\n", (char*)Data->Iopb->Parameters.Write.WriteBuffer);
            //DbgPrint("PRE: WriteBuffer address = %x\n", &(Data->Iopb->Parameters.Write.WriteBuffer));

        }
        else if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
            DbgPrint("PRE: IRP_MJ_CREATE");
        }
        else {
            DbgPrint("PRE: IRP_MJ_ = %x\n", Data->Iopb->MajorFunction);
        }

        //char operation_code[256] = { 0 };
        //switch (Data->Iopb->IrpFlags) {
        //case IRP_READ_OPERATION: {
        //    strcpy(operation_code, "IRP_READ_OPERATION");
        //    break;
        //};
        //case IRP_WRITE_OPERATION: {
        //    strcpy(operation_code, "IRP_WRITE_OPERATION");
        //    break;
        //};
        //case IRP_BUFFERED_IO: {
        //    strcpy(operation_code, "IRP_BUFFERED_IO");
        //    break;
        //};
        //default: {
        //    strcpy(operation_code, "unknown");
        //}
        //}

        //DbgPrint("PRE: IRP code = %s\n", operation_code);
        // 
        //DbgPrint("PRE: WriteBuffer = %s\n", (char*)Data->Iopb->Parameters.Write.WriteBuffer);
        //DbgPrint("PRE: WriteBuffer address = %x\n", &(Data->Iopb->Parameters.Write.WriteBuffer));
        //((char*)Data->Iopb->Parameters.Write.WriteBuffer)[0] = '*';
        

        // Так как IRP-коды у Read и Write буфферов одинаковые, можем не писать следующее:
        //DbgPrint("ReadBuffer = %s\n", (char*)Data->Iopb->Parameters.Read.ReadBuffer);
        //((char*)Data->Iopb->Parameters.Read.ReadBuffer)[0] = '&';
    }*/


    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
PtOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("PassThrough!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}



FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.
    Эта процедура является процедурой завершения после операции для этого
    мини-фильтра.

    Это не доступно для просмотра по страницам, поскольку оно может быть вызвано на уровне DPC.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

    Данные - Указатель на данные обратного вызова фильтра, которые передаются нам.

    FltObjects - Указатель на структуру данных FLT_RELATED_OBJECTS, содержащую
        непрозрачные дескрипторы для этого фильтра, экземпляра, связанного с ним тома и
файлового объекта.

    CompletionContext - Контекст завершения, установленный в процедуре предварительной операции.

    Флаги - Указывает, является ли завершение успешным или происходит слив.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("PassThrough!PtPostOperationPassThrough: Entered\n"));

    // Начало
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL; // Объявление структуры
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED |
        FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo); // Парсинг имени файла на составляющие
    UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"tohsyrov"); // Перевод расширения в UNICODE_STRING
    //PCHAR required_extension = "tohsyrov"; // Перевод расширения в UNICODE_STRING
    //UNICODE_STRING global_UNICODE_STRING = RTL_CONSTANT_STRING(global_file_extensions);

    if (!NT_SUCCESS(status)) {
        //ничего не выводим, чтобы не загружать оперативную память, может привести к crash`у
    }
    else if ( // проверка на совпадение расширения с нашим шаблоном
        //RtlEqualUnicodeString(
        //&required_extension,
        ////&global_required_extension,
        //   // &global_UNICODE_STRING,
        //&NameInfo->Extension, FALSE)
        //|| // проверка на совпадение расширения с нашим шаблоном
        //RtlEqualUnicodeString( &((UNICODE_STRING)RTL_CONSTANT_STRING(L"siplatov")), &NameInfo->Extension, FALSE)

        //пробуем 
         (global_file_extensions_flag != 0) && (NameInfo->Extension.Length>5)
        //((global_file_extensions_flag != 0) && ((int) wcsstr(NameInfo->Extension.Buffer, global_file_extensions) != NULL) == 1)
        ) 
         {

        wchar_t buf_file_ext[64];
        memset(buf_file_ext, 0, sizeof(buf_file_ext));
        memcpy(buf_file_ext, NameInfo->Extension.Buffer, NameInfo->Extension.Length);
        //wcscat(buf_file_ext, L" ");

        if((wchar_t)wcsstr(global_file_extensions, buf_file_ext) != NULL)
            /*wcscmp(buf_ext, global_file_extensions)*/
            //0 == 0)
         {
            DbgPrint("begin---------------------------------------------------------------------------------------------------------------------------------");

            DbgPrint("1.1.1");
            /*UNICODE_STRING us;
            RtlInitString(&us, global_file_extensions);*/

            wchar_t buf[64];
            memset(buf, 0, sizeof(buf));
            memcpy(buf, NameInfo->Extension.Buffer, NameInfo->Extension.Length);


            //DbgPrint("us Unicode string: %wZ\n", us);//Unicode string: tohsyrov

            DbgPrint("Unicode file Extension string: %wZ\n", NameInfo->Extension);
            
            DbgPrint("1.23--without spaces");
            DbgPrint("Length global_file_extensions is %i\n", wcslen(global_file_extensions));
            DbgPrint("global_file_extensions: \"%ls\"\n", global_file_extensions);
            wchar_t isNameMatch_w = wcsstr(global_file_extensions, buf); //
            //DbgPrint("buf2"); 
            if (isNameMatch_w != NULL) //always true
            {
                DbgPrint("TRUE");

            }
            else
            {
                DbgPrint("FALSE");
            }
            DbgPrint(isNameMatch_w);//0
            DbgPrint("result: \"%ls\"\n", wcsstr(global_file_extensions, buf));
            
            //txt exe pub siplatov
            //ext file = sip
            //int k = wstrstr(global_file_extensions, " "); //5
            //добавить пробельчики по бокам и поиск подстроке
            

            //int i = wcsncmp(buf, global_file_extensions, 8);
            //DbgPrint("%d", i); //-28000

            wchar_t p [64] = L" ";
            wcscat(buf, L" ");
            DbgPrint("2--");

            //DbgPrint("Length buf00 is %i\n", wcslen(buf00));//9
            //DbgPrint("Length p is %i\n", wcslen(p));//10
            //DbgPrint("Length buf is %i\n", wcslen(buf));//9

            DbgPrint("Length buf2 is %i\n", wcslen(buf)); //10
            DbgPrint("buf2: \"%ls\"\n", buf);

            //DbgPrint("global_file_extension:");
            //DbgPrint(global_file_extensions);//tohsyrov

            DbgPrint("3---"); //TRUE вручную задавалось
            wchar_t ext_list[64];
            memset(ext_list, 0, sizeof(ext_list));
            memcpy(ext_list, global_file_extensions, wcslen(global_file_extensions)*2);

            wchar_t p_ext_list[64] = L" ";
            DbgPrint("Length ext_list is %i\n", wcslen(ext_list));//
            DbgPrint("Length global_file_extensions is %i\n", wcslen(global_file_extensions));//27
            /*wchar_t* ext_list00 = */wcscat(ext_list, L" ");
            //buf2 = wcsncat(p, buf2, 1);
            wchar_t* ext_list2 = wcscat(p_ext_list, ext_list);

            //DbgPrint("Length ext_list is %i\n", wcslen(ext_list));//28
            //DbgPrint("ext_list: \"%ls\"\n", ext_list);

            //DbgPrint("Length p_ext_list is %i\n", wcslen(p_ext_list));//29
            //DbgPrint("p_ext_list: \"%ls\"\n", p_ext_list);

            DbgPrint("Length ext_list2 is %i\n", wcslen(ext_list2));//29
            DbgPrint("ext_list2: \"%ls\"\n", ext_list2);
            
            DbgPrint("5.23--with spaces");
            if ((wchar_t)wcsstr(ext_list2, buf) != NULL) //нашлась наша подстрока
            {
                DbgPrint("TRUE");
            }
            else
            {
                DbgPrint("FALSE");
            }
            DbgPrint(wcsstr(ext_list2, buf));//0
            DbgPrint("result: \"%ls\"\n", wcsstr(ext_list2, buf));
            // 
            // 
            //DbgPrint("5"); 
            ////DbgPrint(wcscmp( NameInfo->Extension.Buffer , global_file_extensions));
            ////int isNameMatch = wcscmp(NameInfo->Extension.Buffer, global_file_extensions); //проверить ещё раз - crash
            //if (wcscmp( NameInfo->Extension.Buffer , global_file_extensions)==0)
            //{
            //    DbgPrint("TRUE");

            //}
            //else
            //{
            //    DbgPrint("FALSE");
            //}

            ////сравнение в цикле (работает, но слишком веселое решение)
            //for (int b = 0; b < 5; b++)
            //{
            //    DbgPrint(new_u_str[b]);
            //    DbgPrint(new_u_str[b] == NameInfo->Extension.Buffer[b]);
            //    DbgPrint("--\n");
            //    if (new_u_str[b] == NameInfo->Extension.Buffer[b])
            //    {
            //        DbgPrint(b);
            //        DbgPrint("true");
            //    }
            //}


            //DbgPrint("8");


            ////int isNameMatch = wcsstr(NameInfo->Extension.Buffer, new_u_str) != NULL; //work
            //int isNameMatch = wcsstr(NameInfo->Extension.Buffer, new_u_str); //
            //DbgPrint("isNameMatch"); DbgPrint(isNameMatch);
            //if (isNameMatch == 0) //always true
            //{
            //    DbgPrint("TRUE");

            //}
            //else
            //{
            //    DbgPrint("FALSE");
            //}

            //if (isNameMatch != NULL) //always false
            //{
            //    DbgPrint("TRUE");

            //}
            //else
            //{
            //    DbgPrint("FALSE"); 

            //DbgPrint("11");
            //////int isNameMatch = wcsstr(NameInfo->Extension.Buffer, new_u_str) != NULL; //
            //wchar_t wStr [64];
            //memset(wStr, 0, 64);
            //memcpy(wStr, NameInfo->Extension.Buffer, NameInfo->Extension.Length); 
            //int isNameMatchcmp = wcscmp(wStr, new_u_str); //
            ////int isNameMatchcmp = wcscmp(NameInfo->Extension.Buffer, (wchar_t)new_u_str); //
            //DbgPrint("isNameMatch"); DbgPrint(isNameMatchcmp);
            //if (isNameMatchcmp == 0) // 
            //{
            //    DbgPrint("TRUE");

            //}
            //else
            //{
            //    DbgPrint("FALSE");
            //}

            //if (isNameMatchcmp != NULL) // 
            //{
            //    DbgPrint("TRUE");

            //}
            //else
            //{
            //    DbgPrint("FALSE");
            //}

            //free(wStr);

            DbgPrint("len ext file");
            DbgPrint("%u", NameInfo->Extension.Length); //16=8*2

            DbgPrint("Extension.Buffer:");
            DbgPrint("%hhu", +NameInfo->Extension.Buffer[1]); //111 = o) вывод числовом виде кодировки unicode

            //DbgPrint("ext need:");
            //DbgPrint(("Unicode string: %wZ\n", &required_extension));

            DbgPrint("Unicode string file ext: %wZ\n", NameInfo->Extension);//Unicode string: tohsyrov
            DbgPrint("Unicode string global: %wZ\n", global_required_extension);//Unicode string: tohsyrov
            if ((wchar_t)wcsstr(ext_list2, buf) != NULL)
            {
                //проверка на событие IRP_MJ_WRITE
                if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
                    DbgPrint("_____");
                    DbgPrint("Writing");//индикатор, что обнаружен перехват события "запись"
                    DbgPrint("Data:");
                    DbgPrint(Data->Iopb->Parameters.Write.WriteBuffer);//вывод в консоль данных перехваченного буфера

                    if (Data->Iopb->Parameters.Write.WriteBuffer) {//проверяем, что в буфере что-то есть
                        //DbgPrint("Cipher");//индикаторss
                        //unsigned char cipher[64];
                        uint8_t hexarray[1024];//задаем массив, в котором будет храниться буфер
                        memset(hexarray, 0, 1024);//заполнение массива hexarray нулями
                        DbgPrint("Buffer is not null...");
                        DbgPrint("Crypting...");
                        //посимвольно забираем из буфера все символы в массив
                        for (int i = 0; i < strlen(Data->Iopb->Parameters.Write.WriteBuffer); i++) {
                            hexarray[i] = (uint8_t)((char*)Data->Iopb->Parameters.Write.WriteBuffer)[i];
                        }

                        unsigned char KEY[] = "142354759ADFBCAD";//определение ключа
                        uint8_t* key = (uint8_t*)KEY;//приведение ключа к нужному формату
                        uint8_t iv[] = { 0x75, 0x52, 0x5f, 0x69,//инициализирующий вектор
                            0x6e, 0x74, 0x65, 0x72,
                            0x65, 0x73, 0x74, 0x69,
                            0x6e, 0x67, 0x21, 0x21 };

                        struct AES_ctx ctx;//создание объекта шифра (контекст, который будет хранить ключ и инициализирующий вектор)

                        AES_init_ctx_iv(&ctx, key, iv);//инициализация структуры
                        AES_CBC_encrypt_buffer(&ctx, hexarray, 1024);//шифруем буфер (передаем контекст, буфер и длину буфера)

                        DbgPrint("enc_hexarray");
                        DbgPrint(hexarray);
                        for (int i = 0; i < 1024; i++) {
                            ((char*)Data->Iopb->Parameters.Write.WriteBuffer)[i] = hexarray[i];
                        }
                    }

                }
                //проверка на событие IRP_MJ_READ
                else if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
                    DbgPrint("_____");
                    DbgPrint("Reading...");//индикатор, что обнаружен перехват события "read"
                    DbgPrint("Data:");
                    DbgPrint(Data->Iopb->Parameters.Read.ReadBuffer);//вывод содержимого буфера
                    //если буфер не пуст, то расшифровываем его
                    if (strlen((char*)Data->Iopb->Parameters.Read.ReadBuffer) != 0) {
                        DbgPrint("Buffer is not null...");
                        DbgPrint("Decrypting...");//индикатор
                        //unsigned char decipher[64];
                        uint8_t hexarray[1024];//задаем массив, в котором будет храниться буфер
                        memset(hexarray, 0, 1024);//заполняем массив нулями
                        //забираем из буфера в массив все данные
                        for (int i = 0; i < strlen(Data->Iopb->Parameters.Read.ReadBuffer); i++) {
                            hexarray[i] = (uint8_t)((char*)Data->Iopb->Parameters.Read.ReadBuffer)[i];
                        }

                        DbgPrint("Source data:");
                        DbgPrint(hexarray);
                        //DbgPrint(hexarray);

                        unsigned char KEY[] = "142354759ADFBCAD";//определение ключа
                        uint8_t* key = (uint8_t*)KEY;//приведение ключа к нужному формату
                        uint8_t iv[] = { 0x75, 0x52, 0x5f, 0x69,//инициализирующий вектор
                            0x6e, 0x74, 0x65, 0x72,
                            0x65, 0x73, 0x74, 0x69,
                            0x6e, 0x67, 0x21, 0x21 };

                        struct AES_ctx ctx;//создание объекта шифра (контекст, который будет хранить ключ и инициализирующий вектор)

                        AES_init_ctx_iv(&ctx, key, iv);//инициализация структуры
                        AES_CBC_decrypt_buffer(&ctx, hexarray, 1024);//расшифруем буфер (передаем контекст, буфер и длину буфера)
                        DbgPrint("Result:");
                        DbgPrint(hexarray);//вывод массива символов

                        //передаем весь расшифрованный текст в буфер записи
                        for (int i = 0; i < strlen((char*)Data->Iopb->Parameters.Read.ReadBuffer); i++) {
                            ((char*)Data->Iopb->Parameters.Write.WriteBuffer)[i] = hexarray[i];
                        }
                    }
                }
            }
         }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is the main pre-operation dispatch routine for this
    miniFilter. Since this is just a simple passThrough miniFilter it
    does not do anything with the callbackData but rather return
    FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
    miniFilter in the chain.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtPreOperationNoPostOperationPassThrough: Entered\n") );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

