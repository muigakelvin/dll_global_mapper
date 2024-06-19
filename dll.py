import ctypes
import ctypes.wintypes
import psutil
import logging
import os
import urllib.request
import threading

# Constants
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_RELEASE = 0x8000

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(_name_)

# Structures
class MODULEENTRY32(ctypes.Structure):
    fields = [("dwSize", ctypes.wintypes.DWORD),
                ("th32ModuleID", ctypes.wintypes.DWORD),
                ("th32ProcessID", ctypes.wintypes.DWORD),
                ("GlblcntUsage", ctypes.wintypes.DWORD),
                ("ProccntUsage", ctypes.wintypes.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", ctypes.wintypes.DWORD),
                ("hModule", ctypes.wintypes.HMODULE),
                ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260)]

# Windows API Functions
CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
Module32First = ctypes.windll.kernel32.Module32First
Module32Next = ctypes.windll.kernel32.Module32Next
GetLastError = ctypes.windll.kernel32.GetLastError
OpenProcess = ctypes.windll.kernel32.OpenProcess
CloseHandle = ctypes.windll.kernel32.CloseHandle
VirtualFreeEx = ctypes.windll.kernel32.VirtualFreeEx
SuspendThread = ctypes.windll.kernel32.SuspendThread
ResumeThread = ctypes.windll.kernel32.ResumeThread


DLL_DOWNLOAD_URLS = {
    "BL.dll": "DLL-files.com",
}

def log_function_call(func):
    """Decorator to log function calls and results."""
    def wrapper(*args, **kwargs):
        logger.info(f"Calling function: {func._name_} with args: {args} kwargs: {kwargs}")
        result = func(*args, **kwargs)
        logger.info(f"Function {func._name_} returned: {result}")
        return result
    return wrapper

@log_function_call
def get_pid_by_name(process_name):
    """Get the process ID by the process name."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

@log_function_call
def suspend_process(pid):
    """Suspend all threads of the given process."""
    try:
        p = psutil.Process(pid)
        for thread in p.threads():
            hThread = ctypes.windll.kernel32.OpenThread(0x0002, False, thread.id)
            if hThread:
                SuspendThread(hThread)
                CloseHandle(hThread)
        logger.info(f"Suspended process {pid}.")
    except Exception as e:
        logger.error(f"Failed to suspend process threads: {e}")

@log_function_call
def resume_process(pid):
    """Resume all threads of the given process."""
    try:
        p = psutil.Process(pid)
        for thread in p.threads():
            hThread = ctypes.windll.kernel32.OpenThread(0x0002, False, thread.id)
            if hThread:
                ResumeThread(hThread)
                CloseHandle(hThread)
        logger.info(f"Resumed process {pid}.")
    except Exception as e:
        logger.error(f"Failed to resume process threads: {e}")

@log_function_call
def remove_injected_dll(process_name, dll_name):
    """Remove the injected DLL from the specified process."""
    pid = get_pid_by_name(process_name)
    if not pid:
        logger.error(f"Process {process_name} not found.")
        return

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if hSnapshot == -1:
        logger.error(f"Failed to create snapshot for process {process_name}.")
        return

    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)

    if not Module32First(hSnapshot, ctypes.byref(me32)):
        logger.error(f"Failed to retrieve module information for process {process_name}.")
        CloseHandle(hSnapshot)
        return

    found = False
    while True:
        if dll_name.encode('utf-8').lower() in me32.szModule.lower():
            found = True
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not hProcess:
                logger.error(f"Failed to open process {process_name}.")
                break

            suspend_process(pid)
            result = VirtualFreeEx(hProcess, me32.modBaseAddr, 0, MEM_RELEASE)
            if result:
                logger.info(f"Successfully removed DLL: {dll_name}")
            else:
                logger.error(f"Failed to remove DLL: {dll_name}")
            resume_process(pid)
            
            CloseHandle(hProcess)
            break

        if not Module32Next(hSnapshot, ctypes.byref(me32)):
            if GetLastError() == 18:  # ERROR_NO_MORE_FILES
                if not found:
                    logger.info(f"Finished scanning modules. DLL {dll_name} not found.")
            else:
                logger.error(f"Failed to retrieve the next module for process {process_name}.")
            break

    CloseHandle(hSnapshot)

def check_and_install_missing_dlls(dll_names):
    """Check and install missing DLLs if found."""
    threads = []
    for dll in dll_names:
        if not os.path.exists(os.path.join(os.getcwd(), dll)):
            logger.warning(f"{dll} is missing. Attempting to download and install.")
            thread = threading.Thread(target=download_and_install_dll, args=(dll,))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()

def download_and_install_dll(dll_name):
    """Download and install the specified DLL."""
    url = DLL_DOWNLOAD_URLS.get(dll_name)
    if not url:
        logger.error(f"No download URL for {dll_name}.")
        return

    try:
        response = urllib.request.urlopen(url)
        dll_data = response.read()
        with open(os.path.join(os.getcwd(), dll_name), 'wb') as file:
            file.write(dll_data)
        logger.info(f"Successfully downloaded and installed {dll_name}.")
    except Exception as e:
        logger.error(f"Failed to download {dll_name}: {e}")


if _name_ == "_main_":
    check_and_install_missing_dlls(["glmapper.dll"])
    remove_injected_dll("globalmapper.exe", "xlr.dll")