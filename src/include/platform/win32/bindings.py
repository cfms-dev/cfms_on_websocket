from functools import cache
lazy import ctypes

from include.platform.win32.constants import (
    FILE_SHARE_READ,
    INVALID_HANDLE_VALUE,
    OPEN_ALWAYS,
    GenericAccess,
)


@cache
def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_int
    return kernel32


def can_open_file_for_write(path: str) -> bool:
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        path,
        GenericAccess.READ | GenericAccess.WRITE,
        FILE_SHARE_READ,
        None,
        OPEN_ALWAYS,
        0,
        None,
    )
    if handle == ctypes.c_void_p(INVALID_HANDLE_VALUE).value:
        return False
    if not kernel32.CloseHandle(handle):
        raise ctypes.WinError(ctypes.get_last_error())
    return True
