from enum import IntFlag


class GenericAccess(IntFlag):
    READ = 0x80000000
    WRITE = 0x40000000


FILE_SHARE_READ = 0x00000001
OPEN_ALWAYS = 4
INVALID_HANDLE_VALUE = -1
