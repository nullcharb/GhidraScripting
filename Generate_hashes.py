import os
import pefile
import json

def ror(dword, bits):
    return (dword >> bits | dword << (32 - bits)) & 0xFFFFFFFF

def hash(function, bits=13, print_hash=True):
    function_hash = 0
    for c in str(function):
        function_hash = ror(function_hash, bits)
        function_hash += ord(c)
    h = function_hash & 0xFFFFFFFF
    # if print_hash:
        # print('[+] %s = 0x%08X' % (function, h))
        # print("#define HASH_%s           0x%08X" % (function.upper(), h))
    return h

INTERESTING_DLLS = [
    'kernel32.dll', 'comctl32.dll', 'advapi32.dll', 'comdlg32.dll',
    'gdi32.dll',    'msvcrt.dll',   'netapi32.dll', 'ntdll.dll',
    'ntoskrnl.exe', 'oleaut32.dll', 'psapi.dll',    'shell32.dll',
    'shlwapi.dll',  'srsvc.dll',    'urlmon.dll',   'user32.dll',
    'winhttp.dll',  'wininet.dll',  'ws2_32.dll',   'wship6.dll',
    'advpack.dll',
]

INTERESTING_DLLS_1 = [
    'kernel32.dll', 'msvcrt.dll'
]

exports_list = {}

for filename in os.listdir("C:\\windows\\system32"):
    if filename.lower() in INTERESTING_DLLS_1:
        pe = pefile.PE("c:\\windows\\system32\\" + filename)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                api_name = exp.name.decode('utf-8')
                # exports_list[api_name] = hex(hash(api_name))
                api_hash = hex(hash(api_name))
                exports_list[api_hash] = api_name
            except:
                continue

exports_file = 'exports.json'.encode('utf-8')

open(exports_file, 'wb').write(json.dumps(exports_list).encode('utf-8'))