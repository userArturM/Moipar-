"""Read Windows icon resources as data, without starting the executable."""
import ctypes
import os
import struct
from pathlib import Path


def ico_images(path):
    data = Path(path).read_bytes()
    reserved, kind, count = struct.unpack_from('<HHH', data)
    if reserved or kind != 1 or not count:
        raise ValueError('Invalid icon directory')
    images = []
    for index in range(count):
        _, _, _, _, _, _, size, offset = struct.unpack_from('<BBBBHHII', data, 6 + index * 16)
        image = data[offset:offset + size]
        if len(image) != size:
            raise ValueError('Truncated icon image')
        images.append(image)
    return images


def pe_icon_images(path):
    if os.name != 'nt':
        raise OSError('Windows resource reader requires Windows')
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel.LoadLibraryExW.restype = wintypes.HMODULE
    kernel.FindResourceW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p]
    kernel.FindResourceW.restype = ctypes.c_void_p
    kernel.LoadResource.argtypes = [wintypes.HMODULE, ctypes.c_void_p]
    kernel.LoadResource.restype = ctypes.c_void_p
    kernel.LockResource.argtypes = [ctypes.c_void_p]
    kernel.LockResource.restype = ctypes.c_void_p
    kernel.SizeofResource.argtypes = [wintypes.HMODULE, ctypes.c_void_p]
    kernel.SizeofResource.restype = wintypes.DWORD
    kernel.FreeLibrary.argtypes = [wintypes.HMODULE]
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMODULE,
                                     ctypes.c_void_p, ctypes.c_void_p, wintypes.LPARAM)
    kernel.EnumResourceNamesW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, callback_type, wintypes.LPARAM]
    module = kernel.LoadLibraryExW(str(Path(path).resolve()), None, 0x22)
    if not module:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        images = []
        @callback_type
        def collect(handle, kind, name, param):
            resource = kernel.FindResourceW(handle, name, kind)
            size = kernel.SizeofResource(handle, resource)
            address = kernel.LockResource(kernel.LoadResource(handle, resource))
            if size and address:
                images.append(ctypes.string_at(address, size))
            return True
        if not kernel.EnumResourceNamesW(module, 3, collect, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        return images
    finally:
        kernel.FreeLibrary(module)


def verify_icon(executable, icon):
    expected = set(ico_images(icon))
    actual = set(pe_icon_images(executable))
    if not expected or not expected.issubset(actual):
        raise RuntimeError(f'Bitora icon resources do not match: {executable}')
    return len(expected)


if __name__ == '__main__':
    for binary in ('dist/MoiParoli.exe', 'dist/browser_host.exe', 'installer_out/MoiParoli-Setup.exe'):
        count = verify_icon(binary, 'icon.ico')
        print(f'Bitora icon verified: {binary}, {count} image sizes')
