"""Windows shell identity is separate from the stable vault/application ID."""
import sys

SHELL_APP_ID = 'Bitora.Password'


def set_shell_identity():
    if sys.platform != 'win32':
        return False
    try:
        import ctypes
        setter = ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID
        setter.argtypes = [ctypes.c_wchar_p]
        setter.restype = ctypes.c_long
        return setter(SHELL_APP_ID) == 0
    except (AttributeError, OSError):
        return False
