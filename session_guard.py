"""Listen for session/power changes without touching authentication settings."""
import os
import threading


def event_reason(message, parameter):
    if message == 0x2B1 and parameter in (2, 4, 6, 7, 11):
        return 'session'
    if message == 0x218 and parameter in (4, 6, 7, 18):
        return 'suspend'
    return None


def idle_seconds(value):
    try:return max(1,min(120,int(value)))*60
    except (TypeError,ValueError,OverflowError):return 300


class SessionGuard:
    def __init__(self, callback):
        self.callback = callback
        self.hwnd = None
        self.ready = threading.Event()
        self.available = False
        self.thread = None

    def start(self):
        if os.name != 'nt':
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        if self.hwnd:
            import ctypes
            from ctypes import wintypes
            post = ctypes.windll.user32.PostMessageW
            post.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            post(self.hwnd, 0x10, 0, 0)

    def _run(self):
        import ctypes
        from ctypes import wintypes as w
        user = ctypes.WinDLL('user32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        wts = ctypes.WinDLL('wtsapi32', use_last_error=True)
        procedure = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
        class WindowClass(ctypes.Structure):
            _fields_ = [('style', w.UINT), ('proc', procedure), ('extra', ctypes.c_int),
                        ('window_extra', ctypes.c_int), ('instance', w.HINSTANCE),
                        ('icon', w.HICON), ('cursor', w.HANDLE), ('background', w.HBRUSH),
                        ('menu', w.LPCWSTR), ('name', w.LPCWSTR)]
        user.DefWindowProcW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
        user.DefWindowProcW.restype = ctypes.c_ssize_t
        user.DestroyWindow.argtypes = [w.HWND]
        user.RegisterClassW.argtypes = [ctypes.POINTER(WindowClass)]
        user.CreateWindowExW.argtypes = [w.DWORD,w.LPCWSTR,w.LPCWSTR,w.DWORD,
            ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,w.HWND,w.HMENU,w.HINSTANCE,ctypes.c_void_p]
        user.CreateWindowExW.restype = w.HWND
        user.UnregisterClassW.argtypes = [w.LPCWSTR,w.HINSTANCE]
        user.DispatchMessageW.argtypes = [ctypes.POINTER(w.MSG)]
        user.DispatchMessageW.restype = ctypes.c_ssize_t
        user.GetMessageW.argtypes = [ctypes.POINTER(w.MSG),w.HWND,w.UINT,w.UINT]
        user.TranslateMessage.argtypes = [ctypes.POINTER(w.MSG)]
        kernel.GetModuleHandleW.argtypes = [w.LPCWSTR]
        kernel.GetModuleHandleW.restype = w.HMODULE
        wts.WTSRegisterSessionNotification.argtypes = [w.HWND,w.DWORD]
        wts.WTSUnRegisterSessionNotification.argtypes = [w.HWND]
        instance = kernel.GetModuleHandleW(None)
        name = 'BitoraSessionGuard_' + str(id(self))
        @procedure
        def receive(hwnd, message, parameter, data):
            reason = event_reason(message, parameter)
            if reason:
                try:self.callback(reason)
                except Exception:pass
                if message==0x218:return 1
            if message == 0x10:
                user.DestroyWindow(hwnd)
                return 0
            if message == 2:
                user.PostQuitMessage(0)
                return 0
            return user.DefWindowProcW(hwnd, message, parameter, data)
        wc = WindowClass(0,receive,0,0,instance,None,None,None,None,name)
        registered = False
        try:
            if not user.RegisterClassW(ctypes.byref(wc)):
                return
            # An invisible top-level window receives power broadcasts too.
            self.hwnd = user.CreateWindowExW(0,name,'',0,0,0,0,0,None,None,instance,None)
            if not self.hwnd:return
            registered = bool(wts.WTSRegisterSessionNotification(self.hwnd,0))
            self.available = registered
            self.ready.set()
            message = w.MSG()
            while user.GetMessageW(ctypes.byref(message),None,0,0) > 0:
                user.TranslateMessage(ctypes.byref(message))
                user.DispatchMessageW(ctypes.byref(message))
        finally:
            if registered:wts.WTSUnRegisterSessionNotification(self.hwnd)
            if self.hwnd:user.DestroyWindow(self.hwnd)
            self.hwnd = None
            self.available = False
            user.UnregisterClassW(name,instance)
            self.ready.set()
