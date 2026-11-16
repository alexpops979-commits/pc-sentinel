//! Тонкий слой Win32 FFI (без внешних крейтов).
#![allow(non_snake_case, non_camel_case_types, dead_code, clippy::upper_case_acronyms)]

use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LSTATUS = i32;
pub type HKEY = *mut c_void;
pub type HWND = *mut c_void;

pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_SUCCESS: u32 = 0;

pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const INFINITE: u32 = 0xFFFF_FFFF;
pub const STILL_ACTIVE: u32 = 259;
pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
pub const AF_INET: u32 = 2;
pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const KEY_READ: u32 = 0x20019;
pub const KEY_WRITE: u32 = 0x20006;
pub const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
pub const HKEY_CURRENT_USER: usize = 0x8000_0001;
pub const SW_SHOWNORMAL: i32 = 1;
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Окно с сообщением об ошибке.
///
/// В оконной сборке нет консоли: без этого окна любая ошибка запуска
/// выглядит как «приложение не запускается» без объяснения.
pub fn error_box(title: &str, text: &str) {
    const MB_OK: u32 = 0x0;
    const MB_ICONERROR: u32 = 0x10;
    const MB_SETFOREGROUND: u32 = 0x1_0000;
    let title_w = to_wide(title);
    let text_w = to_wide(text);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text_w.as_ptr(),
            title_w.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
    }
}

/// Записывает строковое значение в реестр, создавая раздел при необходимости.
///
/// Нужно для записи в «Программы и компоненты»: без неё приложение нельзя
/// удалить штатным способом, и оно выглядит «зелёным» архивом, а не программой.
pub fn reg_write_string(root: usize, path: &str, name: &str, value: &str) -> bool {
    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;
    unsafe {
        let wpath = to_wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        let mut disposition: u32 = 0;
        let rc = RegCreateKeyExW(
            root,
            wpath.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null_mut(),
            &mut key,
            &mut disposition,
        );
        if rc != 0 {
            return false;
        }
        let wname = to_wide(name);
        // Строка в реестре — UTF-16 с завершающим нулём.
        let data: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = std::slice::from_raw_parts(
            data.as_ptr() as *const u8,
            data.len() * std::mem::size_of::<u16>(),
        );
        let rc = RegSetValueExW(key, wname.as_ptr(), 0, REG_SZ, bytes.as_ptr(), bytes.len() as u32);
        RegCloseKey(key);
        rc == 0
    }
}

/// Записывает целое значение (DWORD) в реестр.
pub fn reg_write_dword(root: usize, path: &str, name: &str, value: u32) -> bool {
    const KEY_WRITE: u32 = 0x20006;
    const REG_DWORD: u32 = 4;
    unsafe {
        let wpath = to_wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        let mut disposition: u32 = 0;
        let rc = RegCreateKeyExW(
            root,
            wpath.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null_mut(),
            &mut key,
            &mut disposition,
        );
        if rc != 0 {
            return false;
        }
        let wname = to_wide(name);
        let bytes = value.to_le_bytes();
        let rc = RegSetValueExW(key, wname.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4);
        RegCloseKey(key);
        rc == 0
    }
}

/// Удаляет раздел реестра вместе с подразделами.
pub fn reg_delete_tree(root: usize, path: &str) -> bool {
    unsafe {
        let wpath = to_wide(path);
        RegDeleteTreeW(root, wpath.as_ptr()) == 0
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

impl FILETIME {
    pub fn as_u64(&self) -> u64 {
        ((self.dwHighDateTime as u64) << 32) | self.dwLowDateTime as u64
    }
}

#[repr(C)]
#[derive(Default)]
pub struct MEMORYSTATUSEX {
    pub dwLength: u32,
    pub dwMemoryLoad: u32,
    pub ullTotalPhys: u64,
    pub ullAvailPhys: u64,
    pub ullTotalPageFile: u64,
    pub ullAvailPageFile: u64,
    pub ullTotalVirtual: u64,
    pub ullAvailVirtual: u64,
    pub ullAvailExtendedVirtual: u64,
}

/// Сводка по системе из psapi: то же, что диспетчер задач показывает
/// на вкладках «Производительность» и «Подробности».
#[repr(C)]
#[derive(Default)]
pub struct PERFORMANCE_INFORMATION {
    pub cb: u32,
    pub commit_total: usize,
    pub commit_limit: usize,
    pub commit_peak: usize,
    pub physical_total: usize,
    pub physical_available: usize,
    pub system_cache: usize,
    pub kernel_total: usize,
    pub kernel_paged: usize,
    pub kernel_nonpaged: usize,
    pub page_size: usize,
    pub handle_count: u32,
    pub process_count: u32,
    pub thread_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; 260],
}

impl Default for PROCESSENTRY32W {
    fn default() -> Self {
        PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260],
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct PROCESS_MEMORY_COUNTERS {
    pub cb: u32,
    pub PageFaultCount: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub QuotaPeakPagedPoolUsage: usize,
    pub QuotaPagedPoolUsage: usize,
    pub QuotaPeakNonPagedPoolUsage: usize,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MIB_IFROW {
    pub wszName: [u16; 256],
    pub dwIndex: u32,
    pub dwType: u32,
    pub dwMtu: u32,
    pub dwSpeed: u32,
    pub dwPhysAddrLen: u32,
    pub bPhysAddr: [u8; 8],
    pub dwAdminStatus: u32,
    pub dwOperStatus: u32,
    pub dwLastChange: u32,
    pub dwInOctets: u32,
    pub dwInUcastPkts: u32,
    pub dwInNUcastPkts: u32,
    pub dwInDiscards: u32,
    pub dwInErrors: u32,
    pub dwInUnknownProtos: u32,
    pub dwOutOctets: u32,
    pub dwOutUcastPkts: u32,
    pub dwOutNUcastPkts: u32,
    pub dwOutDiscards: u32,
    pub dwOutErrors: u32,
    pub dwOutQLen: u32,
    pub dwDescrLen: u32,
    pub bDescr: [u8; 256],
}

impl Default for MIB_IFROW {
    fn default() -> Self {
        MIB_IFROW {
            wszName: [0; 256],
            dwIndex: 0,
            dwType: 0,
            dwMtu: 0,
            dwSpeed: 0,
            dwPhysAddrLen: 0,
            bPhysAddr: [0; 8],
            dwAdminStatus: 0,
            dwOperStatus: 0,
            dwLastChange: 0,
            dwInOctets: 0,
            dwInUcastPkts: 0,
            dwInNUcastPkts: 0,
            dwInDiscards: 0,
            dwInErrors: 0,
            dwInUnknownProtos: 0,
            dwOutOctets: 0,
            dwOutUcastPkts: 0,
            dwOutNUcastPkts: 0,
            dwOutDiscards: 0,
            dwOutErrors: 0,
            dwOutQLen: 0,
            dwDescrLen: 0,
            bDescr: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MIB_TCPROW_OWNER_PID {
    pub dwState: u32,
    pub dwLocalAddr: u32,
    pub dwLocalPort: u32,
    pub dwRemoteAddr: u32,
    pub dwRemotePort: u32,
    pub dwOwningPid: u32,
}

#[repr(C)]
pub struct STARTUPINFOW {
    pub cb: u32,
    pub lpReserved: LPWSTR,
    pub lpDesktop: LPWSTR,
    pub lpTitle: LPWSTR,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

impl Default for STARTUPINFOW {
    fn default() -> Self {
        STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpReserved: std::ptr::null_mut(),
            lpDesktop: std::ptr::null_mut(),
            lpTitle: std::ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: 0,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: std::ptr::null_mut(),
            hStdOutput: std::ptr::null_mut(),
            hStdError: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: u32,
    pub dwThreadId: u32,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetSystemTimes(idle: *mut FILETIME, kernel: *mut FILETIME, user: *mut FILETIME) -> BOOL;
    pub fn GlobalMemoryStatusEx(buf: *mut MEMORYSTATUSEX) -> BOOL;
    pub fn GetLogicalDrives() -> u32;
    pub fn GetDriveTypeW(root: LPCWSTR) -> u32;
    pub fn GetDiskFreeSpaceExW(
        dir: LPCWSTR,
        free_to_caller: *mut u64,
        total: *mut u64,
        free_total: *mut u64,
    ) -> BOOL;
    pub fn OpenProcess(access: u32, inherit: BOOL, pid: u32) -> HANDLE;
    pub fn CloseHandle(h: HANDLE) -> BOOL;
    pub fn SetPriorityClass(h: HANDLE, class: u32) -> BOOL;
    pub fn GetPriorityClass(h: HANDLE) -> u32;
    pub fn GetProcessTimes(
        h: HANDLE,
        creation: *mut FILETIME,
        exit: *mut FILETIME,
        kernel: *mut FILETIME,
        user: *mut FILETIME,
    ) -> BOOL;
    pub fn QueryFullProcessImageNameW(h: HANDLE, flags: u32, buf: LPWSTR, size: *mut u32) -> BOOL;
    pub fn GetTickCount64() -> u64;
    pub fn GetForegroundWindow() -> HWND;
    pub fn GetFileAttributesW(path: LPCWSTR) -> u32;
    pub fn GetLongPathNameW(short: LPCWSTR, long: LPWSTR, size: u32) -> u32;
    pub fn GetActiveProcessorCount(group: u16) -> u32;
    pub fn LoadLibraryW(name: LPCWSTR) -> HANDLE;
    pub fn GetProcAddress(module: HANDLE, name: *const u8) -> *mut c_void;
    pub fn FreeLibrary(module: HANDLE) -> BOOL;
    pub fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
    pub fn Process32FirstW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Process32NextW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> BOOL;
    pub fn GetCurrentProcessId() -> u32;
    pub fn Sleep(ms: u32);
    pub fn GetComputerNameW(buf: LPWSTR, size: *mut u32) -> BOOL;
    pub fn GetEnvironmentVariableW(name: LPCWSTR, buf: LPWSTR, size: u32) -> u32;
    pub fn ExpandEnvironmentStringsW(src: LPCWSTR, buf: LPWSTR, size: u32) -> u32;
    pub fn CreateProcessW(
        app: LPCWSTR,
        cmd: LPWSTR,
        pa: *mut c_void,
        ta: *mut c_void,
        inherit: BOOL,
        flags: u32,
        env: *mut c_void,
        dir: LPCWSTR,
        si: *mut STARTUPINFOW,
        pi: *mut PROCESS_INFORMATION,
    ) -> BOOL;
    pub fn TerminateProcess(h: HANDLE, code: u32) -> BOOL;
    pub fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    pub fn GetExitCodeProcess(h: HANDLE, code: *mut u32) -> BOOL;
    pub fn GetLastError() -> u32;
    pub fn GetSystemDirectoryW(buf: LPWSTR, size: u32) -> u32;
    pub fn GetWindowsDirectoryW(buf: LPWSTR, size: u32) -> u32;
}

#[link(name = "psapi")]
extern "system" {
    pub fn GetProcessMemoryInfo(h: HANDLE, counters: *mut PROCESS_MEMORY_COUNTERS, cb: u32) -> BOOL;
    pub fn EnumProcesses(pids: *mut u32, cb: u32, needed: *mut u32) -> BOOL;
    pub fn GetPerformanceInfo(info: *mut PERFORMANCE_INFORMATION, cb: u32) -> BOOL;
}

#[link(name = "iphlpapi")]
extern "system" {
    pub fn GetIfTable(table: *mut MIB_IFROW, size: *mut u32, order: BOOL) -> u32;
    pub fn GetExtendedTcpTable(
        table: *mut c_void,
        size: *mut u32,
        order: BOOL,
        af: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn RegOpenKeyExW(key: usize, sub: LPCWSTR, opts: u32, access: u32, out: *mut HKEY) -> LSTATUS;
    pub fn RegEnumValueW(
        key: HKEY,
        index: u32,
        name: LPWSTR,
        name_len: *mut u32,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> LSTATUS;
    pub fn RegQueryValueExW(
        key: HKEY,
        name: LPCWSTR,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> LSTATUS;
    pub fn RegCloseKey(key: HKEY) -> LSTATUS;
    pub fn RegDeleteValueW(key: HKEY, name: LPCWSTR) -> LSTATUS;
    pub fn RegCreateKeyExW(
        key: usize,
        sub: LPCWSTR,
        reserved: u32,
        class: LPCWSTR,
        options: u32,
        access: u32,
        sa: *mut c_void,
        out: *mut HKEY,
        disposition: *mut u32,
    ) -> LSTATUS;
    pub fn RegSetValueExW(
        key: HKEY,
        name: LPCWSTR,
        reserved: u32,
        kind: u32,
        data: *const u8,
        len: u32,
    ) -> LSTATUS;
    pub fn RegDeleteTreeW(key: usize, sub: LPCWSTR) -> LSTATUS;
    pub fn RegEnumKeyExW(
        key: HKEY,
        index: u32,
        name: LPWSTR,
        name_len: *mut u32,
        reserved: *mut u32,
        class: LPWSTR,
        class_len: *mut u32,
        last_write: *mut FILETIME,
    ) -> LSTATUS;
}

#[link(name = "shell32")]
extern "system" {
    pub fn ShellExecuteW(
        hwnd: HWND,
        op: LPCWSTR,
        file: LPCWSTR,
        params: LPCWSTR,
        dir: LPCWSTR,
        show: i32,
    ) -> HANDLE;
    pub fn SHBrowseForFolderW(info: *mut BROWSEINFOW) -> *mut c_void;
    pub fn SHGetPathFromIDListW(pidl: *const c_void, path: LPWSTR) -> BOOL;
}

/// BROWSEINFOW из shlobj.h — параметры системного диалога выбора папки.
#[repr(C)]
pub struct BROWSEINFOW {
    pub hwnd_owner: HWND,
    pub pidl_root: *mut c_void,
    pub display_name: LPWSTR,
    pub title: LPCWSTR,
    pub flags: u32,
    pub callback: *mut c_void,
    pub param: isize,
    pub image: i32,
}

impl Default for BROWSEINFOW {
    fn default() -> Self {
        BROWSEINFOW {
            hwnd_owner: std::ptr::null_mut(),
            pidl_root: std::ptr::null_mut(),
            display_name: std::ptr::null_mut(),
            title: std::ptr::null(),
            flags: 0,
            callback: std::ptr::null_mut(),
            param: 0,
            image: 0,
        }
    }
}

/// Системный диалог выбора папки. Возвращает путь или None, если отменили.
pub fn pick_folder(title: &str) -> Option<String> {
    // BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX
    const FLAGS: u32 = 0x0001 | 0x0040 | 0x0010;
    let wtitle = to_wide(title);
    let mut display = vec![0u16; 260];
    let mut info = BROWSEINFOW {
        // Владелец — активное окно, иначе диалог открывается позади приложения.
        hwnd_owner: unsafe { GetForegroundWindow() },
        display_name: display.as_mut_ptr(),
        title: wtitle.as_ptr(),
        flags: FLAGS,
        ..Default::default()
    };
    unsafe {
        let pidl = SHBrowseForFolderW(&mut info);
        if pidl.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let ok = SHGetPathFromIDListW(pidl, buf.as_mut_ptr());
        // Память под pidl выделяет оболочка — освобождаем через CoTaskMemFree.
        if let Some(lib) = DynLib::load("ole32.dll") {
            if let Some(free) = lib.sym("CoTaskMemFree") {
                let free: unsafe extern "system" fn(*mut c_void) = std::mem::transmute(free);
                free(pidl);
            }
        }
        if ok == 0 {
            return None;
        }
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(from_wide(&buf[..end]))
    }
}

/// Превращает короткое имя (8.3) в полное.
///
/// `%TEMP%` часто приходит как `C:\Users\3A18~1\AppData\Local\Temp`, и тогда
/// пути в находках не совпадают с тем, что видит пользователь. Если преобразовать
/// не удалось, возвращаем исходную строку — лучше короткий путь, чем ничего.
pub fn long_path(path: &str) -> String {
    let wide = to_wide(path);
    let mut buf = vec![0u16; 1024];
    let n = unsafe { GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize > buf.len() {
        return path.to_string();
    }
    from_wide(&buf[..n as usize])
}

// ---------- helpers ----------

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PdhFmtCounterValue {
    pub status: u32,
    pub double_value: f64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PdhFmtCounterValueItemW {
    pub name: LPWSTR,
    pub value: PdhFmtCounterValue,
}

pub const PDH_FMT_DOUBLE: u32 = 0x0000_0200;
pub const PDH_MORE_DATA: u32 = 0x8000_07D2;

pub type PdhOpenQueryW = unsafe extern "system" fn(LPCWSTR, usize, *mut HANDLE) -> u32;
pub type PdhAddEnglishCounterW = unsafe extern "system" fn(HANDLE, LPCWSTR, usize, *mut HANDLE) -> u32;
pub type PdhCollectQueryData = unsafe extern "system" fn(HANDLE) -> u32;
pub type PdhGetFormattedCounterArrayW =
    unsafe extern "system" fn(HANDLE, u32, *mut u32, *mut u32, *mut PdhFmtCounterValueItemW) -> u32;
pub type PdhCloseQuery = unsafe extern "system" fn(HANDLE) -> u32;

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub fn env_var(name: &str) -> Option<String> {
    let wname = to_wide(name);
    let mut buf = vec![0u16; 1024];
    let n = unsafe { GetEnvironmentVariableW(wname.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        None
    } else {
        Some(from_wide(&buf[..n as usize]))
    }
}

/// Раскрывает %windir% и подобные подстановки в командной строке.
pub fn expand_env(text: &str) -> String {
    let src = to_wide(text);
    let mut buf = vec![0u16; 4096];
    let n = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize > buf.len() {
        return text.to_string();
    }
    from_wide(&buf[..n.saturating_sub(1) as usize])
}

pub fn computer_name() -> String {
    let mut buf = vec![0u16; 256];
    let mut size = buf.len() as u32;
    let ok = unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut size) };
    if ok != 0 {
        from_wide(&buf[..size as usize])
    } else {
        "PC".to_string()
    }
}

pub fn cpu_count() -> u32 {
    let n = unsafe { GetActiveProcessorCount(0xFFFF) };
    if n == 0 {
        1
    } else {
        n
    }
}

pub fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok != 0 {
            Some(from_wide(&buf[..size as usize]))
        } else {
            None
        }
    }
}

pub fn process_times(pid: u32) -> Option<u64> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut c = FILETIME::default();
        let mut e = FILETIME::default();
        let mut k = FILETIME::default();
        let mut u = FILETIME::default();
        let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u);
        CloseHandle(h);
        if ok != 0 {
            Some(k.as_u64() + u.as_u64())
        } else {
            None
        }
    }
}

pub fn process_memory(pid: u32) -> Option<u64> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut c = PROCESS_MEMORY_COUNTERS::default();
        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = GetProcessMemoryInfo(h, &mut c, c.cb);
        CloseHandle(h);
        if ok != 0 {
            Some(c.WorkingSetSize as u64)
        } else {
            None
        }
    }
}

pub fn shell_open(target: &str, params: Option<&str>) -> bool {
    let file = to_wide(target);
    let op = to_wide("open");
    let p = params.map(to_wide);
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            file.as_ptr(),
            p.as_ref().map(|v| v.as_ptr()).unwrap_or(std::ptr::null()),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    r as isize > 32
}

/// Запуск процесса без окна, возвращает PID.
pub fn spawn_hidden(exe: &str, args: &str) -> Option<u32> {
    let mut cmd = to_wide(&format!("\"{exe}\" {args}"));
    let exe_w = to_wide(exe);
    let mut si = STARTUPINFOW::default();
    let mut pi = PROCESS_INFORMATION::default();
    let ok = unsafe {
        CreateProcessW(
            exe_w.as_ptr(),
            cmd.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return None;
    }
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Some(pi.dwProcessId)
}

/// Путь к системной утилите: `C:\Windows\System32\powercfg.exe`.
///
/// Создавать процесс по одному имени нельзя: `CreateProcessW` с непустым
/// `lpApplicationName` не ищет файл в `PATH`, и запуск молча не удаётся —
/// именно на этом ломались действия оптимизации.
pub fn system_tool(name: &str) -> String {
    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= buf.len() {
        return name.to_string();
    }
    let dir = String::from_utf16_lossy(&buf[..len]);
    format!("{dir}\\{name}")
}

/// Запускает системную утилиту и ждёт её завершения.
///
/// Возвращает код выхода или текст ошибки: без кода выхода нельзя отличить
/// «сделано» от «команда не выполнилась», а действия оптимизации как раз
/// этим и грешили.
pub fn run_system_tool(name: &str, args: &str) -> Result<u32, String> {
    let exe = system_tool(name);
    run_hidden_wait(&exe, args).ok_or_else(|| {
        let code = unsafe { GetLastError() };
        if code == 5 {
            "нужны права администратора".to_string()
        } else {
            format!("не удалось запустить {name} (код {code})")
        }
    })
}

pub fn kill(pid: u32) -> bool {
    unsafe {
        let h = OpenProcess(0x0001, 0, pid); // PROCESS_TERMINATE
        if h.is_null() {
            return false;
        }
        let ok = TerminateProcess(h, 1);
        CloseHandle(h);
        ok != 0
    }
}

/// Живой ли процесс.
///
/// `GetExitCodeProcess` возвращает `STILL_ACTIVE` (259) для работающего
/// процесса; для завершившегося — его код выхода.
pub fn process_alive(pid: u32) -> bool {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == STILL_ACTIVE
    }
}

/// Запуск процесса без окна с ожиданием завершения. Возвращает код выхода.
///
/// Нужен для консольных утилит вроде `avp.com`: они пишут отчёт и только потом
/// завершаются, поэтому читать результат можно лишь после ожидания.
pub fn run_hidden_wait(exe: &str, args: &str) -> Option<u32> {
    let mut cmd = to_wide(&format!("\"{exe}\" {args}"));
    let exe_w = to_wide(exe);
    let mut si = STARTUPINFOW::default();
    let mut pi = PROCESS_INFORMATION::default();
    let ok = unsafe {
        CreateProcessW(
            exe_w.as_ptr(),
            cmd.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return None;
    }
    unsafe {
        // INFINITE: сканирование может идти минутами.
        WaitForSingleObject(pi.hProcess, 0xFFFF_FFFF);
        let mut code: u32 = 0;
        let got = GetExitCodeProcess(pi.hProcess, &mut code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if got == 0 {
            None
        } else {
            Some(code)
        }
    }
}

pub fn system_dir() -> String {
    let mut buf = vec![0u16; 512];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    from_wide(&buf[..n as usize])
}

pub fn windows_dir() -> String {
    let mut buf = vec![0u16; 512];
    let n = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    from_wide(&buf[..n as usize])
}

// ---------- Окна ----------

pub type WNDENUMPROC = unsafe extern "system" fn(HWND, isize) -> BOOL;

#[link(name = "user32")]
extern "system" {
    pub fn EnumWindows(callback: WNDENUMPROC, param: isize) -> BOOL;
    pub fn IsWindowVisible(hwnd: HWND) -> BOOL;
    pub fn GetWindowTextW(hwnd: HWND, buf: LPWSTR, size: i32) -> i32;
    pub fn GetWindowThreadProcessId(hwnd: HWND, pid: *mut u32) -> u32;
    pub fn MessageBoxW(hwnd: HWND, text: LPCWSTR, caption: LPCWSTR, kind: u32) -> i32;
}

/// Есть ли видимое окно, заголовок которого содержит `needle`.
pub fn window_with_title_exists(needle: &str) -> bool {
    struct Ctx {
        needle: String,
        found: bool,
    }

    unsafe extern "system" fn callback(hwnd: HWND, param: isize) -> BOOL {
        let ctx = &mut *(param as *mut Ctx);
        if IsWindowVisible(hwnd) == 0 {
            return 1;
        }
        let mut buf = [0u16; 512];
        let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        if len <= 0 {
            return 1;
        }
        let title = from_wide(&buf[..len as usize]);
        if title.contains(&ctx.needle) {
            ctx.found = true;
            return 0; // останавливаем перебор
        }
        1
    }

    let mut ctx = Ctx {
        needle: needle.to_string(),
        found: false,
    };
    unsafe {
        EnumWindows(callback, &mut ctx as *mut Ctx as isize);
    }
    ctx.found
}

// ---------- Консоль для CLI-режимов ----------
// Release-сборка использует подсистему windows, поэтому своей консоли нет:
// подключаемся к консоли родителя и пишем в неё через WriteConsoleW (Unicode).

const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;

#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(pid: u32) -> BOOL;
    fn WriteConsoleW(h: HANDLE, buf: *const u16, len: u32, written: *mut u32, reserved: *mut c_void) -> BOOL;
    fn GetConsoleMode(h: HANDLE, mode: *mut u32) -> BOOL;
    fn WriteFile(h: HANDLE, buf: *const u8, len: u32, written: *mut u32, overlapped: *mut c_void) -> BOOL;
    fn CreateFileW(
        name: LPCWSTR,
        access: u32,
        share: u32,
        sa: *mut c_void,
        disposition: u32,
        flags: u32,
        template: HANDLE,
    ) -> HANDLE;
}

pub fn attach_console() -> bool {
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) != 0 }
}

pub fn con_print(text: &str) {
    unsafe {
        let mut handle = GetStdHandle(0xFFFF_FFF5); // STD_OUTPUT_HANDLE
        let mut mode: u32 = 0;
        let valid = !handle.is_null() && handle != INVALID_HANDLE_VALUE;
        let has_console = valid && GetConsoleMode(handle, &mut mode) != 0;
        if !has_console && valid {
            // Вывод перенаправлен в файл или канал: пишем байтами, иначе
            // `--scan > файл` молча терял бы весь результат.
            let mut line = text.as_bytes().to_vec();
            line.extend_from_slice(b"\r\n");
            let mut written = 0u32;
            WriteFile(handle, line.as_ptr(), line.len() as u32, &mut written, std::ptr::null_mut());
            return;
        }
        if !has_console {
            let name = to_wide("CONOUT$");
            handle = CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                3,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return;
        }
        let wide: Vec<u16> = text.encode_utf16().collect();
        let mut written = 0u32;
        WriteConsoleW(handle, wide.as_ptr(), wide.len() as u32, &mut written, std::ptr::null_mut());
        let nl = [13u16, 10u16];
        WriteConsoleW(handle, nl.as_ptr(), 2, &mut written, std::ptr::null_mut());
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(kind: u32) -> HANDLE;
}

/// Динамическая загрузка функции из DLL.
pub struct DynLib {
    handle: HANDLE,
}

impl DynLib {
    pub fn load(name: &str) -> Option<DynLib> {
        let w = to_wide(name);
        let h = unsafe { LoadLibraryW(w.as_ptr()) };
        if h.is_null() {
            None
        } else {
            Some(DynLib { handle: h })
        }
    }

    pub fn sym(&self, name: &str) -> Option<*mut c_void> {
        let mut c = Vec::with_capacity(name.len() + 1);
        c.extend_from_slice(name.as_bytes());
        c.push(0);
        let p = unsafe { GetProcAddress(self.handle, c.as_ptr()) };
        if p.is_null() {
            None
        } else {
            Some(p)
        }
    }
}

impl Drop for DynLib {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.handle);
        }
    }
}
