//! Ярлыки Windows (IShellLinkW) и известные папки — через COM, без внешних зависимостей.

#![allow(non_snake_case, clippy::upper_case_acronyms)]

use crate::win::{to_wide, DynLib};
use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct GUID {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

const CLSID_SHELL_LINK: GUID = GUID {
    d1: 0x0002_1401,
    d2: 0,
    d3: 0,
    d4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
};
const IID_ISHELL_LINK_W: GUID = GUID {
    d1: 0x0002_14F9,
    d2: 0,
    d3: 0,
    d4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
};
const IID_IPERSIST_FILE: GUID = GUID {
    d1: 0x0000_010b,
    d2: 0,
    d3: 0,
    d4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
};

// RFD_*: известные папки
const FOLDERID_DESKTOP: GUID = GUID {
    d1: 0xB4BF_CC3A,
    d2: 0xDB2C,
    d3: 0x424C,
    d4: [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41],
};
const FOLDERID_PROGRAMS: GUID = GUID {
    d1: 0xA77F_5D77,
    d2: 0x2E2B,
    d3: 0x44C3,
    d4: [0xA6, 0xA2, 0xAB, 0xA6, 0x01, 0x05, 0x4A, 0x51],
};

type CoInitializeEx = unsafe extern "system" fn(*mut c_void, u32) -> i32;
type CoCreateInstance =
    unsafe extern "system" fn(*const GUID, *mut c_void, u32, *const GUID, *mut *mut c_void) -> i32;
type CoTaskMemFree = unsafe extern "system" fn(*mut c_void);
type SHGetKnownFolderPath =
    unsafe extern "system" fn(*const GUID, u32, *mut c_void, *mut *mut u16) -> i32;

struct Com {
    _ole: DynLib,
    _shell: DynLib,
    _co_init: CoInitializeEx,
    co_create: CoCreateInstance,
    co_free: CoTaskMemFree,
    known_folder: SHGetKnownFolderPath,
}

impl Com {
    fn new() -> Option<Com> {
        let ole = DynLib::load("ole32.dll")?;
        let shell = DynLib::load("shell32.dll")?;
        unsafe {
            let co_init: CoInitializeEx = std::mem::transmute(ole.sym("CoInitializeEx")?);
            let co_create: CoCreateInstance = std::mem::transmute(ole.sym("CoCreateInstance")?);
            let co_free: CoTaskMemFree = std::mem::transmute(ole.sym("CoTaskMemFree")?);
            let known_folder: SHGetKnownFolderPath =
                std::mem::transmute(shell.sym("SHGetKnownFolderPath")?);
            // COINIT_APARTMENTTHREADED = 2; RPC_E_CHANGED_MODE (0x80010106) допустим.
            co_init(std::ptr::null_mut(), 2);
            Some(Com {
                _ole: ole,
                _shell: shell,
                _co_init: co_init,
                co_create,
                co_free,
                known_folder,
            })
        }
    }

    fn folder(&self, id: &GUID) -> Option<String> {
        unsafe {
            let mut raw: *mut u16 = std::ptr::null_mut();
            if (self.known_folder)(id, 0, std::ptr::null_mut(), &mut raw) != 0 || raw.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *raw.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(raw, len);
            let path = String::from_utf16_lossy(slice);
            (self.co_free)(raw as *mut c_void);
            Some(path)
        }
    }
}

unsafe fn vtable_fn(ptr: *mut c_void, index: usize) -> *mut c_void {
    let vtbl = *(ptr as *mut *mut *mut c_void);
    *vtbl.add(index)
}

unsafe fn release(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let f: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(vtable_fn(ptr, 2));
    f(ptr);
}

pub struct Shortcut {
    pub path: String,
    pub target: String,
    pub args: String,
    pub workdir: String,
    pub description: String,
    pub icon: Option<String>,
}

/// Создаёт .lnk через IShellLinkW + IPersistFile.
pub fn create_shortcut(link: &Shortcut) -> Result<(), String> {
    let com = Com::new().ok_or("не удалось загрузить COM")?;
    unsafe {
        let mut shell_link: *mut c_void = std::ptr::null_mut();
        let hr = (com.co_create)(
            &CLSID_SHELL_LINK,
            std::ptr::null_mut(),
            1, // CLSCTX_INPROC_SERVER
            &IID_ISHELL_LINK_W,
            &mut shell_link,
        );
        if hr != 0 || shell_link.is_null() {
            return Err(format!("CoCreateInstance(ShellLink) → 0x{hr:08X}"));
        }

        // IShellLinkW: 20 = SetPath, 9 = SetWorkingDirectory, 11 = SetArguments,
        // 7 = SetDescription, 17 = SetIconLocation
        let set_path: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 =
            std::mem::transmute(vtable_fn(shell_link, 20));
        let set_workdir: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 =
            std::mem::transmute(vtable_fn(shell_link, 9));
        let set_args: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 =
            std::mem::transmute(vtable_fn(shell_link, 11));
        let set_desc: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 =
            std::mem::transmute(vtable_fn(shell_link, 7));
        let set_icon: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32 =
            std::mem::transmute(vtable_fn(shell_link, 17));

        let target = to_wide(&link.target);
        set_path(shell_link, target.as_ptr());

        if !link.workdir.is_empty() {
            let workdir = to_wide(&link.workdir);
            set_workdir(shell_link, workdir.as_ptr());
        }
        if !link.args.is_empty() {
            let args = to_wide(&link.args);
            set_args(shell_link, args.as_ptr());
        }
        if !link.description.is_empty() {
            let desc = to_wide(&link.description);
            set_desc(shell_link, desc.as_ptr());
        }
        if let Some(icon) = &link.icon {
            let icon_w = to_wide(icon);
            set_icon(shell_link, icon_w.as_ptr(), 0);
        }

        // QueryInterface → IPersistFile
        let query: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32 =
            std::mem::transmute(vtable_fn(shell_link, 0));
        let mut persist: *mut c_void = std::ptr::null_mut();
        let hr = query(shell_link, &IID_IPERSIST_FILE, &mut persist);
        if hr != 0 || persist.is_null() {
            release(shell_link);
            return Err(format!("QueryInterface(IPersistFile) → 0x{hr:08X}"));
        }

        // IPersistFile::Save = индекс 6
        let save: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32 =
            std::mem::transmute(vtable_fn(persist, 6));
        let path = to_wide(&link.path);
        let hr = save(persist, path.as_ptr(), 1);

        release(persist);
        release(shell_link);

        if hr != 0 {
            return Err(format!("IPersistFile::Save → 0x{hr:08X}"));
        }
        Ok(())
    }
}

pub fn desktop_dir() -> Option<String> {
    Com::new()?.folder(&FOLDERID_DESKTOP)
}

pub fn start_menu_dir() -> Option<String> {
    Com::new()?.folder(&FOLDERID_PROGRAMS)
}
