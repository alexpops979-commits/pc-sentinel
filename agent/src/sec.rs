//! Безопасность: подписи, автозапуск, сетевые соединения, эвристика, SHA-256.

use crate::json::J;
use crate::rules::Rules;
use crate::sys::ProcInfo;
use crate::win::*;
use std::ffi::c_void;

#[derive(Clone, Default)]
pub struct Finding {
    pub id: String,
    pub severity: String, // critical | warning | info | ok
    pub title: String,
    pub detail: String,
    pub path: String,
    pub pid: u32,
    pub hash: String,
    pub signed: Option<bool>,
    pub recommendation: String,
    pub kind: String, // miner | trojan | persistence | unsigned | anomaly | hygiene
}

impl Finding {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("id", J::s(self.id.clone())),
            ("severity", J::s(self.severity.clone())),
            ("title", J::s(self.title.clone())),
            ("detail", J::s(self.detail.clone())),
            ("path", J::s(self.path.clone())),
            ("pid", J::Int(self.pid as i64)),
            ("hash", J::s(self.hash.clone())),
            (
                "signed",
                match self.signed {
                    Some(true) => J::Bool(true),
                    Some(false) => J::Bool(false),
                    None => J::Null,
                },
            ),
            ("recommendation", J::s(self.recommendation.clone())),
            ("kind", J::s(self.kind.clone())),
        ])
    }
}

// ------------------------- SHA-256 -------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h;
        for i in 0..64 {
            let s1 = a[4].rotate_right(6) ^ a[4].rotate_right(11) ^ a[4].rotate_right(25);
            let ch = (a[4] & a[5]) ^ (!a[4] & a[6]);
            let t1 = a[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a[0].rotate_right(2) ^ a[0].rotate_right(13) ^ a[0].rotate_right(22);
            let maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
            let t2 = s0.wrapping_add(maj);
            a[7] = a[6];
            a[6] = a[5];
            a[5] = a[4];
            a[4] = a[3].wrapping_add(t1);
            a[3] = a[2];
            a[2] = a[1];
            a[1] = a[0];
            a[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(a[i]);
        }
    }
    h.iter().map(|v| format!("{v:08x}")).collect()
}

pub fn hash_file(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    if data.len() > 400 * 1024 * 1024 {
        return None;
    }
    Some(sha256_hex(&data))
}

// ------------------------- Подпись файла -------------------------

#[repr(C)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

#[repr(C)]
struct WintrustFileInfo {
    cb_struct: u32,
    file_path: LPCWSTR,
    file_handle: HANDLE,
    known_subject: *mut Guid,
}

#[repr(C)]
struct WintrustData {
    cb_struct: u32,
    policy_callback: *mut c_void,
    sip_client: *mut c_void,
    ui_choice: u32,
    revocation_checks: u32,
    union_choice: u32,
    file: *mut WintrustFileInfo,
    state_action: u32,
    state_data: HANDLE,
    url_reference: LPCWSTR,
    prov_flags: u32,
    ui_context: u32,
    signature_settings: *mut c_void,
}

type WinVerifyTrust = unsafe extern "system" fn(HWND, *mut Guid, *mut c_void) -> i32;

pub fn verify_raw(path: &str) -> Option<i32> {
    let lib = DynLib::load("wintrust.dll")?;
    let func: WinVerifyTrust = unsafe { std::mem::transmute(lib.sym("WinVerifyTrust")?) };
    let mut action = Guid {
        d1: 0x00AA_C56B,
        d2: 0xCD44,
        d3: 0x11d0,
        d4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };
    let wpath = to_wide(path);
    let mut file = WintrustFileInfo {
        cb_struct: std::mem::size_of::<WintrustFileInfo>() as u32,
        file_path: wpath.as_ptr(),
        file_handle: std::ptr::null_mut(),
        known_subject: std::ptr::null_mut(),
    };
    let mut data = WintrustData {
        cb_struct: std::mem::size_of::<WintrustData>() as u32,
        policy_callback: std::ptr::null_mut(),
        sip_client: std::ptr::null_mut(),
        ui_choice: 2,           // WTD_UI_NONE
        revocation_checks: 0,   // WTD_REVOKE_NONE
        union_choice: 1,        // WTD_CHOICE_FILE
        file: &mut file,
        state_action: 1,        // WTD_STATEACTION_VERIFY
        state_data: std::ptr::null_mut(),
        url_reference: std::ptr::null(),
        prov_flags: 0x100,      // WTD_SAFER_FLAG
        ui_context: 0,
        signature_settings: std::ptr::null_mut(),
    };
    let rc = unsafe {
        func(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WintrustData as *mut c_void,
        )
    };
    data.state_action = 2; // WTD_STATEACTION_CLOSE
    unsafe {
        func(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WintrustData as *mut c_void,
        );
    }
    Some(rc)
}

const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;

pub fn verify_signature(path: &str) -> Option<bool> {
    match verify_raw(path) {
        Some(0) => Some(true),
        // У системных файлов подпись хранится в каталоге, а не в самом файле
        Some(TRUST_E_NOSIGNATURE) => Some(verify_catalog(path)),
        Some(_) => Some(false),
        None => None,
    }
}

// ------------------------- Проверка каталожной подписи -------------------------

#[repr(C)]
struct CatalogInfo {
    cb_struct: u32,
    catalog_file: [u16; 260],
}

#[repr(C)]
struct WintrustCatalogInfo {
    cb_struct: u32,
    catalog_version: u32,
    catalog_file_path: LPCWSTR,
    member_tag: LPCWSTR,
    member_file_path: LPCWSTR,
    member_file: HANDLE,
    calculated_hash: *mut u8,
    calculated_hash_len: u32,
    catalog_context: *mut c_void,
    cat_admin: HANDLE,
}

type CatAdminAcquireContext2 =
    unsafe extern "system" fn(*mut HANDLE, *const Guid, LPCWSTR, *const c_void, u32) -> BOOL;
type CatAdminCalcHash2 =
    unsafe extern "system" fn(HANDLE, HANDLE, *mut u32, *mut u8, u32) -> BOOL;
type CatAdminEnumCatalog =
    unsafe extern "system" fn(HANDLE, *mut u8, u32, u32, *mut HANDLE) -> HANDLE;
type CatCatalogInfoFromContext = unsafe extern "system" fn(HANDLE, *mut CatalogInfo, u32) -> BOOL;
type CatAdminReleaseCatalogContext = unsafe extern "system" fn(HANDLE, HANDLE, u32) -> BOOL;
type CatAdminReleaseContext = unsafe extern "system" fn(HANDLE, u32) -> BOOL;

fn verify_catalog(path: &str) -> bool {
    use std::os::windows::io::AsRawHandle;
    let lib = match DynLib::load("wintrust.dll") {
        Some(l) => l,
        None => return false,
    };
    unsafe {
        let acquire: CatAdminAcquireContext2 =
            match lib.sym("CryptCATAdminAcquireContext2").map(|p| std::mem::transmute(p)) {
                Some(f) => f,
                None => return false,
            };
        let calc: CatAdminCalcHash2 =
            match lib.sym("CryptCATAdminCalcHashFromFileHandle2").map(|p| std::mem::transmute(p)) {
                Some(f) => f,
                None => return false,
            };
        let enumerate: CatAdminEnumCatalog =
            match lib.sym("CryptCATAdminEnumCatalogFromHash").map(|p| std::mem::transmute(p)) {
                Some(f) => f,
                None => return false,
            };
        let info: CatCatalogInfoFromContext =
            match lib.sym("CryptCATCatalogInfoFromContext").map(|p| std::mem::transmute(p)) {
                Some(f) => f,
                None => return false,
            };
        let release_catalog: CatAdminReleaseCatalogContext = match lib
            .sym("CryptCATAdminReleaseCatalogContext")
            .map(|p| std::mem::transmute(p))
        {
            Some(f) => f,
            None => return false,
        };
        let release_admin: CatAdminReleaseContext =
            match lib.sym("CryptCATAdminReleaseContext").map(|p| std::mem::transmute(p)) {
                Some(f) => f,
                None => return false,
            };
        let verify: WinVerifyTrust = match lib.sym("WinVerifyTrust").map(|p| std::mem::transmute(p)) {
            Some(f) => f,
            None => return false,
        };

        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let algo = to_wide("SHA256");
        let mut admin: HANDLE = std::ptr::null_mut();
        if acquire(
            &mut admin,
            std::ptr::null(),
            algo.as_ptr(),
            std::ptr::null(),
            0,
        ) == 0
        {
            return false;
        }

        let mut hash_len: u32 = 64;
        let mut hash = vec![0u8; 64];
        if calc(admin, file.as_raw_handle() as HANDLE, &mut hash_len, hash.as_mut_ptr(), 0) == 0 {
            release_admin(admin, 0);
            return false;
        }

        let mut cat: HANDLE = std::ptr::null_mut();
        let handle = enumerate(admin, hash.as_mut_ptr(), hash_len, 0, &mut cat);
        if handle.is_null() {
            release_admin(admin, 0);
            return false;
        }

        let mut cat_info = CatalogInfo {
            cb_struct: std::mem::size_of::<CatalogInfo>() as u32,
            catalog_file: [0; 260],
        };
        if info(handle, &mut cat_info, 0) == 0 {
            release_catalog(admin, handle, 0);
            release_admin(admin, 0);
            return false;
        }

        let wpath = to_wide(path);
        let member = std::path::Path::new(path)
            .file_name()
            .map(|n| to_wide(&n.to_string_lossy()))
            .unwrap_or_else(|| to_wide(""));
        let mut action = Guid {
            d1: 0x00AA_C56B,
            d2: 0xCD44,
            d3: 0x11d0,
            d4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
        };
        let mut catalog = WintrustCatalogInfo {
            cb_struct: std::mem::size_of::<WintrustCatalogInfo>() as u32,
            catalog_version: 0,
            catalog_file_path: cat_info.catalog_file.as_ptr(),
            member_tag: member.as_ptr(),
            member_file_path: wpath.as_ptr(),
            member_file: std::ptr::null_mut(),
            calculated_hash: hash.as_mut_ptr(),
            calculated_hash_len: hash_len,
            catalog_context: std::ptr::null_mut(),
            cat_admin: admin,
        };
        let mut data = WintrustData {
            cb_struct: std::mem::size_of::<WintrustData>() as u32,
            policy_callback: std::ptr::null_mut(),
            sip_client: std::ptr::null_mut(),
            ui_choice: 2,
            revocation_checks: 0,
            union_choice: 2, // WTD_CHOICE_CATALOG
            file: &mut catalog as *mut WintrustCatalogInfo as *mut WintrustFileInfo,
            state_action: 1,
            state_data: std::ptr::null_mut(),
            url_reference: std::ptr::null(),
            prov_flags: 0x100,
            ui_context: 0,
            signature_settings: std::ptr::null_mut(),
        };
        let rc = verify(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WintrustData as *mut c_void,
        );
        data.state_action = 2;
        verify(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WintrustData as *mut c_void,
        );
        release_catalog(admin, handle, 0);
        release_admin(admin, 0);
        rc == 0
    }
}

// ------------------------- Эвристика -------------------------

fn lower(p: &str) -> String {
    p.to_ascii_lowercase()
}

pub fn is_user_writable(path: &str, rules: &Rules) -> bool {
    rules.is_user_writable(path)
}

pub fn looks_like_miner(name: &str, cmd: &str, rules: &Rules) -> bool {
    rules.is_miner_name(name) || rules.is_miner_arg(cmd)
}

pub fn is_system_path(path: &str) -> bool {
    let p = lower(&path.replace('/', "\\"));
    if p.is_empty() {
        return true;
    }
    p.contains("\\windows\\system32\\")
        || p.contains("\\windows\\syswow64\\")
        || p.contains("\\windows\\winsxs\\")
        || p.contains("\\program files\\")
        || p.contains("\\program files (x86)\\")
        || p.contains("\\windows\\")
}

/// Быстрый анализ списка процессов: возвращает подозрительные находки.
pub fn analyze_processes(procs: &[ProcInfo], rules: &Rules) -> (Vec<Finding>, u32, u32) {
    let mut findings = Vec::new();
    let mut signed_count = 0;
    let mut unsigned_count = 0;

    for p in procs {
        if p.path.is_empty() || p.pid <= 4 {
            continue;
        }
        let sig = verify_signature(&p.path);
        match sig {
            Some(true) => signed_count += 1,
            Some(false) => unsigned_count += 1,
            None => {}
        }

        let miner = looks_like_miner(&p.name, &p.path, rules);
        if miner {
            findings.push(Finding {
                id: format!("miner-{}", p.pid),
                severity: "critical".into(),
                title: format!("Признаки майнера: {}", p.name),
                detail: format!(
                    "Процесс PID {} запущен из {} и совпадает с шаблоном известных майнеров.",
                    p.pid, p.path
                ),
                path: p.path.clone(),
                pid: p.pid,
                hash: hash_file(&p.path).unwrap_or_default(),
                signed: sig,
                recommendation: "Завершите процесс и проверьте автозагрузку. Если файл вам неизвестен — отправьте его в карантин.".into(),
                kind: "miner".into(),
            });
            continue;
        }

        if sig == Some(false) && is_user_writable(&p.path, rules) {
            let severity = if p.cpu > 12.0 { "critical" } else { "warning" };
            findings.push(Finding {
                id: format!("unsigned-{}", p.pid),
                severity: severity.into(),
                title: format!("Неподписанный процесс из пользовательской папки: {}", p.name),
                detail: format!(
                    "PID {} · {} · загрузка CPU {:.1}%. Файл без цифровой подписи запускается из временной или пользовательской директории.",
                    p.pid, p.path, p.cpu
                ),
                path: p.path.clone(),
                pid: p.pid,
                hash: hash_file(&p.path).unwrap_or_default(),
                signed: sig,
                recommendation: "Проверьте происхождение файла. При сомнениях завершите процесс через диспетчер.".into(),
                kind: "unsigned".into(),
            });
        }
    }
    (findings, signed_count, unsigned_count)
}

// ------------------------- Автозапуск -------------------------

#[derive(Clone, Default)]
pub struct Autorun {
    pub name: String,
    pub command: String,
    pub location: String,
    pub hive: String,
    pub key: String,
    pub exists: bool,
    pub suspicious: bool,
}

impl Autorun {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("name", J::s(self.name.clone())),
            ("command", J::s(self.command.clone())),
            ("location", J::s(self.location.clone())),
            ("hive", J::s(self.hive.clone())),
            ("key", J::s(self.key.clone())),
            ("exists", J::Bool(self.exists)),
            ("suspicious", J::Bool(self.suspicious)),
        ])
    }
}

const RUN_KEYS: [(&str, usize, &str); 5] = [
    ("HKLM\\Run", HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("HKLM\\Run (x32)", HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("HKCU\\Run", HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("HKLM\\RunOnce", HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("HKCU\\RunOnce", HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
];

pub fn autoruns(rules: &Rules) -> Vec<Autorun> {
    let mut out = Vec::new();
    for (label, root, path) in RUN_KEYS {
        out.extend(enum_run_key(label, root, path, rules));
    }
    out.extend(enum_startup_folder("Startup (пользователь)", "APPDATA", "Microsoft\\Windows\\Start Menu\\Programs\\Startup", rules));
    out.extend(enum_startup_folder("Startup (общие)", "ProgramData", "Microsoft\\Windows\\Start Menu\\Programs\\Startup", rules));
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

fn enum_run_key(label: &str, root: usize, path: &str, rules: &Rules) -> Vec<Autorun> {
    let mut out = Vec::new();
    unsafe {
        let wpath = to_wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wpath.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return out;
        }
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; 512];
            let mut name_len: u32 = 512;
            let mut kind: u32 = 0;
            let mut data = vec![0u8; 4096];
            let mut data_len: u32 = data.len() as u32;
            let rc = RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            );
            if rc == ERROR_NO_MORE_ITEMS as i32 {
                break;
            }
            if rc != 0 {
                index += 1;
                if index > 400 {
                    break;
                }
                continue;
            }
            index += 1;
            let name_s = from_wide(&name[..name_len as usize]);
            if name_s.is_empty() {
                continue;
            }
            let command = if kind == REG_SZ || kind == REG_EXPAND_SZ {
                let wide: Vec<u16> = data[..data_len as usize]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                from_wide(&wide)
            } else {
                String::from("<не строка>")
            };
            let exe = extract_exe(&expand_env(&command));
            let exists = exe.is_empty() || std::path::Path::new(&exe).exists();
            let suspicious = rules.is_script_launch(&command)
                || (!exe.is_empty()
                    && (is_user_writable(&exe, rules) || verify_signature(&exe) == Some(false)));
            out.push(Autorun {
                name: name_s,
                command,
                location: label.to_string(),
                hive: if root == HKEY_LOCAL_MACHINE { "HKLM".into() } else { "HKCU".into() },
                key: path.to_string(),
                exists,
                suspicious,
            });
        }
        RegCloseKey(key);
    }
    out
}

fn enum_startup_folder(label: &str, env: &str, sub: &str, rules: &Rules) -> Vec<Autorun> {
    let mut out = Vec::new();
    let base = match env_var(env) {
        Some(v) => v,
        None => return out,
    };
    let dir = format!("{base}\\{sub}");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.to_lowercase() == "desktop.ini" {
                continue;
            }
            let full = path.to_string_lossy().to_string();
            out.push(Autorun {
                name,
                command: full.clone(),
                location: label.to_string(),
                hive: env.to_string(),
                key: dir.clone(),
                exists: true,
                suspicious: is_user_writable(&full, rules) && verify_signature(&full) == Some(false),
            });
        }
    }
    out
}

pub fn extract_exe(command: &str) -> String {
    let c = command.trim();
    if let Some(rest) = c.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    let lower = c.to_ascii_lowercase();
    for needle in [".exe", ".com", ".bat", ".cmd", ".vbs", ".ps1", ".dll"] {
        if let Some(pos) = lower.find(needle) {
            return c[..pos + needle.len()].to_string();
        }
    }
    c.split_whitespace().next().unwrap_or("").to_string()
}

// ------------------------- Сетевые соединения -------------------------

#[derive(Clone, Default)]
pub struct Conn {
    pub pid: u32,
    pub proc: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub remote_ip: String,
}

impl Conn {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("pid", J::Int(self.pid as i64)),
            ("proc", J::s(self.proc.clone())),
            ("local", J::s(self.local.clone())),
            ("remote", J::s(self.remote.clone())),
            ("state", J::s(self.state.clone())),
            ("remoteIp", J::s(self.remote_ip.clone())),
        ])
    }
}

fn ip_string(addr: u32) -> String {
    let b = addr.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn port_of(raw: u32) -> u16 {
    (((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)) as u16
}

fn state_name(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "SYN_SENT",
        3 => "SYN_RCVD",
        4 => "ESTABLISHED",
        5 => "FIN_WAIT1",
        6 => "FIN_WAIT2",
        7 => "CLOSE_WAIT",
        8 => "LAST_ACK",
        9 => "LISTEN",
        10 => "CLOSING",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

pub fn connections() -> Vec<Conn> {
    let mut out = Vec::new();
    unsafe {
        let mut size: u32 = 0;
        let rc = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize + 64];
        let mut size2 = buf.len() as u32;
        let rc2 = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut c_void,
            &mut size2,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc2 != 0 {
            return out;
        }
        let entries = *(buf.as_ptr() as *const u32) as usize;
        let rows = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
        for i in 0..entries.min(2048) {
            let row = &*rows.add(i);
            let local_ip = ip_string(row.dwLocalAddr);
            let remote_ip = ip_string(row.dwRemoteAddr);
            let local = format!("{}:{}", local_ip, port_of(row.dwLocalPort));
            let remote = format!("{}:{}", remote_ip, port_of(row.dwRemotePort));
            out.push(Conn {
                pid: row.dwOwningPid,
                proc: String::new(),
                local,
                remote,
                state: state_name(row.dwState).to_string(),
                remote_ip,
            });
        }
    }
    out
}

pub fn attach_process_names(conns: &mut [Conn], procs: &[ProcInfo]) {
    for c in conns.iter_mut() {
        if let Some(p) = procs.iter().find(|p| p.pid == c.pid) {
            c.proc = p.name.clone();
        }
    }
}

// ------------------------- Отчёт проверки -------------------------

pub struct ScanReport {
    pub started: u64,
    pub duration_ms: u64,
    pub checked: usize,
    pub signed: u32,
    pub unsigned: u32,
    pub threats: Vec<Finding>,
    pub autoruns: Vec<Autorun>,
    pub risky_conns: Vec<Conn>,
}

impl ScanReport {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("startedAt", J::Int(self.started as i64)),
            ("durationMs", J::Int(self.duration_ms as i64)),
            ("checked", J::Int(self.checked as i64)),
            ("signed", J::Int(self.signed as i64)),
            ("unsigned", J::Int(self.unsigned as i64)),
            ("score", J::num(self.score())),
            ("coverage", J::num(self.coverage() * 100.0)),
            (
                "skipped",
                J::Int(self.checked.saturating_sub((self.signed + self.unsigned) as usize) as i64),
            ),
            (
                "threats",
                J::Arr(self.threats.iter().map(|f| f.to_json()).collect()),
            ),
            (
                "autoruns",
                J::Arr(self.autoruns.iter().map(|a| a.to_json()).collect()),
            ),
            (
                "riskyConnections",
                J::Arr(self.risky_conns.iter().map(|c| c.to_json()).collect()),
            ),
        ])
    }

    /// Доля процессов, у которых удалось проверить подпись.
    /// Без прав администратора часть системных процессов недоступна.
    pub fn coverage(&self) -> f64 {
        if self.checked == 0 {
            return 0.0;
        }
        let verified = (self.signed + self.unsigned) as f64;
        (verified / self.checked as f64).clamp(0.0, 1.0)
    }

    pub fn score(&self) -> f64 {
        let mut score: f64 = 100.0;
        for t in &self.threats {
            score -= match t.severity.as_str() {
                "critical" => 18.0,
                "warning" => 7.0,
                _ => 1.0,
            };
        }
        let suspicious_autoruns = self.autoruns.iter().filter(|a| a.suspicious).count() as f64;
        score -= suspicious_autoruns * 4.0;
        score.clamp(0.0, 100.0)
    }
}
