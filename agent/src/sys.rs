//! Сбор системной телеметрии: CPU, RAM, диски, сеть, GPU, процессы.

use crate::json::J;
use crate::win::*;
use std::collections::HashMap;
use std::ffi::c_void;

#[derive(Clone, Default)]
pub struct CpuInfo {
    pub usage: f64,
    pub cores: u32,
    pub name: String,
    pub mhz: u32,
    /// Всего потоков в системе (как в диспетчере задач).
    pub threads: u32,
    /// Открытых дескрипторов.
    pub handles: u32,
    /// Число процессов.
    pub processes: u32,
}

#[derive(Clone, Default)]
pub struct MemInfo {
    pub total: u64,
    pub used: u64,
    pub percent: f64,
    /// Выделено (commit) и предел выделения — вкладка «Память» диспетчера задач.
    pub committed: u64,
    pub commit_limit: u64,
    /// Кэш и доступная память.
    pub cached: u64,
    pub available: u64,
    /// Пулы ядра.
    pub paged_pool: u64,
    pub nonpaged_pool: u64,
}

#[derive(Clone, Default)]
pub struct DiskInfo {
    pub letter: String,
    pub label: String,
    pub total: u64,
    pub free: u64,
    pub percent: f64,
    /// Активность диска, % (как «Активное время» в диспетчере задач).
    pub active: f64,
    pub read_bps: f64,
    pub write_bps: f64,
}

#[derive(Clone, Default)]
pub struct NetInfo {
    pub down_bps: f64,
    pub up_bps: f64,
    pub total_down: u64,
    pub total_up: u64,
}

#[derive(Clone, Default)]
pub struct GpuInfo {
    pub available: bool,
    pub name: String,
    pub vendor: String,
    pub usage: f64,
    pub mem_used: u64,
    pub mem_total: u64,
    pub temp: f64,
    pub clock: u32,
    pub fan: u32,
    pub power: f64,
}

#[derive(Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent: u32,
    pub name: String,
    pub path: String,
    pub cpu: f64,
    pub mem: u64,
    pub threads: u32,
    pub user: String,
}

pub struct Sampler {
    prev_cpu: Option<(u64, u64, u64)>,
    prev_net: u64,
    prev_proc: HashMap<u32, (u64, u64)>,
    paths: HashMap<u32, String>,
    net: Option<NetProbe>,
    disk: Option<DiskProbe>,
    total_down: u64,
    total_up: u64,
    cores: u32,
    cpu_name: String,
    gpu: Option<GpuProbe>,
    pub last: Option<Snapshot>,
    last_tick: u64,
}
#[derive(Default)]
pub struct Snapshot {
    pub cpu: CpuInfo,
    pub mem: MemInfo,
    pub disks: Vec<DiskInfo>,
    pub net: NetInfo,
    pub gpu: GpuInfo,
    pub procs: Vec<ProcInfo>,
    pub uptime: u64,
    pub host: String,
    pub os: String,
    pub ts: u64,
}

impl Snapshot {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("ts", J::Int(self.ts as i64)),
            ("host", J::s(self.host.clone())),
            ("os", J::s(self.os.clone())),
            ("uptime", J::Int(self.uptime as i64)),
            (
                "cpu",
                J::obj(vec![
                    ("usage", J::num(self.cpu.usage)),
                    ("cores", J::Int(self.cpu.cores as i64)),
                    ("name", J::s(self.cpu.name.clone())),
                    ("mhz", J::Int(self.cpu.mhz as i64)),
                    ("threads", J::Int(self.cpu.threads as i64)),
                    ("handles", J::Int(self.cpu.handles as i64)),
                    ("processes", J::Int(self.cpu.processes as i64)),
                ]),
            ),
            (
                "mem",
                J::obj(vec![
                    ("total", J::Int(self.mem.total as i64)),
                    ("used", J::Int(self.mem.used as i64)),
                    ("percent", J::num(self.mem.percent)),
                    ("committed", J::Int(self.mem.committed as i64)),
                    ("commitLimit", J::Int(self.mem.commit_limit as i64)),
                    ("cached", J::Int(self.mem.cached as i64)),
                    ("available", J::Int(self.mem.available as i64)),
                    ("pagedPool", J::Int(self.mem.paged_pool as i64)),
                    ("nonPagedPool", J::Int(self.mem.nonpaged_pool as i64)),
                ]),
            ),
            (
                "disks",
                J::Arr(
                    self.disks
                        .iter()
                        .map(|d| {
                            J::obj(vec![
                                ("letter", J::s(d.letter.clone())),
                                ("label", J::s(d.label.clone())),
                                ("total", J::Int(d.total as i64)),
                                ("free", J::Int(d.free as i64)),
                                ("percent", J::num(d.percent)),
                                ("active", J::num(d.active)),
                                ("readBps", J::num(d.read_bps)),
                                ("writeBps", J::num(d.write_bps)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "net",
                J::obj(vec![
                    ("down", J::num(self.net.down_bps)),
                    ("up", J::num(self.net.up_bps)),
                    ("totalDown", J::Int(self.net.total_down as i64)),
                    ("totalUp", J::Int(self.net.total_up as i64)),
                ]),
            ),
            (
                "gpu",
                J::obj(vec![
                    ("available", J::Bool(self.gpu.available)),
                    ("name", J::s(self.gpu.name.clone())),
                    ("vendor", J::s(self.gpu.vendor.clone())),
                    ("usage", J::num(self.gpu.usage)),
                    ("memUsed", J::Int(self.gpu.mem_used as i64)),
                    ("memTotal", J::Int(self.gpu.mem_total as i64)),
                    ("temp", J::num(self.gpu.temp)),
                    ("clock", J::Int(self.gpu.clock as i64)),
                    ("fan", J::Int(self.gpu.fan as i64)),
                    ("power", J::num(self.gpu.power)),
                ]),
            ),
            (
                "procs",
                J::Arr(self.procs.iter().map(proc_json).collect()),
            ),
        ])
    }
}

pub fn proc_json(p: &ProcInfo) -> J {
    J::obj(vec![
        ("pid", J::Int(p.pid as i64)),
        ("parent", J::Int(p.parent as i64)),
        ("name", J::s(p.name.clone())),
        ("path", J::s(p.path.clone())),
        ("cpu", J::num(p.cpu)),
        ("mem", J::Int(p.mem as i64)),
        ("threads", J::Int(p.threads as i64)),
        ("user", J::s(p.user.clone())),
    ])
}

impl Sampler {
    pub fn new() -> Sampler {
        let cores = cpu_count();
        Sampler {
            prev_cpu: None,
            prev_net: 0,
            prev_proc: HashMap::new(),
            paths: HashMap::new(),
            net: NetProbe::new(),
            disk: DiskProbe::new(),
            total_down: 0,
            total_up: 0,
            cores,
            cpu_name: cpu_brand(),
            gpu: GpuProbe::new(),
            last: None,
            last_tick: 0,
        }
    }

    pub fn sample(&mut self) -> &Snapshot {
        let now = unsafe { GetTickCount64() };
        let cached = self.last.is_some() && now.saturating_sub(self.last_tick) < 400;
        if !cached {
            let snap = self.collect(now);
            self.last = Some(snap);
            self.last_tick = now;
        }
        self.last.as_ref().unwrap()
    }

    fn collect(&mut self, now: u64) -> Snapshot {
        let cpu = self.sample_cpu();
        let mem = sample_mem();
        let mut disks = sample_disks();
        if let Some(probe) = self.disk.as_mut() {
            probe.apply(&mut disks);
        }
        let net = self.sample_net(now);
        let gpu = match &self.gpu {
            Some(g) => g.read(),
            None => GpuInfo::default(),
        };
        let procs = self.sample_procs(now);
        Snapshot {
            cpu,
            mem,
            disks,
            net,
            gpu,
            procs,
            uptime: now / 1000,
            host: computer_name(),
            os: os_name(),
            ts: now,
        }
    }

    fn sample_cpu(&mut self) -> CpuInfo {
        let mut idle = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
        let mut usage = 0.0;
        if ok != 0 {
            let cur = (idle.as_u64(), kernel.as_u64(), user.as_u64());
            if let Some(prev) = self.prev_cpu {
                let d_idle = cur.0.saturating_sub(prev.0) as f64;
                let d_kernel = cur.1.saturating_sub(prev.1) as f64;
                let d_user = cur.2.saturating_sub(prev.2) as f64;
                let total = d_kernel + d_user;
                if total > 0.0 {
                    usage = ((total - d_idle) / total * 100.0).clamp(0.0, 100.0);
                }
            }
            self.prev_cpu = Some(cur);
        }
        let perf = perf_info();
        CpuInfo {
            usage,
            cores: self.cores,
            name: self.cpu_name.clone(),
            mhz: cpu_mhz(),
            threads: perf.thread_count,
            handles: perf.handle_count,
            processes: perf.process_count,
        }
    }

    fn sample_net(&mut self, now: u64) -> NetInfo {
        let (down, up) = match &mut self.net {
            Some(n) => n.read(),
            None => (0.0, 0.0),
        };
        let dt = if self.prev_net > 0 {
            (now.saturating_sub(self.prev_net)) as f64 / 1000.0
        } else {
            0.0
        };
        self.prev_net = now;
        self.total_down += (down * dt) as u64;
        self.total_up += (up * dt) as u64;
        NetInfo {
            down_bps: down,
            up_bps: up,
            total_down: self.total_down,
            total_up: self.total_up,
        }
    }

    fn sample_procs(&mut self, now: u64) -> Vec<ProcInfo> {
        let mut out: Vec<ProcInfo> = Vec::new();
        let mut next: HashMap<u32, (u64, u64)> = HashMap::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut entry = PROCESSENTRY32W::default();
            let mut ok = Process32FirstW(snap, &mut entry);
            while ok != 0 {
                let pid = entry.th32ProcessID;
                if pid != 0 {
                    let name = from_wide(&entry.szExeFile);
                    let cpu_time = process_times(pid).unwrap_or(0);
                    let mem = process_memory(pid).unwrap_or(0);
                    let mut cpu = 0.0;
                    if let Some((prev_cpu, prev_tick)) = self.prev_proc.get(&pid) {
                        let dt = now.saturating_sub(*prev_tick) as f64 * 10_000.0;
                        if dt > 0.0 {
                            let used = cpu_time.saturating_sub(*prev_cpu) as f64;
                            // Делим на число ядер: диспетчер задач показывает долю
                            // от всей системы, а не от одного ядра. Иначе процесс,
                            // занявший одно ядро из восьми, выглядел бы как 100%.
                            let cores = self.cores.max(1) as f64;
                            cpu = (used / dt * 100.0 / cores).clamp(0.0, 100.0);
                        }
                    }
                    let path = match self.paths.get(&pid) {
                        Some(p) => p.clone(),
                        None => {
                            let p = process_path(pid).unwrap_or_default();
                            self.paths.insert(pid, p.clone());
                            p
                        }
                    };
                    next.insert(pid, (cpu_time, now));
                    out.push(ProcInfo {
                        pid,
                        parent: entry.th32ParentProcessID,
                        name,
                        path,
                        cpu,
                        mem,
                        threads: entry.cntThreads,
                        user: String::new(),
                    });
                }
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                ok = Process32NextW(snap, &mut entry);
            }
            CloseHandle(snap);
        }
        if self.paths.len() > 600 {
            self.paths.clear();
        }
        self.prev_proc = next;
        out.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
        out.truncate(90);
        out
    }
}

// ---------------- Сеть через PDH-счётчики ----------------

pub struct NetProbe {
    lib: DynLib,
    query: HANDLE,
    rx: HANDLE,
    tx: HANDLE,
    collect: PdhCollectQueryData,
    read_array: PdhGetFormattedCounterArrayW,
    close: PdhCloseQuery,
    primed: bool,
}

unsafe impl Send for NetProbe {}

impl NetProbe {
    pub fn new() -> Option<NetProbe> {
        let lib = DynLib::load("pdh.dll")?;
        unsafe {
            let open: PdhOpenQueryW = std::mem::transmute(lib.sym("PdhOpenQueryW")?);
            let add: PdhAddEnglishCounterW =
                std::mem::transmute(lib.sym("PdhAddEnglishCounterW")?);
            let collect: PdhCollectQueryData =
                std::mem::transmute(lib.sym("PdhCollectQueryData")?);
            let read_array: PdhGetFormattedCounterArrayW =
                std::mem::transmute(lib.sym("PdhGetFormattedCounterArrayW")?);
            let close: PdhCloseQuery = std::mem::transmute(lib.sym("PdhCloseQuery")?);

            let mut query: HANDLE = std::ptr::null_mut();
            if open(std::ptr::null(), 0, &mut query) != 0 {
                return None;
            }
            let rx_path = to_wide("\\Network Interface(*)\\Bytes Received/sec");
            let tx_path = to_wide("\\Network Interface(*)\\Bytes Sent/sec");
            let mut rx: HANDLE = std::ptr::null_mut();
            let mut tx: HANDLE = std::ptr::null_mut();
            if add(query, rx_path.as_ptr(), 0, &mut rx) != 0
                || add(query, tx_path.as_ptr(), 0, &mut tx) != 0
            {
                close(query);
                return None;
            }
            collect(query);
            Some(NetProbe {
                lib,
                query,
                rx,
                tx,
                collect,
                read_array,
                close,
                primed: false,
            })
        }
    }

    pub fn read(&mut self) -> (f64, f64) {
        unsafe {
            (self.collect)(self.query);
            if !self.primed {
                self.primed = true;
                return (0.0, 0.0);
            }
            let rx = sum_counter(self.read_array, self.rx);
            let tx = sum_counter(self.read_array, self.tx);
            (rx.max(0.0), tx.max(0.0))
        }
    }
}

impl Drop for NetProbe {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.query);
        }
        let _ = &self.lib;
    }
}

// ---------------- Диски через PDH-счётчики ----------------

/*
 * «Активное время», чтение и запись — те же счётчики PhysicalDisk, что
 * использует диспетчер задач. Имена экземпляров выглядят как «0 C:»,
 * поэтому сопоставляем их с буквами дисков.
 */
pub struct DiskProbe {
    lib: DynLib,
    query: HANDLE,
    active: HANDLE,
    read: HANDLE,
    write: HANDLE,
    collect: PdhCollectQueryData,
    read_array: PdhGetFormattedCounterArrayW,
    close: PdhCloseQuery,
    primed: bool,
}

unsafe impl Send for DiskProbe {}

impl DiskProbe {
    pub fn new() -> Option<DiskProbe> {
        let lib = DynLib::load("pdh.dll")?;
        unsafe {
            let open: PdhOpenQueryW = std::mem::transmute(lib.sym("PdhOpenQueryW")?);
            let add: PdhAddEnglishCounterW =
                std::mem::transmute(lib.sym("PdhAddEnglishCounterW")?);
            let collect: PdhCollectQueryData =
                std::mem::transmute(lib.sym("PdhCollectQueryData")?);
            let read_array: PdhGetFormattedCounterArrayW =
                std::mem::transmute(lib.sym("PdhGetFormattedCounterArrayW")?);
            let close: PdhCloseQuery = std::mem::transmute(lib.sym("PdhCloseQuery")?);

            let mut query: HANDLE = std::ptr::null_mut();
            if open(std::ptr::null(), 0, &mut query) != 0 {
                return None;
            }
            let mut active: HANDLE = std::ptr::null_mut();
            let mut read: HANDLE = std::ptr::null_mut();
            let mut write: HANDLE = std::ptr::null_mut();
            let paths = [
                "\\PhysicalDisk(*)\\% Disk Time",
                "\\PhysicalDisk(*)\\Disk Read Bytes/sec",
                "\\PhysicalDisk(*)\\Disk Write Bytes/sec",
            ];
            let mut handles = [&mut active, &mut read, &mut write];
            for (path, slot) in paths.iter().zip(handles.iter_mut()) {
                let w = to_wide(path);
                if add(query, w.as_ptr(), 0, *slot) != 0 {
                    close(query);
                    return None;
                }
            }
            collect(query);
            Some(DiskProbe {
                lib,
                query,
                active,
                read,
                write,
                collect,
                read_array,
                close,
                primed: false,
            })
        }
    }

    /// Дописывает активность и скорости в уже собранный список дисков.
    pub fn apply(&mut self, disks: &mut [DiskInfo]) {
        unsafe {
            (self.collect)(self.query);
            if !self.primed {
                self.primed = true;
                return;
            }
            let active = counter_items(self.read_array, self.active);
            let read = counter_items(self.read_array, self.read);
            let write = counter_items(self.read_array, self.write);
            for disk in disks.iter_mut() {
                let letter = disk.letter.chars().next().unwrap_or('C');
                let pick = |items: &[(String, f64)]| -> f64 {
                    items
                        .iter()
                        .find(|(name, _)| {
                            let upper = name.to_uppercase();
                            upper.ends_with(&format!(" {letter}:"))
                                || upper.ends_with(&format!("({letter}:)"))
                        })
                        .map(|(_, v)| *v)
                        .unwrap_or(0.0)
                };
                disk.active = pick(&active).clamp(0.0, 100.0);
                disk.read_bps = pick(&read).max(0.0);
                disk.write_bps = pick(&write).max(0.0);
            }
        }
    }
}

impl Drop for DiskProbe {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.query);
        }
        let _ = &self.lib;
    }
}

/// Значения счётчика вместе с именами экземпляров.
unsafe fn counter_items(
    read_array: PdhGetFormattedCounterArrayW,
    counter: HANDLE,
) -> Vec<(String, f64)> {
    let mut size: u32 = 0;
    let mut count: u32 = 0;
    let rc = read_array(counter, PDH_FMT_DOUBLE, &mut size, &mut count, std::ptr::null_mut());
    if rc != PDH_MORE_DATA || size == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size as usize + 64];
    let items = buf.as_mut_ptr() as *mut PdhFmtCounterValueItemW;
    let mut count2: u32 = 0;
    let rc2 = read_array(counter, PDH_FMT_DOUBLE, &mut size, &mut count2, items);
    if rc2 != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count2 as usize);
    for i in 0..count2 as usize {
        let item = &*items.add(i);
        if item.value.status != 0 {
            continue;
        }
        let name = if item.name.is_null() {
            String::new()
        } else {
            let len = (0..).map(|k| *item.name.add(k)).take_while(|c| *c != 0).count();
            from_wide(std::slice::from_raw_parts(item.name, len))
        };
        out.push((name, item.value.double_value));
    }
    out
}

unsafe fn sum_counter(
    read_array: PdhGetFormattedCounterArrayW,
    counter: HANDLE,
) -> f64 {
    let mut size: u32 = 0;
    let mut count: u32 = 0;
    let rc = read_array(counter, PDH_FMT_DOUBLE, &mut size, &mut count, std::ptr::null_mut());
    if rc != PDH_MORE_DATA || size == 0 {
        return 0.0;
    }
    let mut buf = vec![0u8; size as usize + 64];
    let items = buf.as_mut_ptr() as *mut PdhFmtCounterValueItemW;
    let mut count2: u32 = 0;
    let rc2 = read_array(counter, PDH_FMT_DOUBLE, &mut size, &mut count2, items);
    if rc2 != 0 {
        return 0.0;
    }
    let mut total = 0.0;
    for i in 0..count2 as usize {
        let item = &*items.add(i);
        let name = if item.name.is_null() {
            String::new()
        } else {
            let len = (0..)
                .map(|k| *item.name.add(k))
                .take_while(|c| *c != 0)
                .count();
            from_wide(std::slice::from_raw_parts(item.name, len))
        };
        let lower = name.to_lowercase();
        if lower.contains("loopback")
            || lower.contains("isatap")
            || lower.contains("teredo")
            || lower.contains("pseudo")
        {
            continue;
        }
        if item.value.status == 0 {
            total += item.value.double_value;
        }
    }
    total
}

pub fn sample_mem() -> MemInfo {
    let mut m = MEMORYSTATUSEX::default();
    m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let ok = unsafe { GlobalMemoryStatusEx(&mut m) };
    if ok == 0 {
        return MemInfo::default();
    }
    // Дополнительные поля — из psapi: там же их берёт диспетчер задач.
    let perf = perf_info();
    let page = perf.page_size as u64;
    MemInfo {
        total: m.ullTotalPhys,
        used: m.ullTotalPhys.saturating_sub(m.ullAvailPhys),
        percent: m.dwMemoryLoad as f64,
        committed: perf.commit_total as u64 * page,
        commit_limit: perf.commit_limit as u64 * page,
        cached: perf.system_cache as u64 * page,
        available: m.ullAvailPhys,
        paged_pool: perf.kernel_paged as u64 * page,
        nonpaged_pool: perf.kernel_nonpaged as u64 * page,
    }
}

/// Сводка psapi; при ошибке — нули, чтобы не выдумывать значения.
fn perf_info() -> PERFORMANCE_INFORMATION {
    let mut info = PERFORMANCE_INFORMATION::default();
    info.cb = std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32;
    let ok = unsafe { GetPerformanceInfo(&mut info, info.cb) };
    if ok == 0 {
        return PERFORMANCE_INFORMATION::default();
    }
    info
}

pub fn sample_disks() -> Vec<DiskInfo> {
    let mut out = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root = format!("{letter}:\\");
        let wroot = to_wide(&root);
        let dtype = unsafe { GetDriveTypeW(wroot.as_ptr()) };
        // 2 = removable, 3 = fixed, 5 = cdrom, 6 = ramdisk
        if dtype != 2 && dtype != 3 && dtype != 6 {
            continue;
        }
        let mut free_to_caller: u64 = 0;
        let mut total: u64 = 0;
        let mut free_total: u64 = 0;
        let ok = unsafe {
            GetDiskFreeSpaceExW(wroot.as_ptr(), &mut free_to_caller, &mut total, &mut free_total)
        };
        if ok == 0 || total == 0 {
            continue;
        }
        let used = total.saturating_sub(free_total);
        out.push(DiskInfo {
            letter: format!("{letter}:"),
            label: if dtype == 2 { "Съёмный".into() } else { "Локальный".into() },
            total,
            free: free_total,
            percent: used as f64 / total as f64 * 100.0,
            ..Default::default()
        });
    }
    out
}

fn os_name() -> String {
    let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let product = reg_read_string(HKEY_LOCAL_MACHINE, path, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let version = reg_read_string(HKEY_LOCAL_MACHINE, path, "DisplayVersion").unwrap_or_default();
    let build = reg_read_string(HKEY_LOCAL_MACHINE, path, "CurrentBuild").unwrap_or_default();
    let mut out = product.trim().to_string();
    if !version.is_empty() {
        out.push(' ');
        out.push_str(version.trim());
    }
    if !build.is_empty() {
        out.push_str(&format!(" · сборка {}", build.trim()));
    }
    out
}

fn cpu_brand() -> String {
    // Читаем CentralProcessor\0\ProcessorNameString из реестра.
    let path = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    if let Some(v) = reg_read_string(HKEY_LOCAL_MACHINE, path, "ProcessorNameString") {
        return v.trim().to_string();
    }
    "CPU".to_string()
}

fn cpu_mhz() -> u32 {
    let path = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    reg_read_dword(HKEY_LOCAL_MACHINE, path, "~MHz").unwrap_or(0)
}

pub fn reg_read_dword(root: usize, path: &str, name: &str) -> Option<u32> {
    unsafe {
        let wpath = to_wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wpath.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return None;
        }
        let wname = to_wide(name);
        let mut kind: u32 = 0;
        let mut value: u32 = 0;
        let mut size: u32 = 4;
        let rc = RegQueryValueExW(
            key,
            wname.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            &mut value as *mut u32 as *mut u8,
            &mut size,
        );
        RegCloseKey(key);
        if rc == 0 && size == 4 {
            Some(value)
        } else {
            None
        }
    }
}

pub fn reg_read_string(root: usize, path: &str, name: &str) -> Option<String> {
    unsafe {
        let wpath = to_wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wpath.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return None;
        }
        let wname = to_wide(name);
        let mut kind: u32 = 0;
        let mut size: u32 = 0;
        let rc = RegQueryValueExW(
            key,
            wname.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        );
        if rc != 0 || size == 0 {
            RegCloseKey(key);
            return None;
        }
        let mut buf = vec![0u8; size as usize + 2];
        let mut size2 = size;
        let rc2 = RegQueryValueExW(
            key,
            wname.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            buf.as_mut_ptr(),
            &mut size2,
        );
        RegCloseKey(key);
        if rc2 != 0 {
            return None;
        }
        if kind == REG_SZ || kind == REG_EXPAND_SZ {
            let wide: Vec<u16> = buf[..size2 as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(from_wide(&wide))
        } else {
            None
        }
    }
}

// ---------------- GPU (NVML) ----------------

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct NvmlUtilization {
    gpu: u32,
    memory: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct NvmlMemory {
    total: u64,
    free: u64,
    used: u64,
}

type NvmlInit = unsafe extern "system" fn() -> i32;
type NvmlShutdown = unsafe extern "system" fn() -> i32;
type NvmlCount = unsafe extern "system" fn(*mut u32) -> i32;
type NvmlHandle = unsafe extern "system" fn(u32, *mut *mut c_void) -> i32;
type NvmlName = unsafe extern "system" fn(*mut c_void, *mut i8, u32) -> i32;
type NvmlUtil = unsafe extern "system" fn(*mut c_void, *mut NvmlUtilization) -> i32;
type NvmlMem = unsafe extern "system" fn(*mut c_void, *mut NvmlMemory) -> i32;
type NvmlTemp = unsafe extern "system" fn(*mut c_void, u32, *mut u32) -> i32;
type NvmlClock = unsafe extern "system" fn(*mut c_void, u32, *mut u32) -> i32;
type NvmlFan = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
type NvmlPower = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;

// ---------------- GPU: счётчики WDDM (как в диспетчере задач) ----------------

/*
 * Диспетчер задач берёт температуру не из NVML, а из WDDM-счётчиков:
 * D3DKMTQueryAdapterInfo с KMTQAITYPE_ADAPTERPERFDATA. Драйвер отдаёт значение
 * в десятых долях градуса и обновляет его на каждом такте, поэтому цифра живая.
 * NVML возвращает целые градусы и на части карт обновляет их редко — из-за этого
 * показатель «залипал».
 */

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Luid {
    low: u32,
    high: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct AdapterInfo {
    h_adapter: u32,
    luid: Luid,
    num_sources: u32,
    preferred: i32,
}

#[repr(C)]
struct EnumAdapters2 {
    num_adapters: u32,
    adapters: *mut AdapterInfo,
}

#[repr(C)]
struct QueryAdapterInfo {
    h_adapter: u32,
    kind: u32,
    data: *mut c_void,
    size: u32,
}

#[repr(C)]
struct CloseAdapter {
    h_adapter: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct AdapterPerfData {
    physical_adapter_index: u32,
    memory_frequency: u64,
    max_memory_frequency: u64,
    max_memory_frequency_oc: u64,
    memory_bandwidth: u64,
    pcie_bandwidth: u64,
    fan: u32,
    power: u32,
    temperature: u32,
    power_state_override: u32,
}

#[repr(C)]
struct AdapterRegistryInfo {
    adapter: [u16; 260],
    bios: [u16; 260],
    dac: [u16; 260],
    chip: [u16; 260],
}

impl Default for AdapterRegistryInfo {
    fn default() -> Self {
        AdapterRegistryInfo {
            adapter: [0; 260],
            bios: [0; 260],
            dac: [0; 260],
            chip: [0; 260],
        }
    }
}

/// Значения из d3dkmthk.h.
const KMTQAITYPE_ADAPTERREGISTRYINFO: u32 = 8;
const KMTQAITYPE_ADAPTERPERFDATA: u32 = 62;

type D3dkmtEnumAdapters2 = unsafe extern "system" fn(*mut EnumAdapters2) -> i32;
type D3dkmtQueryAdapterInfo = unsafe extern "system" fn(*mut QueryAdapterInfo) -> i32;
type D3dkmtCloseAdapter = unsafe extern "system" fn(*mut CloseAdapter) -> i32;

pub struct PerfProbe {
    _lib: DynLib,
    query: D3dkmtQueryAdapterInfo,
    close: D3dkmtCloseAdapter,
    adapters: Vec<u32>,
}

unsafe impl Send for PerfProbe {}

impl PerfProbe {
    pub fn new() -> Option<PerfProbe> {
        let lib = DynLib::load("gdi32.dll")?;
        unsafe {
            let enumerate: D3dkmtEnumAdapters2 = std::mem::transmute(lib.sym("D3DKMTEnumAdapters2")?);
            let query: D3dkmtQueryAdapterInfo = std::mem::transmute(lib.sym("D3DKMTQueryAdapterInfo")?);
            let close: D3dkmtCloseAdapter = std::mem::transmute(lib.sym("D3DKMTCloseAdapter")?);

            // Больше 16 адаптеров не бывает; если буфера не хватит, вызов вернёт ошибку.
            let mut buf: Vec<AdapterInfo> = vec![AdapterInfo::default(); 16];
            let mut req = EnumAdapters2 {
                num_adapters: buf.len() as u32,
                adapters: buf.as_mut_ptr(),
            };
            if enumerate(&mut req) < 0 {
                return None;
            }
            buf.truncate(req.num_adapters as usize);
            if buf.is_empty() {
                return None;
            }
            let adapters = buf.iter().map(|a| a.h_adapter).collect();
            Some(PerfProbe {
                _lib: lib,
                query,
                close,
                adapters,
            })
        }
    }

    fn name_of(&self, h_adapter: u32) -> String {
        let mut info = AdapterRegistryInfo::default();
        let mut q = QueryAdapterInfo {
            h_adapter,
            kind: KMTQAITYPE_ADAPTERREGISTRYINFO,
            data: &mut info as *mut AdapterRegistryInfo as *mut c_void,
            size: std::mem::size_of::<AdapterRegistryInfo>() as u32,
        };
        if unsafe { (self.query)(&mut q) } < 0 {
            return String::new();
        }
        let end = info.adapter.iter().position(|c| *c == 0).unwrap_or(info.adapter.len());
        from_wide(&info.adapter[..end])
    }

    /// Температура в градусах и обороты кулера, если драйвер их отдаёт.
    pub fn read(&self) -> Option<(f64, u32)> {
        let mut best: Option<(f64, u32)> = None;
        for &h in &self.adapters {
            let mut perf = AdapterPerfData::default();
            let mut q = QueryAdapterInfo {
                h_adapter: h,
                kind: KMTQAITYPE_ADAPTERPERFDATA,
                data: &mut perf as *mut AdapterPerfData as *mut c_void,
                size: std::mem::size_of::<AdapterPerfData>() as u32,
            };
            if unsafe { (self.query)(&mut q) } < 0 || perf.temperature == 0 {
                continue;
            }
            let temp = perf.temperature as f64 / 10.0;
            // На машине с двумя адаптерами берём дискретный: он и есть тот,
            // что показывает NVML. Иначе — самый горячий.
            let discrete = self.name_of(h).to_uppercase().contains("NVIDIA");
            let better = match best {
                None => true,
                Some((t, _)) => (discrete && temp >= t - 5.0) || temp > t,
            };
            if better {
                best = Some((temp, perf.fan));
            }
        }
        best
    }
}

impl Drop for PerfProbe {
    fn drop(&mut self) {
        for &h in &self.adapters {
            let mut c = CloseAdapter { h_adapter: h };
            unsafe { (self.close)(&mut c) };
        }
    }
}

pub struct GpuProbe {
    lib: DynLib,
    device: *mut c_void,
    name: String,
    _init: NvmlInit,
    shutdown: NvmlShutdown,
    util: NvmlUtil,
    mem: NvmlMem,
    temp: NvmlTemp,
    clock: NvmlClock,
    fan: NvmlFan,
    power: NvmlPower,
    perf: Option<PerfProbe>,
}

unsafe impl Send for GpuProbe {}

impl GpuProbe {
    pub fn new() -> Option<GpuProbe> {
        let lib = DynLib::load("nvml.dll").or_else(|| {
            let p = format!("{}\\nvml.dll", system_dir());
            DynLib::load(&p)
        })?;
        unsafe {
            let init: NvmlInit = std::mem::transmute(lib.sym("nvmlInit_v2")?);
            let shutdown: NvmlShutdown = std::mem::transmute(lib.sym("nvmlShutdown")?);
            let count: NvmlCount = std::mem::transmute(lib.sym("nvmlDeviceGetCount_v2")?);
            let handle: NvmlHandle = std::mem::transmute(lib.sym("nvmlDeviceGetHandleByIndex_v2")?);
            let name_fn: NvmlName = std::mem::transmute(lib.sym("nvmlDeviceGetName")?);
            let util: NvmlUtil = std::mem::transmute(lib.sym("nvmlDeviceGetUtilizationRates")?);
            let mem: NvmlMem = std::mem::transmute(lib.sym("nvmlDeviceGetMemoryInfo")?);
            let temp: NvmlTemp = std::mem::transmute(lib.sym("nvmlDeviceGetTemperature")?);
            let clock: NvmlClock = std::mem::transmute(lib.sym("nvmlDeviceGetClockInfo")?);
            let fan: NvmlFan = std::mem::transmute(lib.sym("nvmlDeviceGetFanSpeed")?);
            let power: NvmlPower = std::mem::transmute(lib.sym("nvmlDeviceGetPowerUsage")?);

            if init() != 0 {
                return None;
            }
            let mut n: u32 = 0;
            if count(&mut n) != 0 || n == 0 {
                return None;
            }
            let mut dev: *mut c_void = std::ptr::null_mut();
            if handle(0, &mut dev) != 0 {
                return None;
            }
            let mut buf = [0i8; 96];
            let mut name = String::from("NVIDIA GPU");
            if name_fn(dev, buf.as_mut_ptr(), buf.len() as u32) == 0 {
                let bytes: Vec<u8> = buf.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
                name = String::from_utf8_lossy(&bytes).to_string();
            }
            Some(GpuProbe {
                lib,
                device: dev,
                name,
                _init: init,
                shutdown,
                util,
                mem,
                temp,
                clock,
                fan,
                power,
                perf: PerfProbe::new(),
            })
        }
    }

    pub fn read(&self) -> GpuInfo {
        let mut info = GpuInfo {
            available: true,
            name: self.name.clone(),
            vendor: "NVIDIA".into(),
            ..Default::default()
        };
        unsafe {
            let mut u = NvmlUtilization::default();
            if (self.util)(self.device, &mut u) == 0 {
                info.usage = u.gpu as f64;
            }
            let mut m = NvmlMemory::default();
            if (self.mem)(self.device, &mut m) == 0 {
                info.mem_used = m.used;
                info.mem_total = m.total;
            }
            let mut t: u32 = 0;
            if (self.temp)(self.device, 0, &mut t) == 0 {
                info.temp = t as f64;
            }
            let mut c: u32 = 0;
            if (self.clock)(self.device, 0, &mut c) == 0 {
                info.clock = c;
            }
            let mut f: u32 = 0;
            if (self.fan)(self.device, &mut f) == 0 {
                info.fan = f;
            }
            let mut p: u32 = 0;
            if (self.power)(self.device, &mut p) == 0 {
                info.power = p as f64 / 1000.0;
            }
        }
        // Температуру берём из WDDM-счётчиков: там она в десятых долях градуса
        // и обновляется каждый такт, поэтому цифра меняется, как в диспетчере задач.
        if let Some((temp, fan)) = self.perf.as_ref().and_then(|p| p.read()) {
            info.temp = temp;
            if fan > 0 {
                info.fan = fan;
            }
        }
        info
    }
}

impl Drop for GpuProbe {
    fn drop(&mut self) {
        unsafe {
            (self.shutdown)();
        }
        let _ = &self.lib;
    }
}
