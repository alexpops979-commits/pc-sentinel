//! Оценка здоровья ПК и персональные рекомендации.

use crate::json::J;
use crate::sec::{Autorun, Finding};
use crate::sys::Snapshot;

/// Компонент оценки. `score: None` означает, что данных для оценки нет:
/// значение не выдумывается и не участвует в общем балле.
#[derive(Default)]
pub struct Component {
    pub name: String,
    pub score: Option<f64>,
    pub detail: String,
    /// Что показать вместо балла, если балл — не то же самое, что измеренная
    /// величина (например, «39.9 °C» при оценке охлаждения).
    pub value: Option<String>,
    /// Заполнение шкалы 0..100, если оно не совпадает с баллом.
    pub ratio: Option<f64>,
}

pub struct HealthReport {
    pub score: f64,
    pub grade: String,
    pub headline: String,
    pub summary: String,
    pub components: Vec<Component>,
    pub issues: Vec<Finding>,
}

impl HealthReport {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("score", J::num(self.score)),
            ("grade", J::s(self.grade.clone())),
            ("headline", J::s(self.headline.clone())),
            ("summary", J::s(self.summary.clone())),
            (
                "components",
                J::Arr(
                    self.components
                        .iter()
                        .map(|c| {
                            J::obj(vec![
                                ("name", J::s(c.name.clone())),
                                (
                                    "score",
                                    match c.score {
                                        Some(v) => J::num(v),
                                        None => J::Null,
                                    },
                                ),
                                ("measured", J::Bool(c.score.is_some())),
                                ("detail", J::s(c.detail.clone())),
                                (
                                    "value",
                                    match &c.value {
                                        Some(v) => J::s(v.clone()),
                                        None => J::Null,
                                    },
                                ),
                                (
                                    "ratio",
                                    match c.ratio {
                                        Some(v) => J::num(v),
                                        None => J::Null,
                                    },
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "issues",
                J::Arr(self.issues.iter().map(|f| f.to_json()).collect()),
            ),
        ])
    }
}

fn clamp_score(v: f64) -> f64 {
    v.clamp(0.0, 100.0)
}

fn grade_for(score: f64) -> &'static str {
    if score >= 90.0 {
        "Отлично"
    } else if score >= 75.0 {
        "Хорошо"
    } else if score >= 55.0 {
        "Требует внимания"
    } else {
        "Критично"
    }
}

pub fn evaluate(
    snap: &Snapshot,
    scan_score: Option<f64>,
    findings: &[Finding],
    autoruns: &[Autorun],
) -> HealthReport {
    let cpu_score = clamp_score(100.0 - (snap.cpu.usage - 55.0).max(0.0) * 1.7);
    let mem_score = clamp_score(100.0 - (snap.mem.percent - 68.0).max(0.0) * 2.1);
    let worst_disk = snap
        .disks
        .iter()
        .map(|d| d.percent)
        .fold(0.0f64, f64::max);
    // Нет накопителей в отчёте — нечего оценивать.
    let disk_score = if snap.disks.is_empty() {
        None
    } else {
        Some(clamp_score(100.0 - (worst_disk - 78.0).max(0.0) * 3.2))
    };
    // Защита: после полной проверки берём её балл, иначе оцениваем по реально
    // прочитанному автозапуску — эти данные есть всегда, без прав администратора.
    let suspicious_autoruns = autoruns.iter().filter(|a| a.suspicious).count() as f64;
    let security_score = Some(match scan_score {
        Some(v) => clamp_score(v),
        None => clamp_score(100.0 - suspicious_autoruns * 8.0),
    });
    // Охлаждение — только при доступном датчике температуры GPU.
    let thermal_score = if snap.gpu.available && snap.gpu.temp > 0.0 {
        Some(clamp_score(100.0 - (snap.gpu.temp - 70.0).max(0.0) * 2.5))
    } else {
        None
    };

    // Веса пересчитываются по фактически измеренным компонентам,
    // поэтому непроверенная защита не раздувает и не занижает общий балл.
    let weighted: [(f64, Option<f64>); 5] = [
        (0.24, Some(cpu_score)),
        (0.20, Some(mem_score)),
        (0.16, disk_score),
        (0.30, security_score),
        (0.10, thermal_score),
    ];
    let measured_weight: f64 = weighted
        .iter()
        .filter(|(_, value)| value.is_some())
        .map(|(w, _)| w)
        .sum();
    let total = if measured_weight > 0.0 {
        weighted
            .iter()
            .filter_map(|(w, value)| value.map(|v| v * w))
            .sum::<f64>()
            / measured_weight
    } else {
        0.0
    };

    let mut issues: Vec<Finding> = findings.to_vec();

    if snap.cpu.usage > 70.0 {
        let top = snap.procs.first();
        issues.push(Finding {
            id: "cpu-load".into(),
            severity: "warning".into(),
            title: "Высокая загрузка процессора".into(),
            detail: format!(
                "Средняя загрузка {:.0}%{}. Это может снижать FPS в играх и вызывать микрофризы.",
                snap.cpu.usage,
                top.map(|p| format!(", основной потребитель — {} ({:.0}%)", p.name, p.cpu))
                    .unwrap_or_default()
            ),
            recommendation: "Закройте лишние фоновые приложения или ограничьте их приоритет.".into(),
            kind: "anomaly".into(),
            ..Default::default()
        });
    }

    if snap.mem.percent > 82.0 {
        issues.push(Finding {
            id: "mem-load".into(),
            severity: "warning".into(),
            title: "Мало свободной оперативной памяти".into(),
            detail: format!(
                "Занято {:.0}% из {:.1} ГБ. При нехватке памяти система уходит в файл подкачки — это основной источник фризов.",
                snap.mem.percent,
                snap.mem.total as f64 / 1024.0 / 1024.0 / 1024.0
            ),
            recommendation: "Закройте вкладки браузера и тяжёлые приложения перед игрой.".into(),
            kind: "anomaly".into(),
            ..Default::default()
        });
    }

    if worst_disk > 88.0 {
        issues.push(Finding {
            id: "disk-full".into(),
            severity: "warning".into(),
            title: "Диск почти заполнен".into(),
            detail: format!("Самый заполненный том занят на {:.0}%. Свободное место влияет на подкачку и обновления.", worst_disk),
            recommendation: "Очистите временные файлы и корзину.".into(),
            kind: "hygiene".into(),
            ..Default::default()
        });
    }

    let suspicious = autoruns.iter().filter(|a| a.suspicious).count();
    if suspicious > 0 {
        issues.push(Finding {
            id: "autorun-risk".into(),
            severity: "warning".into(),
            title: format!("Подозрительные элементы автозагрузки: {suspicious}"),
            detail: "Некоторые программы запускаются автоматически из пользовательских папок без цифровой подписи.".into(),
            recommendation: "Проверьте список автозагрузки и отключите неизвестные записи.".into(),
            kind: "persistence".into(),
            ..Default::default()
        });
    }

    if snap.gpu.available && snap.gpu.temp > 78.0 {
        issues.push(Finding {
            id: "gpu-hot".into(),
            severity: "warning".into(),
            title: "Видеокарта греется".into(),
            detail: format!("Температура GPU {:.0} °C. При перегреве срабатывает троттлинг и FPS падает.", snap.gpu.temp),
            recommendation: "Продуйте систему охлаждения и проверьте профиль вентиляторов.".into(),
            kind: "thermal".into(),
            ..Default::default()
        });
    }

    // Заголовок не должен звучать бодрее, чем реальные находки:
    // при критичных проблемах «отлично» не показываем.
    let has_critical = issues.iter().any(|i| i.severity == "critical");
    let has_warning = issues.iter().any(|i| i.severity == "warning");
    let headline = if has_critical {
        "Нужно вмешательство".to_string()
    } else if total >= 90.0 && !has_warning {
        "Система в отличном состоянии".to_string()
    } else if total >= 75.0 {
        "Система работает стабильно".to_string()
    } else if total >= 55.0 {
        "Есть что подтянуть".to_string()
    } else {
        "Нужно вмешательство".to_string()
    };

    let summary = format!(
        "Процессор {:.0}%, память {:.0}%, диски {:.0}%. Проблем: {}.",
        snap.cpu.usage,
        snap.mem.percent,
        worst_disk,
        issues.len()
    );

    HealthReport {
        score: total,
        grade: grade_for(total).to_string(),
        headline,
        summary,
        components: vec![
            Component {
                name: "Процессор".into(),
                score: Some(cpu_score),
                detail: format!("{:.0}% загрузки · {} потоков", snap.cpu.usage, snap.cpu.cores),
                ..Default::default()
            },
            Component {
                name: "Память".into(),
                score: Some(mem_score),
                detail: format!("{:.0}% занято", snap.mem.percent),
                ..Default::default()
            },
            Component {
                name: "Накопители".into(),
                score: disk_score,
                detail: if snap.disks.is_empty() {
                    "накопители не обнаружены".into()
                } else {
                    format!("{:.0}% занято", worst_disk)
                },
                ..Default::default()
            },
            Component {
                name: "Защита".into(),
                score: security_score,
                detail: if scan_score.is_some() {
                    "по результатам проверки".into()
                } else if suspicious_autoruns > 0.0 {
                    format!("{:.0} подозрительных в автозагрузке", suspicious_autoruns)
                } else {
                    "автозагрузка без подозрительных записей".into()
                },
                ..Default::default()
            },
            Component {
                // Показываем саму температуру, а не абстрактный балл охлаждения:
                // «Температура 100» читалось бы как 100 °C.
                name: "Температура".into(),
                score: thermal_score,
                value: if snap.gpu.available && snap.gpu.temp > 0.0 {
                    Some(format!("{:.1} °C", snap.gpu.temp))
                } else {
                    None
                },
                ratio: if snap.gpu.available && snap.gpu.temp > 0.0 {
                    Some(snap.gpu.temp.clamp(0.0, 100.0))
                } else {
                    None
                },
                detail: if snap.gpu.available && snap.gpu.temp > 0.0 {
                    "графический процессор".into()
                } else if snap.gpu.available {
                    "датчик температуры недоступен".into()
                } else {
                    "нет поддержки датчика GPU".into()
                },
            },
        ],
        issues,
    }
}
