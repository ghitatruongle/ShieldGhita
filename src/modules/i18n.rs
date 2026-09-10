use std::sync::atomic::{AtomicU8, Ordering};

static LANG: AtomicU8 = AtomicU8::new(VI);

pub const VI: u8 = 0;
pub const EN: u8 = 1;
pub const ZH: u8 = 2;
pub const RU: u8 = 3;

pub fn code_to_index(code: &str) -> u8 {
    match code {
        "en" => EN,
        "zh" => ZH,
        "ru" => RU,
        _ => VI,
    }
}

#[allow(dead_code)]
pub fn index_to_code(idx: u8) -> &'static str {
    match idx {
        EN => "en",
        ZH => "zh",
        RU => "ru",
        _ => "vi",
    }
}

pub fn set_language(code: &str) {
    LANG.store(code_to_index(code), Ordering::Relaxed);
}

pub fn current_index() -> u8 {
    LANG.load(Ordering::Relaxed)
}

pub fn tr_with(lang: u8, vi: &'static str, en: &'static str, zh: &'static str) -> &'static str {
    // 3-arg variant has no RU string: RU falls back to EN (matches
    // ui/common.slint I18n.t lang==3 ? en). Use tr4 when a RU string exists.
    match lang {
        EN => en,
        ZH => zh,
        RU => en,
        _ => vi,
    }
}

pub fn tr(vi: &'static str, en: &'static str, zh: &'static str) -> &'static str {
    tr_with(current_index(), vi, en, zh)
}

pub fn tr4_with(
    lang: u8,
    vi: &'static str,
    en: &'static str,
    zh: &'static str,
    ru: &'static str,
) -> &'static str {
    match lang {
        EN => en,
        ZH => zh,
        RU => ru,
        _ => vi,
    }
}

pub fn tr4(vi: &'static str, en: &'static str, zh: &'static str, ru: &'static str) -> &'static str {
    tr4_with(current_index(), vi, en, zh, ru)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_code_mapping_roundtrip() {
        assert_eq!(code_to_index("vi"), VI);
        assert_eq!(code_to_index("en"), EN);
        assert_eq!(code_to_index("zh"), ZH);
        assert_eq!(code_to_index("ru"), RU);
        assert_eq!(code_to_index("fr"), VI);
        assert_eq!(code_to_index(""), VI);
        assert_eq!(index_to_code(VI), "vi");
        assert_eq!(index_to_code(EN), "en");
        assert_eq!(index_to_code(ZH), "zh");
        assert_eq!(index_to_code(RU), "ru");
        assert_ne!(VI, EN);
        assert_ne!(EN, ZH);
        assert_ne!(ZH, RU);
    }

    #[test]
    fn test_tr_with_selects_requested_language() {
        assert_eq!(tr_with(VI, "Xin chào", "Hello", "你好"), "Xin chào");
        assert_eq!(tr_with(EN, "Xin chào", "Hello", "你好"), "Hello");
        assert_eq!(tr_with(ZH, "Xin chào", "Hello", "你好"), "你好");
        assert_eq!(tr_with(RU, "Xin chào", "Hello", "你好"), "Hello");
        assert_eq!(tr_with(9, "Xin chào", "Hello", "你好"), "Xin chào");

        assert_eq!(
            tr4_with(VI, "Xin chào", "Hello", "你好", "Привет"),
            "Xin chào"
        );
        assert_eq!(tr4_with(EN, "Xin chào", "Hello", "你好", "Привет"), "Hello");
        assert_eq!(tr4_with(ZH, "Xin chào", "Hello", "你好", "Привет"), "你好");
        assert_eq!(
            tr4_with(RU, "Xin chào", "Hello", "你好", "Привет"),
            "Привет"
        );
    }

    #[test]
    fn test_perf_tr_lookup() {
        crate::modules::perf::measure("i18n::tr", 1_000_000, || {
            std::hint::black_box(tr("Bảo mật", "Security", "安全"));
        });
    }
}
