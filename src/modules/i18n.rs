use std::sync::atomic::{AtomicU8, Ordering};

static LANG: AtomicU8 = AtomicU8::new(VI);

pub const VI: u8 = 0;
pub const EN: u8 = 1;
pub const ZH: u8 = 2;

pub fn code_to_index(code: &str) -> u8 {
    match code {
        "en" => EN,
        "zh" => ZH,
        _ => VI,
    }
}

pub fn set_language(code: &str) {
    LANG.store(code_to_index(code), Ordering::Relaxed);
}

pub fn current_index() -> u8 {
    LANG.load(Ordering::Relaxed)
}

pub fn tr_with(lang: u8, vi: &'static str, en: &'static str, zh: &'static str) -> &'static str {
    match lang {
        EN => en,
        ZH => zh,
        _ => vi,
    }
}

pub fn tr(vi: &'static str, en: &'static str, zh: &'static str) -> &'static str {
    tr_with(current_index(), vi, en, zh)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_code_mapping_roundtrip() {
        assert_eq!(code_to_index("vi"), VI);
        assert_eq!(code_to_index("en"), EN);
        assert_eq!(code_to_index("zh"), ZH);
        assert_eq!(code_to_index("fr"), VI);
        assert_eq!(code_to_index(""), VI);
        assert_ne!(VI, EN);
        assert_ne!(EN, ZH);
    }

    #[test]
    fn test_tr_with_selects_requested_language() {
        assert_eq!(tr_with(VI, "Xin chào", "Hello", "你好"), "Xin chào");
        assert_eq!(tr_with(EN, "Xin chào", "Hello", "你好"), "Hello");
        assert_eq!(tr_with(ZH, "Xin chào", "Hello", "你好"), "你好");
        assert_eq!(tr_with(9, "Xin chào", "Hello", "你好"), "Xin chào");
    }

    #[test]
    fn test_perf_tr_lookup() {
        crate::modules::perf::measure("i18n::tr", 1_000_000, || {
            std::hint::black_box(tr("Bảo mật", "Security", "安全"));
        });
    }
}
