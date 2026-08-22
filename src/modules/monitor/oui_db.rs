pub fn lookup_vendor(mac: &str) -> String {
    let clean = mac.replace(['-', ':'], "").to_uppercase();
    if clean.len() < 6 {
        return "Không xác định / Generic".into();
    }

    if let Ok(first_byte) = u8::from_str_radix(&clean[0..2], 16) {
        if (first_byte & 0x02) != 0 {
            return "Thiết bị di động (Địa chỉ MAC riêng tư)".into();
        }
    }

    let oui = &clean[0..6];
    match oui {
        "0017F2" | "0019E3" | "001B63" | "001E52" | "002312" | "002500" | "002608" | "3C0754"
        | "40A6D9" | "5855CA" | "68967B" | "703EAC" | "784F43" | "8C8590" | "9801A7" | "A483E7"
        | "AC87A3" | "B8782E" | "C82A14" | "D0034B" | "E4E4AB" | "F01898" | "F4F15A" | "147DDA"
        | "18E728" | "28CFE9" | "34A395" | "48605F" | "5CF938" | "60F81D" | "7C6D62" | "88665A"
        | "9C35EB" | "A8667F" | "B019C6" | "C0847D" | "DC5285" | "E0680A" | "F8FFC2" => {
            "Apple Inc. (iPhone / iPad / Mac)".into()
        }

        "0007AB" | "001247" | "001599" | "00166C" | "001D25" | "0021D2" | "0024E8" | "00265D"
        | "08FC88" | "183B7E" | "244B03" | "3423BA" | "44F459" | "5056A8" | "64B853" | "7840E4"
        | "88329B" | "9C0298" | "AC5F3E" | "C4731E" | "D48839" | "E47CF9" | "F47B5E" | "0012FB"
        | "0015B9" | "0017D5" | "001A8A" | "0023D7" | "107719" | "2013E0" | "38AA3C" | "4C3C16"
        | "6C8336" | "805719" | "9463D1" | "BC4486" | "CC07AB" | "E8E5D6" => {
            "Samsung Electronics (Galaxy / Smart TV)".into()
        }

        "001882" | "101279" | "1868CB" | "2857BE" | "3C1E04" | "4419B6" | "48EA63" | "5803FB"
        | "7446A0" | "849A40" | "988B5D" | "A41437" | "BC5451" | "C05627" | "D89685" | "E0508B" => {
            "Hikvision / Ezviz (Camera an ninh)".into()
        }

        "38AF29" | "4C11BF" | "9002A9" | "A0BD1D" | "B0411D" | "E0508C" | "F45EAB" | "3C8375"
        | "40A0F8" | "6C709B" | "702C1F" => "Dahua / Imou (Camera an ninh)".into(),

        "00408C" | "ACCC8E" | "B8A44F" => "Axis Communications (CCTV Camera)".into(),
        "001212" | "282C02" | "7C2F80" | "A4DA22" => "Tuya Smart / Yoosee (IP Camera / IoT)".into(),

        "009EE8" | "0C1DAF" | "14F65A" | "185936" | "2082C0" | "286C07" | "3480B3" | "50642B"
        | "584498" | "640980" | "742344" | "7C49EB" | "88C397" | "9C99A0" | "ACF7F3" | "C40BCB"
        | "D4970B" | "E446DA" | "F48E92" | "102CB6" | "2C6BF5" | "38539C" | "4C49E3" | "68DE3A"
        | "7811DC" | "8CBEBE" | "A086C6" | "BC25E0" | "DC5A14" => {
            "Xiaomi (Điện thoại / Camera / IoT)".into()
        }

        "04646D" | "14B968" | "24DF6A" | "482CA0" | "78C12C" | "A4EB42" | "C8B29B" | "DC7144"
        | "E88D28" => "OPPO / Realme (Điện thoại)".into(),
        "002637" | "14686A" | "388B59" | "582A40" | "84DBAC" | "B41A3D" | "C808E9" | "E09971" => {
            "Vivo Mobile (Điện thoại)".into()
        }
        "001E10" | "0425C5" | "104780" | "1CA85B" | "286ED4" | "404D8E" | "4846FB" | "548998"
        | "707B86" | "80B686" | "888603" | "AC853D" | "B41513" | "C88D83" | "E0191D" | "F8E71E" => {
            "Huawei Technologies (Phone / Router)".into()
        }

        "0002B3" | "000347" | "000423" | "0007E9" | "000E0C" | "001302" | "0013E8" | "001500"
        | "0016EA" | "0018DE" | "001B21" | "001E64" | "00216A" | "0022FB" | "002314" | "0024D7"
        | "002710" | "28704E" | "3413E8" | "3C5282" | "4851B7" | "5891CF" | "645106" | "8086F2"
        | "A44CC8" | "AC6784" => "Intel Corp. (PC / Laptop)".into(),

        "001422" | "0015C5" | "00188B" | "0019B9" | "001A6B" | "001D09" | "002170" | "1866DA"
        | "24B6FD" | "74867A" | "B8AC6F" | "D4BED9" => "Dell Inc. (Máy tính PC / Laptop)".into(),
        "0001E6" | "000802" | "000F20" | "001871" | "00215A" | "0025B3" | "002655" | "10604B"
        | "2C27D7" | "705A0F" | "9C8E99" | "C8CB9E" => "HP Inc. (Máy tính / Máy in)".into(),
        "000C6E" | "0011D8" | "0013D4" | "0015F2" | "0018F3" | "001BFC" | "001E8C" | "049226"
        | "08606E" | "107B44" | "2CFDA1" | "704D7B" => {
            "ASUSTeK Computer (Laptop / Mainboard)".into()
        }
        "00016C" | "006067" | "00A060" | "00E018" | "00E08F" | "1078D2" => {
            "Acer Inc. (Laptop / PC)".into()
        }
        "00096B" | "001A64" | "002186" | "002618" | "207693" | "54EE75" | "70723C" | "8CE748"
        | "A4C494" | "C4346B" => "Lenovo (Laptop / ThinkPad)".into(),

        "000A3A" | "001478" | "0019E0" | "001D0F" | "002127" | "0023CD" | "002586" | "14CC20"
        | "1C3BF3" | "30B5C2" | "50C7BF" | "60E327" | "704F57" | "7C8BCA" | "90F652" | "A0F3C1"
        | "B0487A" | "C025E9" | "D80D17" | "E894F6" | "F4EC38" => {
            "TP-Link Technologies (Router / AP / Tapo)".into()
        }
        "00B00C" | "14CF92" | "502B73" | "C83A35" | "D83214" => "Tenda Technology (Router)".into(),
        "00000C" | "000142" | "000143" | "000196" | "0001C7" | "0001C9" => {
            "Cisco Systems (Router / Switch)".into()
        }
        "00095B" | "000FB5" | "00146C" | "00184D" | "001E2A" | "001F33" | "0024B2" => {
            "Netgear (Router / Wi-Fi)".into()
        }
        "00055D" | "000D88" | "000F3D" | "001195" | "001346" | "0015E9" | "00179A" => {
            "D-Link Systems (Router)".into()
        }
        "000C43" | "001E8F" | "04A151" | "247F20" | "40313C" => {
            "VNPT Technology (Modem / Router)".into()
        }
        "001A79" | "18622C" | "20F41B" | "88CEFA" => "Viettel Group (Router / Modem)".into(),
        "0019A8" | "54625A" | "7488B8" | "A021B7" => "FPT Telecom (Router / Modem)".into(),

        "00014A" | "00041F" | "000725" | "00096E" | "001315" | "0019C5" | "00248D" => {
            "Sony Corp. (PlayStation / Bravia TV)".into()
        }
        "0005C9" | "001C62" | "001E75" | "001F6B" | "0022A9" | "10F96F" | "18B79E" | "203D66"
        | "3C25D7" | "5884B7" | "9893CC" | "A816B2" | "B83765" | "CC2D8C" | "E4E749" | "F013C3" => {
            "LG Electronics (webOS Smart TV)".into()
        }

        "18FE34" | "240AC4" | "246F28" | "24A160" | "24B2DE" | "2C3AE8" | "30AEA4" | "3C71BF"
        | "483FDA" | "4C11AE" | "545A46" | "5C0272" | "600194" | "68C63A" | "70039F" | "7C87CE"
        | "840D8E" | "84F3EB" | "9097D5" | "A020A6" | "AC67B2" | "B4E62D" | "BCDD29" | "C44F33"
        | "CC50E3" | "D8A01D" | "DC4F22" | "E09806" | "E868E7" | "ECFABC" | "F4CFA2" => {
            "Espressif IoT (Smart Device / Tuya)".into()
        }
        "B827EB" | "DCA632" | "E45F01" => "Raspberry Pi Foundation (Microcomputer)".into(),

        "001788" | "ECB5FA" => "Philips Hue (Đèn thông minh)".into(),
        "3C286D" | "FC65DE" => "Google LLC (Nest / Chromecast)".into(),
        "68FF7B" => "Amazon Technologies (Echo / IoT)".into(),
        "000C29" | "005056" => "VMware (Máy ảo)".into(),
        "00155D" => "Microsoft Hyper-V (Máy ảo)".into(),
        "F492BF" | "7483C2" => "Ubiquiti Networks (UniFi)".into(),

        _ => {
            if mac.starts_with("00:00:00") {
                "Cục bộ (Virtual / Loopback)".into()
            } else {
                "Thiết bị mạng (LAN Host)".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_vendor_common_brands() {
        assert!(lookup_vendor("00:17:F2:11:22:33").contains("Apple"));
        assert!(lookup_vendor("00:07:AB:44:55:66").contains("Samsung"));
        assert!(lookup_vendor("00:18:82:77:88:99").contains("Hikvision"));
        assert!(lookup_vendor("00:0A:3A:AA:BB:CC").contains("TP-Link"));
        assert!(lookup_vendor("00:00:00:00:00:00").contains("Cục bộ"));
        assert!(lookup_vendor("00:00:00").contains("Cục bộ"));
        assert!(lookup_vendor("00:00").contains("Không xác định"));
    }

    #[test]
    fn test_lookup_vendor_merged_admin_groups() {
        assert!(lookup_vendor("00:0C:29:AA:BB:CC").contains("VMware"));
        assert!(lookup_vendor("00:15:5D:AA:BB:CC").contains("Hyper-V"));
        assert!(lookup_vendor("F4:92:BF:AA:BB:CC").contains("Ubiquiti"));
        assert!(lookup_vendor("3C:28:6D:AA:BB:CC").contains("Google"));
    }

    #[test]
    fn test_lookup_vendor_randomized_mac() {
        assert!(lookup_vendor("DA:A1:19:AA:BB:CC").contains("MAC riêng tư"));
    }
}
