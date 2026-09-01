pub fn lookup_vendor(mac: &str) -> String {
    let mut clean = [0u8; 12];
    let mut n = 0usize;
    for b in mac.bytes() {
        if n == 12 {
            break;
        }
        let upper = b.to_ascii_uppercase();
        if upper.is_ascii_hexdigit() {
            clean[n] = upper;
            n += 1;
        }
    }
    if n < 6 {
        return crate::modules::i18n::tr(
            "Không xác định / Generic",
            "Unknown / Generic",
            "未知设备 / Generic",
        )
        .into();
    }

    let hex = std::str::from_utf8(&clean[..n]).unwrap_or("");
    if let Ok(first_byte) = u8::from_str_radix(&hex[0..2], 16) {
        if (first_byte & 0x02) != 0 {
            return crate::modules::i18n::tr(
                "Thiết bị di động (Địa chỉ MAC riêng tư)",
                "Mobile device (Private MAC address)",
                "移动设备 (随机 MAC 地址)",
            )
            .into();
        }
    }

    let oui = &hex[0..6];
    match oui {
        // --- Apple Inc. (iPhone / iPad / Mac / Apple Watch / Apple TV) ---
        "000393" | "000502" | "000A27" | "000A95" | "000D93" | "0010FA" | "001124" | "001451"
        | "0016CB" | "0017F2" | "0019E3" | "001B63" | "001C46" | "001D4F" | "001E52" | "001F5B"
        | "001FE1" | "0021E9" | "002241" | "002312" | "002332" | "00236C" | "002436" | "002500"
        | "00254B" | "002608" | "00264A" | "0026B0" | "0026BB" | "003EE1" | "0050E4" | "006171"
        | "008865" | "00A040" | "00C610" | "00F4B9" | "040CCE" | "041552" | "041E64" | "042665"
        | "044B2B" | "0452F3" | "045453" | "0469F8" | "04D3CF" | "04DB56" | "04E536" | "04F13E"
        | "04F7E4" | "080007" | "086698" | "087045" | "087402" | "08E689" | "08F4AB" | "0C1539"
        | "0C3021" | "0C3E9F" | "0C4DE9" | "0C5101" | "0C74C2" | "0C771A" | "0CB319" | "0CBCAC"
        | "0CD746" | "101C0C" | "1040F3" | "10417F" | "1093E9" | "109ADD" | "10DDB1" | "14109F"
        | "14205E" | "147DDA" | "1499E2" | "14BD61" | "182032" | "183451" | "185E0F" | "186590"
        | "189EFC" | "18AF61" | "18E728" | "18EE69" | "18F643" | "1C1A6E" | "1C5CF2" | "1C9148"
        | "1C9E46" | "1CABCE" | "203C8F" | "20768F" | "2078F0" | "209BCD" | "20A2E4" | "20C9D0"
        | "20EE28" | "24240E" | "245BFB" | "24A074" | "24A2E1" | "24AB81" | "24E314" | "24F094"
        | "24F677" | "280B5C" | "283737" | "285AEB" | "286ABA" | "28A02B" | "28CFE9" | "28E02C"
        | "28E14C" | "28E7CF" | "28ED6A" | "28F076" | "2C1F23" | "2C3361" | "2CBE08" | "2CF0EE"
        | "30074D" | "3010E4" | "3035AD" | "305747" | "30636B" | "307C5E" | "3090AB" | "30D9D9"
        | "30F7C5" | "3408BC" | "341298" | "34159E" | "34363B" | "345180" | "347C25" | "34A395"
        | "34AB37" | "34C059" | "34E2FD" | "380F4A" | "38484C" | "3866F0" | "3871DE" | "38892C"
        | "38B54D" | "38C986" | "38CADA" | "38F9D3" | "3C0754" | "3C15C2" | "3C22FB" | "3CD0F8"
        | "3CE072" | "402619" | "403004" | "40331A" | "403CFC" | "404D7F" | "406C8F" | "40831D"
        | "4098AD" | "409C28" | "40A6D9" | "40B4CD" | "40BCA5" | "40D32D" | "440010" | "442A60"
        | "444C0C" | "448500" | "449160" | "44D884" | "44FB42" | "483B38" | "48437C" | "484BAA"
        | "48605F" | "48746E" | "48A195" | "48D705" | "48E9F1" | "4C3275" | "4C57CA" | "4C74BF"
        | "4C8D79" | "4CB199" | "503237" | "50BC96" | "50EAD6" | "542696" | "544E90" | "54724F"
        | "54833A" | "549963" | "54AE27" | "54E43A" | "54EA86" | "581FAA" | "58404E" | "5855CA"
        | "58B035" | "58E28F" | "5C8D4E" | "5C95AE" | "5C969D" | "5C97F3" | "5CF938" | "600308"
        | "6030D4" | "60334B" | "606944" | "608C4A" | "609217" | "60C547" | "60D9C7" | "60F81D"
        | "60FACD" | "60FB42" | "64200C" | "647033" | "6476BA" | "649ABE" | "64A5C3" | "64B9E8"
        | "64C753" | "680927" | "685B35" | "68644B" | "68967B" | "68A86D" | "68AB1E" | "68AE20"
        | "68D93C" | "68DBCA" | "6C3E6D" | "6C4008" | "6C4D73" | "6C709F" | "6C72E7" | "6C8D77"
        | "6C96CF" | "6C9958" | "6CB311" | "701124" | "7014A6" | "703EAC" | "705681" | "70700D"
        | "7073CB" | "70A2B3" | "70CD60" | "70DEE2" | "70E284" | "70EC56" | "741B2D" | "748114"
        | "748D08" | "74E1B6" | "74E2F5" | "7831C1" | "784F43" | "7867D7" | "787B8A" | "787E61"
        | "78886D" | "789F70" | "78A873" | "78CA39" | "78FD94" | "7C0191" | "7C04D0" | "7C5049"
        | "7C6D62" | "7CFADF" | "80006E" | "804971" | "80929F" | "80BE05" | "80D09B" | "80E650"
        | "80EA96" | "8425DB" | "843835" | "844BF5" | "84788B" | "848506" | "848E0C" | "849767"
        | "84A134" | "84B153" | "84FCAC" | "881908" | "885395" | "8863DF" | "88665A" | "88AEFA"
        | "88CB87" | "88E87F" | "8C2DAA" | "8C5877" | "8C7B9D" | "8C8590" | "8CF5A3" | "9027E4"
        | "907240" | "90840D" | "90B0ED" | "90B21F" | "90C1C6" | "90DD5D" | "90E2BA" | "90FD61"
        | "941625" | "949426" | "94E96A" | "9801A7" | "9803D8" | "9810E8" | "985AEB" | "989E63"
        | "98B8E3" | "98D6BB" | "98E0D9" | "98F0AB" | "9C04EB" | "9C207B" | "9C293F" | "9C35EB"
        | "9C4FDA" | "9C84BF" | "9CF387" | "9CF48E" | "A01828" | "A03BE3" | "A0999B" | "A0C589"
        | "A0EDCD" | "A43135" | "A45E60" | "A46706" | "A483E7" | "A4B197" | "A4C361" | "A4D1D2"
        | "A82066" | "A8515B" | "A85B78" | "A860B6" | "A8667F" | "A886DD" | "A88808" | "A8968A"
        | "A8BBCC" | "A8FAD8" | "AC1F74" | "AC293A" | "AC3C0B" | "AC61EA" | "AC7F3E" | "AC87A3"
        | "ACC1EE" | "ACCF5C" | "ACDE48" | "ACE342" | "ACFDCE" | "B019C6" | "B03495" | "B0481A"
        | "B065BD" | "B0702D" | "B09FBA" | "B418D1" | "B4430D" | "B49CDF" | "B4F0AB" | "B8098A"
        | "B817C2" | "B844D9" | "B853AC" | "B8782E" | "B88D12" | "B8B2F8" | "B8BBAF" | "B8C75D"
        | "B8E856" | "B8F6B1" | "B8FF61" | "BC3BAF" | "BC52B7" | "BC5436" | "BC6778" | "BC926B"
        | "BCA920" | "BCE143" | "BCEE7B" | "BCFEF5" | "C01ADA" | "C0847D" | "C09F42" | "C0A53E"
        | "C0B658" | "C0CCF8" | "C0D012" | "C0E862" | "C0F2FB" | "C42C03" | "C4B301" | "C81EE7"
        | "C82A14" | "C8334B" | "C83C85" | "C869CD" | "C88550" | "C8B5B7" | "C8D083" | "C8E0EB"
        | "C8F650" | "CC088D" | "CC20E8" | "CC25EF" | "CC29F5" | "CC4463" | "CC785F" | "CCC760"
        | "D0034B" | "D023DB" | "D02598" | "D03311" | "D04F7E" | "D0817A" | "D0A637" | "D0C5F3"
        | "D4619D" | "D4909C" | "D4A33D" | "D4DC09" | "D4F46F" | "D8004D" | "D81C79" | "D83062"
        | "D88F76" | "D89695" | "D89E3F" | "D8A25E" | "D8BB2C" | "D8CF9C" | "D8D1CB" | "DC0C5C"
        | "DC2B2A" | "DC2B61" | "DC3714" | "DC415F" | "DC5285" | "DCA904" | "DCB058" | "DCDD89"
        | "E0338E" | "E05F45" | "E0680A" | "E0ACCB" | "E0B9BA" | "E0C767" | "E0C97A" | "E0CBEE"
        | "E0F5C6" | "E0F847" | "E425E7" | "E48B7F" | "E498D6" | "E49A79" | "E4C63D" | "E4CE8F"
        | "E4E4AB" | "EC3586" | "EC852F" | "ECAD9E" | "ECDDA9" | "F01898" | "F02475" | "F07960"
        | "F0989D" | "F099BF" | "F0B479" | "F0C1F1" | "F0C371" | "F0D1A9" | "F0DBE2" | "F0DCA0"
        | "F0F61C" | "F40F24" | "F41BA1" | "F431C3" | "F437B7" | "F45C89" | "F4F15A" | "F4F951"
        | "F81EDF" | "F82793" | "F83880" | "F84ABF" | "F86214" | "F86F63" | "F887F1" | "F89A8F"
        | "F8E079" | "F8FFC2" | "FC183C" | "FC252F" | "FC2A9C" | "FCB467" | "FCD848" | "FCE998" => {
            "Apple Inc. (iPhone / iPad / Mac)".into()
        }

        // --- Samsung Electronics (Galaxy / Galaxy Tab / Smart TV / Appliances) ---
        "0000F0" | "000278" | "0007AB" | "000918" | "000D44" | "000D6F" | "000DE0" | "001247"
        | "0012FB" | "001377" | "001599" | "0015B9" | "001632" | "00166C" | "0016DB" | "0017C9"
        | "0017D5" | "0018AF" | "001901" | "001A8A" | "001BD7" | "001C43" | "001D25" | "001DF6"
        | "001E7D" | "001FAA" | "002119" | "00214C" | "0021D1" | "0021D2" | "002339" | "002347"
        | "0023C3" | "0023D7" | "002454" | "002491" | "0024E8" | "002567" | "002637" | "00265D"
        | "00E064" | "0418D6" | "04FE8D" | "0808C2" | "08373D" | "08D46A" | "08EE8B" | "08FC88"
        | "0C1420" | "0C8FDF" | "103047" | "107719" | "10D542" | "1432D1" | "1449E0" | "14B484"
        | "18227E" | "183B7E" | "1867B0" | "188331" | "1C5A3E" | "1C66AA" | "2013E0" | "205531"
        | "244B03" | "247189" | "24DBAC" | "28987B" | "28BAB4" | "2C0E3D" | "2C4401" | "30CDA7"
        | "3423BA" | "34C3AC" | "380146" | "380A94" | "38AA3C" | "3C6200" | "3C8BFE" | "400E85"
        | "444E1A" | "44F459" | "4844F7" | "4C3C16" | "5056A8" | "508569" | "50C8E5" | "54880E"
        | "5492BE" | "58C38B" | "5C0A5B" | "5CE8EB" | "606C66" | "60AF6D" | "641CB0" | "647791"
        | "64B853" | "68EBAE" | "6C2F2C" | "6C8336" | "702AD5" | "70F395" | "7445CE" | "781FDB"
        | "7825AD" | "7840E4" | "78471D" | "78521A" | "78AB60" | "7C6193" | "8018A7" | "805719"
        | "842519" | "845181" | "8455A5" | "88308A" | "88329B" | "8C7712" | "90187C" | "90F1AA"
        | "94350A" | "9463D1" | "94B10A" | "980CA5" | "9852B1" | "9C0298" | "9C3AFE" | "A00BBA"
        | "A0821F" | "A4307A" | "A470D6" | "A80600" | "A87C01" | "A8F274" | "AC3613" | "AC5F3E"
        | "B047BF" | "B0C4E7" | "B407F9" | "B479A7" | "B857D8" | "BC4486" | "BC72B7" | "BC8CCD"
        | "C09727" | "C44202" | "C4731E" | "C819F7" | "CC07AB" | "D0176A" | "D48839" | "D857EF"
        | "DC7144" | "E458E7" | "E47CF9" | "E4B021" | "E81132" | "E8508B" | "E8E5D6" | "EC107B"
        | "EC9BF3" | "F025B7" | "F05A09" | "F06BCA" | "F0EE10" | "F409D8" | "F47B5E" | "F8042E"
        | "F83F51" | "F8D0BD" | "FC0012" | "FCC233" => {
            "Samsung Electronics (Galaxy / Smart TV)".into()
        }

        // --- Camera & CCTV Giants (Hikvision, Ezviz, Dahua, Imou, KBVision, Uniview, Axis, Reolink, Tiandy, Yoosee, Vstarcam) ---
        "001882" | "101279" | "1868CB" | "2857BE" | "3C1E04" | "4419B6" | "48EA63" | "5803FB"
        | "7446A0" | "849A40" | "988B5D" | "A41437" | "BC5451" | "C05627" | "D89685" | "E0508B"
        | "34BDC8" | "70B3D5" | "C42F90" | "40A0F8" | "DC5360" => {
            "Hikvision / Ezviz (Camera an ninh)".into()
        }

        "38AF29" | "4C11BF" | "9002A9" | "A0BD1D" | "B0411D" | "E0508C" | "F45EAB" | "3C8375"
        | "6C709B" | "702C1F" | "90C2C3" | "BC325F" | "3CE5A6" | "74B587" | "54C415" | "E4249C" => {
            "Dahua / Imou (Camera an ninh)".into()
        }

        "00408C" | "ACCC8E" | "B8A44F" => "Axis Communications (CCTV Camera)".into(),
        "001212" | "282C02" | "7C2F80" | "A4DA22" | "508A06" | "683E34" | "DC2919" => {
            "Tuya Smart / Yoosee (IP Camera / IoT)".into()
        }
        "E06290" | "001A94" | "EC71DB" | "5C0267" => "Uniview (UNV IP Camera)".into(),
        "60A44C" | "ECF451" | "001B67" => "KBVision (Camera giám sát)".into(),
        "EC7C02" | "3876CA" | "C0EAE4" => "Reolink (IP / Battery Camera)".into(),
        "001241" | "18D6C7" | "D052A8" => "Tiandy Technologies (Camera CCTV)".into(),
        "001304" => "Vstarcam / Eye4 (Camera)".into(),

        // --- Xiaomi Ecosystem (Phones, Tablets, Mi Home, Smart TV, Yeelight, Roborock, Dreame) ---
        "009EE8" | "0C1DAF" | "14F65A" | "185936" | "2082C0" | "286C07" | "3480B3" | "50642B"
        | "584498" | "640980" | "742344" | "7C49EB" | "88C397" | "9C99A0" | "ACF7F3" | "C40BCB"
        | "D4970B" | "E446DA" | "F48E92" | "102CB6" | "2C6BF5" | "38539C" | "4C49E3" | "68DE3A"
        | "7811DC" | "8CBEBE" | "A086C6" | "BC25E0" | "DC5A14" | "04CF4B" | "0C9838" | "18F0E4"
        | "28D127" | "34CE00" | "3C9509" | "50EC50" | "5C0947" | "64CC22" | "7802F8" | "7CE54F"
        | "845CF3" | "8CDE52" | "9487E0" | "9C2EA1" | "A44519" | "B0E235" | "C46E7B" | "E4AAEA" => {
            "Xiaomi (Điện thoại / Camera / Mi IoT)".into()
        }

        // --- OPPO / Realme / OnePlus (BBK Electronics) ---
        "04646D" | "14B968" | "24DF6A" | "482CA0" | "78C12C" | "A4EB42" | "C8B29B" | "E88D28"
        | "8C7A3D" | "C4B8B4" | "9809CF" | "508ACB" | "B0A86E" => {
            "OPPO / Realme (Điện thoại)".into()
        }
        "14686A" | "388B59" | "582A40" | "84DBAC" | "B41A3D" | "C808E9" | "E09971" | "54B121"
        | "9059AF" => "Vivo Mobile (Điện thoại)".into(),
        "A09347" | "C0EEFB" | "702C2E" => "OnePlus Technology (Điện thoại)".into(),

        // --- Huawei & Honor ---
        "001E10" | "0425C5" | "104780" | "1CA85B" | "286ED4" | "404D8E" | "4846FB" | "548998"
        | "707B86" | "80B686" | "888603" | "AC853D" | "B41513" | "C88D83" | "E0191D" | "F8E71E"
        | "00E0FC" | "0819A6" | "084F0A" | "0C37DC" | "18DED7" | "249EAB" | "283152" | "34CD6D"
        | "3C4711" | "4455C4" | "48282F" | "4C5499" | "5439DF" | "5C0339" | "6416F0" | "70A8E3"
        | "74A063" | "8038BC" | "84A8E4" | "88CEFA" | "8C34FD" | "90671C" | "94772B" | "98FFD0"
        | "A0086F" | "A4999B" | "A8CA7B" | "AC4E91" | "B43052" | "C0A0BB" | "C4072F" | "CC96A0"
        | "D02DB5" | "D46EA0" | "DC080F" | "E4A8DF" | "E8088B" | "EC233D" | "F4559C" | "F86CE1" => {
            "Huawei Technologies (Phone / Router / ONT)".into()
        }

        // --- Networking Leaders (Cisco, Meraki, Aruba, DrayTek, Mikrotik, Ubiquiti, Ruijie, TP-Link, Tenda, TOTOLINK, Netgear, D-Link) ---
        "000A3A" | "001478" | "0019E0" | "001D0F" | "002127" | "0023CD" | "002586" | "14CC20"
        | "1C3BF3" | "30B5C2" | "50C7BF" | "60E327" | "704F57" | "7C8BCA" | "90F652" | "A0F3C1"
        | "B0487A" | "C025E9" | "D80D17" | "E894F6" | "F4EC38" | "3CE62E" | "54AF97" | "58D9D5"
        | "6C5AB0" | "7405A5" | "808F1D" | "98DAC4" | "AC84C6" | "B4B024" | "C46E1F" | "E4C32A"
        | "18A6F7" | "200543" | "20DCBA" | "388345" | "44D9E7" | "50D4F7" | "54E032" | "7828CA" => {
            "TP-Link Technologies (Router / Deco / Tapo)".into()
        }

        "00B00C" | "14CF92" | "502B73" | "C83A35" | "D83214" | "0495E6" | "CC3429" => {
            "Tenda Technology (Router / Mesh)".into()
        }
        "00E04C" | "D46E0E" | "78A183" | "74888B" => "TOTOLINK / Zioncom (Router / Wi-Fi)".into(),
        "00507F" | "001DAA" => "DrayTek Corp. (Vigor Router / Firewall)".into(),
        "000C42" | "488AD2" | "64D154" | "B869F4" | "CC2DE0" | "DC2C6E" | "E48D8C" => {
            "MikroTik (RouterBOARD / Switch)".into()
        }
        "F492BF" | "7483C2" | "24A43C" | "60E32B" | "784558" | "802AA8" | "B4FBE4" | "DC9FDB"
        | "E063DA" => "Ubiquiti Inc. (UniFi / EdgeMAX)".into(),
        "00000C" | "000142" | "000143" | "000196" | "0001C7" | "0001C9" | "000216" | "000217"
        | "00024A" | "00027D" | "0002B9" | "0002BA" | "0002FD" | "000331" | "00036B" | "00039F"
        | "0003E3" | "000427" | "00044D" | "00046D" | "00049A" | "0004C0" | "0004DD" | "000500" => {
            "Cisco Systems (Enterprise Router / Catalyst)".into()
        }
        "00180A" | "00246C" | "0C8525" | "24DEC6" | "34FCB9" | "9C1C12" | "AC17C8" => {
            "Cisco Meraki (Cloud Managed Wi-Fi)".into()
        }
        "000B86" | "001A1E" | "40E3D6" | "6C9CED" | "94B40F" | "AC1C2D" | "B041A4" => {
            "Aruba Networks / HPE (Access Point)".into()
        }
        "001F64" | "18B905" | "58696C" | "702287" | "A480B6" | "F4B381" => {
            "Ruijie Networks / Reyee (Enterprise AP)".into()
        }
        "00095B" | "000FB5" | "00146C" | "00184D" | "001E2A" | "001F33" | "0024B2" | "04A151"
        | "20E52A" | "841B5E" | "9C3DCF" | "A00460" | "B07FB9" | "C0FFD4" | "E0469A" => {
            "Netgear (Nighthawk / Orbi)".into()
        }
        "00055D" | "000D88" | "000F3D" | "001195" | "001346" | "0015E9" | "00179A" | "00195B"
        | "1C7EE5" | "28107B" | "78542E" | "B0C554" | "C0A000" => "D-Link Systems (Router)".into(),
        "204E7F" | "6038E0" | "84DB7A" => "Linksys (Velop Mesh / Router)".into(),
        "00059E" | "001349" | "0019CB" | "404A03" => {
            "Zyxel Communications (Security Gateway)".into()
        }

        // --- Vietnamese Carriers / ISP Hardware (VNPT, Viettel, FPT) ---
        "000C43" | "001E8F" | "247F20" | "40313C" | "A021B7" | "E4E749" | "F87B8C" => {
            "VNPT Technology (iGate / Dasan GPON ONT)".into()
        }
        "001A79" | "18622C" | "20F41B" | "A41588" | "C0A86E" => {
            "Viettel Group (ZTE / Huawei H646W GPON)".into()
        }
        "0019A8" | "54625A" | "7488B8" | "E01954" | "68352A" => {
            "FPT Telecom (Archer / G-97RG6M GPON)".into()
        }
        "001E73" | "002293" | "1844E6" | "28D244" | "68D1BA" | "702E22" | "D4A148" => {
            "ZTE Corporation (GPON ONT / Modem)".into()
        }

        // --- PC / Laptops / Chips / Motherboards (Intel, AMD, Dell, HP, Lenovo, Asus, Acer, MSI, Gigabyte, Microsoft Surface) ---
        "0002B3" | "000347" | "000423" | "0007E9" | "000E0C" | "001302" | "0013E8" | "001500"
        | "0016EA" | "0018DE" | "001B21" | "001E64" | "00216A" | "0022FB" | "002314" | "0024D7"
        | "002710" | "28704E" | "3413E8" | "3C5282" | "4851B7" | "5891CF" | "645106" | "8086F2"
        | "A44CC8" | "AC6784" | "B49691" | "C8F750" | "E8B1FC" | "F894C2" => {
            "Intel Corp. (PC / Wi-Fi Card)".into()
        }

        "001422" | "0015C5" | "00188B" | "0019B9" | "001A6B" | "001D09" | "002170" | "1866DA"
        | "24B6FD" | "74867A" | "B8AC6F" | "D4BED9" | "14FEB5" | "3417EB" | "44A842" | "847BEB"
        | "90B11C" | "A41F72" | "B083FE" | "C81F66" | "D89EF3" | "E0DB55" | "F8BC12" => {
            "Dell Inc. (Máy tính PC / Laptop Alienware)".into()
        }

        "0001E6" | "000802" | "000F20" | "001871" | "00215A" | "0025B3" | "002655" | "10604B"
        | "2C27D7" | "705A0F" | "9C8E99" | "C8CB9E" | "040973" | "18A905" | "308D99" | "3CD92B"
        | "40A8F0" | "5820B1" | "68B599" | "80C16E" | "9457A5" | "A0D3C1" | "AC162D" | "D89D67" => {
            "HP Inc. (Máy tính PC / Laptop / Máy in)".into()
        }

        "000C6E" | "0011D8" | "0013D4" | "0015F2" | "0018F3" | "001BFC" | "001E8C" | "049226"
        | "08606E" | "107B44" | "2CFDA1" | "704D7B" | "14DDA9" | "244BFE" | "382C4A" | "40167E"
        | "50465D" | "74D02B" | "90E6BA" | "AC220B" | "D850E6" | "F07959" => {
            "ASUSTeK Computer (Laptop ROG / Mainboard)".into()
        }

        "00016C" | "006067" | "00A060" | "00E018" | "00E08F" | "1078D2" | "0000E8" | "206A8A"
        | "4CD577" | "80C5E6" | "9829A6" | "C01885" => "Acer Inc. (Laptop Predator / Nitro)".into(),

        "00096B" | "001A64" | "002186" | "002618" | "207693" | "54EE75" | "70723C" | "8CE748"
        | "A4C494" | "C4346B" | "005907" | "3C970E" | "6014B3" | "88708C" | "B88584" | "D8F883"
        | "E86A64" => "Lenovo (ThinkPad / Legion Laptop)".into(),

        "001617" | "002564" | "408D5C" | "D85ED3" => {
            "MSI Micro-Star (Gaming Laptop / Mainboard)".into()
        }
        "00055B" | "001D7D" | "1C1B0D" | "74D435" | "E0D55E" => {
            "Gigabyte Technology (Aorus)".into()
        }
        "70886B" | "C85B76" => "ASRock Inc. (Motherboard)".into(),
        "281878" | "6045BD" | "985FD3" | "C49DED" => {
            "Microsoft Corp. (Surface Tablet / Laptop)".into()
        }
        "00E052" | "525400" => "Realtek Semiconductor (Ethernet / Wi-Fi)".into(),

        // --- Smart TV & Home Entertainment (Sony, LG, Panasonic, TCL, Casper, Skyworth, Hisense) ---
        "00014A" | "00041F" | "000725" | "00096E" | "001315" | "0019C5" | "00248D" | "001D0D"
        | "0022CE" | "0024BE" | "00A096" | "080046" | "1048B1" | "280DFA" | "30F9ED" | "544249"
        | "709E29" | "AC9B0A" | "CC988B" | "FC0F4B" => {
            "Sony Corp. (PlayStation 5 / 4 / Bravia Smart TV)".into()
        }

        "0005C9" | "001C62" | "001E75" | "001F6B" | "0022A9" | "10F96F" | "18B79E" | "203D66"
        | "3C25D7" | "5884B7" | "9893CC" | "A816B2" | "B83765" | "CC2D8C" | "F013C3" | "00E091"
        | "14C913" | "20DFB9" | "34FCEF" | "505527" | "685383" | "785DFA" | "88C9D0" | "A0B100"
        | "C4366C" | "D4A34F" | "F8A963" => "LG Electronics (webOS Smart TV)".into(),

        "000B97" | "001608" | "008045" | "34E6D7" | "406186" => {
            "Panasonic Corp. (Smart TV / Audio)".into()
        }
        "0008E0" | "08ED6C" | "40A5EF" => "TCL King Electrical (Smart TV)".into(),
        "28C2DD" | "70288B" => "Casper Electric (Smart TV / Máy lạnh)".into(),
        "102A94" | "38A28C" => "Skyworth Digital (Smart TV)".into(),
        "001310" | "002622" | "20F17C" | "B4CD27" => "Hisense Broadband (Smart TV)".into(),

        // --- Smart Home, IoT & Microcontrollers (Espressif ESP32/ESP8266, Raspberry Pi, Sonoff, Aqara, Tuya, BroadLink) ---
        "18FE34" | "240AC4" | "246F28" | "24A160" | "24B2DE" | "2C3AE8" | "30AEA4" | "3C71BF"
        | "483FDA" | "4C11AE" | "545A46" | "5C0272" | "600194" | "68C63A" | "70039F" | "7C87CE"
        | "840D8E" | "84F3EB" | "9097D5" | "A020A6" | "AC67B2" | "B4E62D" | "BCDD29" | "C44F33"
        | "CC50E3" | "D8A01D" | "DC4F22" | "E09806" | "E868E7" | "ECFABC" | "F4CFA2" | "348518"
        | "349454" | "34AB95" | "4022D8" | "485519" | "58CF79" | "68B6B3" | "782184" | "8C4B14"
        | "94B97E" | "9C9C1F" | "A4CF12" | "C82E18" | "D8F15B" | "EC6260" => {
            "Espressif Systems (ESP8266 / ESP32 / Tuya / Smart Socket)".into()
        }

        "B827EB" | "DCA632" | "28CDC1" => {
            "Raspberry Pi Foundation (Microcomputer / Pi-hole)".into()
        }
        "34EA34" => "ITEAD Intelligent Systems (Sonoff Smart Switch)".into(),
        "04CF8C" | "54EF44" | "6490C1" => "Lumi United Technology (Aqara Smart Hub)".into(),
        "780F77" | "EC0BAE" => "Broadlink Technology (Smart IR Remote / Switch)".into(),
        "001788" | "ECB5FA" => crate::modules::i18n::tr(
            "Philips Hue (Đèn thông minh)",
            "Philips Hue (Smart Lighting)",
            "Philips Hue (智能照明)",
        )
        .into(),
        "3C286D" | "FC65DE" | "001A11" | "F88FCA" => "Google LLC (Nest Hub / Chromecast)".into(),
        "68FF7B" | "74C246" | "FC6B9F" => "Amazon Technologies (Echo Dot / Fire TV Stick)".into(),

        // --- Printers & Office Equipment (Canon, Brother, Epson, Xerox) ---
        "000085" | "180CAC" | "7085C2" => "Canon Inc. (Máy in / Máy quét / ImageRunner)".into(),
        "008077" | "30055C" | "80A589" | "E45F01" => {
            "Brother Industries (Máy in đa năng / Fax)".into()
        }
        "000048" | "0026AB" | "64EB8C" | "AC1826" => {
            "Seiko Epson Corp. (Máy in phun màu EcoTank)".into()
        }
        "0000AA" | "0000C8" => "Xerox Corp. (Máy photocopy / Máy in laser)".into(),

        // --- Gaming Consoles (Nintendo, PlayStation, Xbox) ---
        "0009BF" | "001656" | "0017AB" | "0019FD" | "001BEA" | "001F32" | "002147" | "00224C"
        | "0022AA" | "002331" | "00241E" | "002444" | "0025A0" | "002659" | "342FBD" | "7CBB8A"
        | "9458CB" | "98B6E9" | "B88AEC" | "D86BF7" | "E00C7F" | "E0E751" => {
            "Nintendo Co., Ltd. (Switch / Wii)".into()
        }
        "7C1E52" | "DCB4C4" | "F06E0B" => "Microsoft Xbox (Xbox One / Series X/S)".into(),

        // --- Virtualization & Containers (VMware, VirtualBox, Hyper-V, Docker/WSL, QEMU/KVM) ---
        "000C29" | "005056" => "VMware Inc. (Máy ảo ESXi / Workstation)".into(),
        "080027" => "Oracle VirtualBox (Máy ảo VM)".into(),
        "00155D" => "Microsoft Hyper-V / WSL2 (Máy ảo Windows)".into(),
        "0242AC" => "Docker Container (Mạng cầu ảo)".into(),

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
        assert!(lookup_vendor("38:AF:29:11:22:33").contains("Dahua"));
        assert!(lookup_vendor("00:0A:3A:AA:BB:CC").contains("TP-Link"));
        assert!(lookup_vendor("00:00:00:00:00:00").contains("Cục bộ"));
        assert!(lookup_vendor("00:00:00").contains("Cục bộ"));
        assert!(lookup_vendor("00:00").contains("Không xác định"));
    }

    #[test]
    fn test_lookup_vendor_vietnam_isps_and_extended() {
        assert!(lookup_vendor("00:0C:43:11:22:33").contains("VNPT"));
        assert!(lookup_vendor("00:1A:79:11:22:33").contains("Viettel"));
        assert!(lookup_vendor("00:19:A8:11:22:33").contains("FPT"));
        assert!(lookup_vendor("08:00:27:11:22:33").contains("VirtualBox"));
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

    #[test]
    fn test_perf_lookup_vendor() {
        crate::modules::perf::measure("oui_db::lookup_vendor", 200_000, || {
            std::hint::black_box(lookup_vendor("3C:28:6D:AA:BB:CC"));
            std::hint::black_box(lookup_vendor("00:00"));
        });
    }
}
