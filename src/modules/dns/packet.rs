use super::*;

impl DnsBlocker {
    pub fn parse_query_info(pkt: &[u8]) -> Option<(String, u16)> {
        if pkt.len() < 12 {
            return None;
        }
        let mut pos = 12;
        let mut labels = Vec::new();
        let mut loop_count = 0;
        while pos < pkt.len() {
            loop_count += 1;
            if loop_count > 128 {
                return None;
            }
            let len = pkt[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                // Compressed QNAME in a query: reject outright instead of
                // skipping, so spoofed pointers cannot desync parsing.
                return None;
            }
            pos += 1;
            if pos + len > pkt.len() {
                return None;
            }
            labels.push(std::str::from_utf8(&pkt[pos..pos + len]).ok()?.to_string());
            pos += len;
        }
        if labels.is_empty() || pos + 2 > pkt.len() {
            None
        } else {
            let qtype = ((pkt[pos] as u16) << 8) | (pkt[pos + 1] as u16);
            Some((labels.join("."), qtype))
        }
    }

    #[allow(dead_code)]
    pub fn parse_query_name(pkt: &[u8]) -> Option<String> {
        Self::parse_query_info(pkt).map(|(name, _)| name)
    }

    pub fn response_matches_query(resp: &[u8], query: &[u8]) -> bool {
        if resp.len() < 12 || query.len() < 12 {
            return false;
        }
        if resp[0] != query[0] || resp[1] != query[1] {
            return false;
        }
        if resp[2] & 0x80 == 0 {
            return false;
        }
        match (Self::parse_query_info(query), Self::parse_query_info(resp)) {
            (Some((q_name, q_type)), Some((r_name, r_type))) => {
                r_name.eq_ignore_ascii_case(&q_name) && r_type == q_type
            }
            _ => false,
        }
    }

    pub fn extract_min_ttl(resp: &[u8]) -> Option<u32> {
        if resp.len() < 12 {
            return None;
        }
        let an_count = u16::from_be_bytes([resp[6], resp[7]]);
        if an_count == 0 {
            return None;
        }
        let mut pos = 12;
        let mut guard = 0;
        while pos < resp.len() {
            guard += 1;
            if guard > 128 {
                return None;
            }
            let len_byte = resp[pos];
            if len_byte & 0xC0 == 0xC0 {
                pos += 2;
                break;
            } else if len_byte == 0 {
                pos += 1;
                break;
            } else {
                pos += 1 + len_byte as usize;
            }
        }
        pos += 4;
        let mut min_ttl = u32::MAX;
        for _ in 0..an_count {
            guard += 1;
            if guard > 256 {
                break;
            }
            if pos >= resp.len() {
                break;
            }
            if resp[pos] & 0xC0 == 0xC0 {
                pos += 2;
            } else {
                let mut label_guard = 0;
                while pos < resp.len() {
                    label_guard += 1;
                    if label_guard > 128 {
                        return None;
                    }
                    let l = resp[pos];
                    // Mid-name compression pointer (e.g. `3www` + `0xC00C`).
                    // Treating 0xC0 as a label length of 192 desyncs the parser.
                    if l & 0xC0 == 0xC0 {
                        pos += 2;
                        break;
                    }
                    if l & 0xC0 != 0 {
                        return None;
                    }
                    if l == 0 {
                        pos += 1;
                        break;
                    }
                    pos += 1 + l as usize;
                }
            }
            if pos + 10 > resp.len() {
                break;
            }
            let ttl =
                u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
            min_ttl = min_ttl.min(ttl);
            let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10 + rdlength;
        }
        if min_ttl == u32::MAX {
            None
        } else {
            Some(min_ttl)
        }
    }
}
impl DnsBlocker {
    pub fn build_nxdomain(q: &[u8]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r[3] = (r[3] & 0xF0) | 0x03;
        r[6..12].fill(0);
        Some(r)
    }

    pub fn build_sinkhole_a_record(q: &[u8], ip: [u8; 4]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = Vec::with_capacity(q.len() + 16);
        r.extend_from_slice(&q[0..2]);
        r.push(0x81);
        r.push(0x80);
        // Force QDCOUNT=1; never copy potentially-spoofed q[4..6].
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00]);
        r.extend_from_slice(&[0x00, 0x00]);

        let mut pos = 12;
        let mut loop_count = 0;
        while pos < q.len() {
            loop_count += 1;
            if loop_count > 128 {
                return None;
            }
            let len = q[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            if pos + 1 + len > q.len() {
                return None;
            }
            pos += 1 + len;
        }
        if pos + 4 > q.len() {
            return None;
        }
        pos += 4;
        r.extend_from_slice(&q[12..pos]);

        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
        r.extend_from_slice(&[0x00, 0x04]);
        r.extend_from_slice(&ip);

        Some(r)
    }

    pub fn build_sinkhole_aaaa_record(q: &[u8], ip6: [u8; 16]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = Vec::with_capacity(q.len() + 28);
        r.extend_from_slice(&q[0..2]);
        r.push(0x81);
        r.push(0x80);
        // Force QDCOUNT=1; never copy potentially-spoofed q[4..6].
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00]);
        r.extend_from_slice(&[0x00, 0x00]);

        let mut pos = 12;
        let mut loop_count = 0;
        while pos < q.len() {
            loop_count += 1;
            if loop_count > 128 {
                return None;
            }
            let len = q[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            if pos + 1 + len > q.len() {
                return None;
            }
            pos += 1 + len;
        }
        if pos + 4 > q.len() {
            return None;
        }
        pos += 4;
        r.extend_from_slice(&q[12..pos]);

        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&[0x00, 0x1C]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
        r.extend_from_slice(&[0x00, 0x10]);
        r.extend_from_slice(&ip6);

        Some(r)
    }

    pub fn build_servfail(q: &[u8]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r[3] = (r[3] & 0xF0) | 0x02;
        r[6..12].fill(0);
        Some(r)
    }

    pub fn is_legit_local_domain(domain: &str) -> bool {
        let d = domain.to_lowercase();
        let trimmed = d.trim_end_matches('.');
        trimmed == "localhost"
            || trimmed.ends_with(".localhost")
            || trimmed.ends_with(".local")
            || trimmed.ends_with(".lan")
            || trimmed.ends_with(".home")
            || trimmed.ends_with(".internal")
            || trimmed.ends_with(".intranet")
            || trimmed.ends_with(".arpa")
            || trimmed.ends_with(".localdomain")
    }

    pub fn is_private_ip_record(resp: &[u8]) -> bool {
        if resp.len() < 12 {
            return false;
        }
        let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
        if ancount == 0 {
            return false;
        }

        let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
        let mut pos = 12;
        for _ in 0..qdcount {
            while pos < resp.len() {
                let len = resp[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if len & 0xC0 == 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + len;
            }
            if pos + 4 > resp.len() {
                return false;
            }
            pos += 4;
        }

        for _ in 0..ancount {
            if pos >= resp.len() {
                break;
            }
            while pos < resp.len() {
                let len = resp[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if len & 0xC0 == 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + len;
            }
            if pos + 10 > resp.len() {
                break;
            }
            let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > resp.len() {
                break;
            }

            if rtype == 1 && rdlength == 4 {
                let ip = &resp[pos..pos + 4];
                if Self::is_private_ipv4(ip[0], ip[1], ip[2], ip[3]) {
                    return true;
                }
            } else if rtype == 28 && rdlength == 16 {
                let ip6 = &resp[pos..pos + 16];
                if ip6[0..10].iter().all(|&b| b == 0) && ip6[10] == 0xff && ip6[11] == 0xff {
                    if Self::is_private_ipv4(ip6[12], ip6[13], ip6[14], ip6[15]) {
                        return true;
                    }
                } else if (ip6[..15].iter().all(|&b| b == 0) && ip6[15] == 1)
                    || (ip6[0] == 0xfe && (ip6[1] & 0xc0) == 0x80)
                    || ((ip6[0] & 0xfe) == 0xfc)
                {
                    return true;
                }
            }
            pos += rdlength;
        }

        false
    }

    fn is_private_ipv4(a: u8, b: u8, c: u8, d: u8) -> bool {
        // RFC1918, loopback, link-local, 0/8, CGNAT 100.64/10, benchmarking 198.18/15
        a == 0
            || a == 10
            || a == 127
            || (a == 100 && (b & 0xc0) == 64)
            || (a == 169 && b == 254)
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 198 && (b == 18 || b == 19))
            || (a == 192 && b == 0 && c == 0)
            || (a == 255 && b == 255 && c == 255 && d == 255)
    }
}
