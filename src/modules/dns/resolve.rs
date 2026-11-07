use super::*;

impl DnsBlocker {
    pub fn build_a_query(host: &str) -> Option<Vec<u8>> {
        let host = host.trim().trim_end_matches('.');
        if host.is_empty() {
            return None;
        }
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in host.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        Some(query)
    }

    pub fn parse_first_a_record(resp: &[u8]) -> Option<std::net::IpAddr> {
        if resp.len() < 12 {
            return None;
        }
        let questions = u16::from_be_bytes([resp[4], resp[5]]);
        let answers = u16::from_be_bytes([resp[6], resp[7]]);
        let mut cursor = 12usize;
        for _ in 0..questions {
            while cursor < resp.len() {
                let len = resp[cursor] as usize;
                cursor += 1;
                if len == 0 {
                    break;
                }
                if len & 0xC0 == 0xC0 {
                    cursor += 1;
                    break;
                }
                cursor += len;
            }
            cursor += 4;
        }
        for _ in 0..answers {
            if cursor >= resp.len() {
                return None;
            }
            let label = resp[cursor];
            if label & 0xC0 == 0xC0 {
                cursor += 2;
            } else {
                loop {
                    if cursor >= resp.len() {
                        return None;
                    }
                    let len = resp[cursor] as usize;
                    cursor += 1;
                    if len == 0 {
                        break;
                    }
                    cursor += len;
                }
            }
            if cursor + 10 > resp.len() {
                return None;
            }
            let rtype = u16::from_be_bytes([resp[cursor], resp[cursor + 1]]);
            let rdlen = u16::from_be_bytes([resp[cursor + 8], resp[cursor + 9]]) as usize;
            cursor += 10;
            if cursor + rdlen > resp.len() {
                return None;
            }
            if rtype == 1 && rdlen == 4 {
                let octets = [
                    resp[cursor],
                    resp[cursor + 1],
                    resp[cursor + 2],
                    resp[cursor + 3],
                ];
                return Some(std::net::IpAddr::from(octets));
            }
            cursor += rdlen;
        }
        None
    }

    pub fn host_of(url: &str) -> Option<String> {
        let without_scheme = url.split("://").last().unwrap_or(url);
        let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = host.split(':').next().unwrap_or(host);
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    }

    pub async fn resolve_host_via_upstream(
        client: &reqwest::Client,
        host: &str,
        doh_urls: &[String],
    ) -> Option<std::net::IpAddr> {
        let query = Self::build_a_query(host)?;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        for url in doh_urls {
            let client = client.clone();
            let url = url.clone();
            let query = query.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let resp = tokio::time::timeout(
                    Duration::from_millis(1500),
                    client
                        .post(&url)
                        .header("content-type", "application/dns-message")
                        .header("accept", "application/dns-message")
                        .body(query)
                        .send(),
                )
                .await;
                if let Ok(Ok(resp)) = resp {
                    if let Ok(bytes) = resp.bytes().await {
                        let _ = tx.send(bytes.to_vec()).await;
                    }
                }
            });
        }
        drop(tx);
        let response = rx.recv().await?;
        Self::parse_first_a_record(&response)
    }

    pub(super) async fn forward_parallel_racing(
        &self,
        query_packet: &[u8],
        doh_urls: &[String],
    ) -> Option<Vec<u8>> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);

        for url in doh_urls.iter() {
            let client = self.http_client.clone();
            let url = url.clone();
            let pkt = query_packet.to_vec();
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                let res = tokio::time::timeout(
                    Duration::from_millis(800),
                    client
                        .post(&url)
                        .header("Content-Type", "application/dns-message")
                        .header("Accept", "application/dns-message")
                        .body(pkt.clone())
                        .send(),
                )
                .await;

                if let Ok(Ok(resp)) = res {
                    if resp.status().is_success() {
                        // Cap DoH body and keep the read under the same budget.
                        const MAX_DOH_BYTES: usize = 64 * 1024;
                        let read =
                            tokio::time::timeout(Duration::from_millis(800), resp.bytes()).await;
                        if let Ok(Ok(bytes)) = read {
                            if bytes.len() <= MAX_DOH_BYTES
                                && Self::response_matches_query(&bytes, &pkt)
                            {
                                let _ = tx_clone.send(bytes.to_vec()).await;
                            }
                        }
                    }
                }
            });
        }

        drop(tx);

        match tokio::time::timeout(Duration::from_millis(1200), rx.recv()).await {
            Ok(Some(resp)) => Some(resp),
            _ => None,
        }
    }
}
