use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use serde::Deserialize;

#[derive(Deserialize)]
struct DnsAllowlistConfig {
    allowed_domains: Vec<String>,
}

pub struct DnsFilter {
    exact_domains: HashSet<String>,
    wildcard_suffixes: Vec<String>,
    pub learned_ips: HashSet<Ipv4Addr>,
}

impl DnsFilter {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: DnsAllowlistConfig = serde_yaml::from_str(&content)?;
        let mut exact_domains = HashSet::new();
        let mut wildcard_suffixes = Vec::new();
        for domain in config.allowed_domains {
            let domain = domain.to_lowercase();
            if let Some(suffix) = domain.strip_prefix("*.") {
                wildcard_suffixes.push(format!(".{suffix}"));
                exact_domains.insert(suffix.to_string());
            } else {
                exact_domains.insert(domain);
            }
        }
        Ok(DnsFilter { exact_domains, wildcard_suffixes, learned_ips: HashSet::new() })
    }

    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let domain = domain.trim_end_matches('.');
        if self.exact_domains.contains(domain) {
            return true;
        }
        for suffix in &self.wildcard_suffixes {
            if domain.ends_with(suffix.as_str()) {
                return true;
            }
        }
        false
    }

    pub fn learn_ip(&mut self, ip: Ipv4Addr) {
        self.learned_ips.insert(ip);
    }

    pub fn is_learned_ip(&self, ip: &Ipv4Addr) -> bool {
        self.learned_ips.contains(ip)
    }

    pub fn extract_query_domain(dns_payload: &[u8]) -> Option<String> {
        let packet = simple_dns::Packet::parse(dns_payload).ok()?;
        let question = packet.questions.first()?;
        Some(question.qname.to_string().to_lowercase())
    }

    pub fn learn_from_dns_response(&mut self, dns_payload: &[u8]) {
        let packet = match simple_dns::Packet::parse(dns_payload) {
            Ok(p) => p,
            Err(_) => return,
        };
        let domain_allowed = packet
            .questions
            .first()
            .map(|q| self.is_domain_allowed(&q.qname.to_string()))
            .unwrap_or(false);
        if !domain_allowed {
            return;
        }
        for answer in &packet.answers {
            if let simple_dns::rdata::RData::A(a) = &answer.rdata {
                self.learn_ip(Ipv4Addr::from(a.address));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_filter(domains: &[&str]) -> DnsFilter {
        let yaml = format!(
            "allowed_domains:\n{}",
            domains.iter().map(|d| format!("  - {d}")).collect::<Vec<_>>().join("\n")
        );
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        DnsFilter::from_file(file.path()).unwrap()
    }

    #[test]
    fn test_exact_domain_allowed() {
        let f = make_filter(&["api.github.com"]);
        assert!(f.is_domain_allowed("api.github.com"));
        assert!(!f.is_domain_allowed("github.com"));
    }

    #[test]
    fn test_wildcard_domain_matching() {
        let f = make_filter(&["*.apple.com"]);
        assert!(f.is_domain_allowed("developer.apple.com"));
        assert!(f.is_domain_allowed("apple.com"));
        assert!(!f.is_domain_allowed("evil-apple.com"));
    }

    #[test]
    fn test_case_insensitive() {
        let f = make_filter(&["api.github.com"]);
        assert!(f.is_domain_allowed("API.GITHUB.COM"));
    }

    #[test]
    fn test_learned_ip() {
        let mut f = make_filter(&["api.github.com"]);
        let ip: Ipv4Addr = "140.82.114.4".parse().unwrap();
        assert!(!f.is_learned_ip(&ip));
        f.learn_ip(ip);
        assert!(f.is_learned_ip(&ip));
    }

    #[test]
    fn test_trailing_dot_stripped() {
        let f = make_filter(&["api.github.com"]);
        assert!(f.is_domain_allowed("api.github.com."));
    }
}
