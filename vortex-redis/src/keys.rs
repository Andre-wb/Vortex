#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpace {
    prefix: String,
    domain: &'static str,
}

impl KeySpace {
    pub fn new(prefix: impl Into<String>, domain: &'static str) -> Self {
        KeySpace {
            prefix: prefix.into(),
            domain,
        }
    }

    pub fn key(&self, name: &str) -> String {
        format!("{}:{}:{}", self.prefix, self.domain, name)
    }

    pub fn member_key(&self, name: &str, member: &str) -> String {
        format!("{}:{}:{}:{}", self.prefix, self.domain, name, member)
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn domain(&self) -> &'static str {
        self.domain
    }
}

#[cfg(test)]
mod tests {
    use super::KeySpace;

    #[test]
    fn every_key_carries_the_deployment_prefix_and_domain() {
        let space = KeySpace::new("vortex", "bmp");
        assert_eq!(space.key("index"), "vortex:bmp:index");
        assert_eq!(space.member_key("box", "abcd"), "vortex:bmp:box:abcd");
    }

    #[test]
    fn two_domains_never_collide_under_one_prefix() {
        let bmp = KeySpace::new("vortex", "bmp");
        let waf = KeySpace::new("vortex", "waf");
        assert_ne!(bmp.key("rate"), waf.key("rate"));
    }
}
