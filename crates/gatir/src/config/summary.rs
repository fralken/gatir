//! The description of a configuration that `gatir config check` prints and
//! the debug log shows: never a secret value.

use super::Config;

impl Config {
    /// A multi-line description that never includes secret values.
    pub fn summary(&self) -> String {
        let listen = join(self.listen.iter());
        let parents = match (&self.pac, self.parents.is_empty()) {
            (Some(pac), _) if pac.overrides.is_empty() => {
                format!("chosen by the PAC script at {}", pac.location)
            }
            (Some(pac), _) => format!(
                "chosen by the PAC script at {}, with {} override{}",
                pac.location,
                pac.overrides.len(),
                if pac.overrides.len() == 1 { "" } else { "s" }
            ),
            (None, true) => "none (direct connections)".to_owned(),
            (None, false) => join(self.parents.iter()),
        };
        let credentials = match &self.credentials {
            None => "none".to_owned(),
            Some(c) => {
                let identity = if c.domain.is_empty() {
                    c.username.clone()
                } else {
                    format!("{}@{}", c.username, c.domain)
                };
                let base = match &c.secret {
                    Some(secret) => format!(
                        "{identity}, method {}, secret: {} (hidden)",
                        c.method.as_str(),
                        secret.kind()
                    ),
                    None => format!("logged-in identity, method {}", c.method.as_str()),
                };
                if c.origin_hosts.entries().is_empty() {
                    base
                } else {
                    format!(
                        "{base}, also to {} directly",
                        join(c.origin_hosts.entries().iter())
                    )
                }
            }
        };
        let access = if self.access.rules().is_empty() {
            format!(
                "default {}, no rules",
                self.access.default_action().as_str()
            )
        } else {
            let rules = join(
                self.access
                    .rules()
                    .iter()
                    .map(|rule| format!("{} {}", rule.action.as_str(), rule.source)),
            );
            format!(
                "default {}; first match wins: {rules}",
                self.access.default_action().as_str()
            )
        };
        let no_proxy = if self.no_proxy.entries().is_empty() {
            "none".to_owned()
        } else {
            join(self.no_proxy.entries().iter())
        };
        // Names only: the values are secrets.
        let headers = if self.request_headers.is_empty() {
            "none".to_owned()
        } else {
            join(self.request_headers.iter().map(|(name, _)| name))
        };
        let tunnels = if self.tunnels.is_empty() {
            "none".to_owned()
        } else {
            join(self.tunnels.iter())
        };
        let socks5 = match &self.socks5 {
            None => "none".to_owned(),
            Some(socks5) => format!(
                "{}, {}",
                join(socks5.listen.iter()),
                match &socks5.credentials {
                    None => "no user name or password asked".to_owned(),
                    Some(credentials) => format!(
                        "user name {:?} and a password asked, password hidden",
                        credentials.username
                    ),
                }
            ),
        };
        let timeouts = format!(
            "connect {}s, client idle {}s, response {}s, tunnel idle {}s, shutdown grace {}s",
            self.timeouts.connect.as_secs(),
            self.timeouts.client_idle.as_secs(),
            self.timeouts.response.as_secs(),
            self.timeouts.tunnel_idle.as_secs(),
            self.timeouts.shutdown_grace.as_secs()
        );
        format!(
            "listen:      {listen}\nparents:     {parents}\ncredentials: {credentials}\n\
             access:      {access}\nno_proxy:    {no_proxy}\nheaders:     {headers} (set on requests through a parent)\ntunnels:     {tunnels}\nsocks5:      {socks5}\n\
             timeouts:    {timeouts}\nlog level:   {}",
            self.log_level.as_str()
        )
    }
}

fn join<T: std::fmt::Display>(items: impl Iterator<Item = T>) -> String {
    items.map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}
