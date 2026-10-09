use super::{interface::InterfaceTarget, BatchOptions, BatchResult};
use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection};
use std::{path::Path, time::Duration};

const SCHEMA_VERSION: i64 = 1;

pub(super) struct Store {
    conn: Connection,
}

impl Store {
    pub(super) fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open SQLite database {path}"))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", true)?;
        let _: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        let mut store = Self { conn };
        store.migrate()?;
        set_private_permissions(path)?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let current: i64 = self.conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current > SCHEMA_VERSION {
            return Err(anyhow!(
                "database schema version {current} is newer than supported version {SCHEMA_VERSION}"
            ));
        }

        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                check_url TEXT NOT NULL,
                requested_protocol TEXT NOT NULL,
                concurrency INTEGER NOT NULL,
                timeout_seconds INTEGER NOT NULL,
                proxy_count INTEGER NOT NULL,
                interface_count INTEGER NOT NULL,
                valid_count INTEGER NOT NULL DEFAULT 0,
                invalid_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS interface_runs (
                id INTEGER PRIMARY KEY,
                run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                interface_name TEXT NOT NULL,
                local_ips TEXT NOT NULL,
                tester_ip TEXT
            );

            CREATE TABLE IF NOT EXISTS proxy_checks (
                id INTEGER PRIMARY KEY,
                interface_run_id INTEGER NOT NULL REFERENCES interface_runs(id) ON DELETE CASCADE,
                source TEXT NOT NULL,
                input_redacted TEXT NOT NULL,
                requested_protocol TEXT NOT NULL,
                detected_protocol TEXT,
                proxy_host TEXT NOT NULL,
                tested_ip TEXT,
                proxy_port INTEGER NOT NULL,
                valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
                latency_ms INTEGER,
                exit_ip TEXT,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS stage_results (
                id INTEGER PRIMARY KEY,
                proxy_check_id INTEGER NOT NULL REFERENCES proxy_checks(id) ON DELETE CASCADE,
                stage INTEGER NOT NULL,
                stage_name TEXT NOT NULL,
                status TEXT NOT NULL,
                duration_ms INTEGER,
                error TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_interface_runs_run
                ON interface_runs(run_id);
            CREATE INDEX IF NOT EXISTS idx_proxy_checks_interface_valid
                ON proxy_checks(interface_run_id, valid);
            CREATE INDEX IF NOT EXISTS idx_proxy_checks_endpoint
                ON proxy_checks(proxy_host, proxy_port);
            CREATE INDEX IF NOT EXISTS idx_stage_results_check_stage
                ON stage_results(proxy_check_id, stage);

            INSERT OR IGNORE INTO schema_meta(key, value)
                VALUES ('schema_version', '1');
            ",
        )?;
        self.conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    pub(super) fn start_run(
        &self, options: &BatchOptions, proxy_count: usize, interface_count: usize,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO runs(
                check_url, requested_protocol, concurrency, timeout_seconds,
                proxy_count, interface_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                options.check_url,
                options.default_protocol,
                usize_to_i64(options.concurrency),
                u64_to_i64(options.timeout_secs),
                usize_to_i64(proxy_count),
                usize_to_i64(interface_count),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub(super) fn start_interface_run(
        &self, run_id: i64, target: &InterfaceTarget, tester_ip: Option<std::net::IpAddr>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO interface_runs(run_id, interface_name, local_ips, tester_ip)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                run_id,
                target.label(),
                target.local_ips_text(),
                tester_ip.map(|ip| ip.to_string())
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub(super) fn insert_result(&self, interface_run_id: i64, result: &BatchResult) -> Result<()> {
        let detected_protocol = result.metrics.as_ref().map(|m| m.protocol.to_string());
        let latency_ms = result.metrics.as_ref().map(|m| u128_to_i64(m.latency_ms));
        let exit_ip = result.metrics.as_ref().map(|m| m.exit_ip.to_string());
        let valid = i64::from(result.valid());

        self.conn.execute(
            "INSERT INTO proxy_checks(
                interface_run_id, source, input_redacted, requested_protocol,
                detected_protocol, proxy_host, tested_ip, proxy_port, valid,
                latency_ms, exit_ip, error
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                interface_run_id,
                result.proxy.report_source(),
                result.proxy.report_input(),
                result.proxy.protocol.to_string(),
                detected_protocol,
                result.proxy.host,
                result.tested_ip.map(|ip| ip.to_string()),
                i64::from(result.proxy.port),
                valid,
                latency_ms,
                exit_ip,
                result.error,
            ],
        )?;
        let check_id = self.conn.last_insert_rowid();
        let status = if result.valid() { "pass" } else { "fail" };
        self.conn.execute(
            "INSERT INTO stage_results(
                proxy_check_id, stage, stage_name, status, duration_ms, error
             ) VALUES (?1, 3, 'proxy_http_validation', ?2, ?3, ?4)",
            params![check_id, status, latency_ms, result.error],
        )?;
        Ok(())
    }

    pub(super) fn finish_run(&self, run_id: i64, valid: usize, invalid: usize) -> Result<()> {
        self.conn.execute(
            "UPDATE runs
             SET completed_at = CURRENT_TIMESTAMP, valid_count = ?2, invalid_count = ?3
             WHERE id = ?1",
            params![run_id, usize_to_i64(valid), usize_to_i64(invalid)],
        )?;
        Ok(())
    }
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u128_to_i64(value: u128) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn set_private_permissions(path: &str) -> Result<()> {
    if path == ":memory:" {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(Path::new(path), std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set private permissions on database {path}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{ProbeMetrics, ProxyProtocol, ProxySpec};
    use std::net::{IpAddr, Ipv4Addr};

    fn options() -> BatchOptions {
        BatchOptions {
            proxy_files: vec!["proxies.txt".into()],
            source_lists: vec![],
            source_urls: vec![],
            output: "out.tsv".into(),
            valid_output: None,
            database: ":memory:".into(),
            interfaces: vec![],
            all_interfaces: false,
            default_protocol: "auto".into(),
            concurrency: 4,
            timeout_secs: 5,
            check_url: "http://127.0.0.1/ip".into(),
        }
    }

    #[test]
    fn schema_and_redacted_result_are_persisted() {
        let store = Store::open(":memory:").unwrap();
        let run_id = store.start_run(&options(), 1, 1).unwrap();
        let target = InterfaceTarget::default_route();
        let interface_run_id = store.start_interface_run(run_id, &target, None).unwrap();
        let result = BatchResult {
            proxy: ProxySpec {
                raw: "socks5://user:secret@example.com:1080".into(),
                source: "https://user:secret@example.com/list?token=abc".into(),
                host: "example.com".into(),
                port: 1080,
                username: Some("user".into()),
                password: Some("secret".into()),
                protocol: ProxyProtocol::Socks5,
            },
            tested_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            metrics: Some(ProbeMetrics {
                protocol: ProxyProtocol::Socks5,
                latency_ms: 12,
                exit_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            }),
            error: None,
        };
        store.insert_result(interface_run_id, &result).unwrap();
        store.finish_run(run_id, 1, 0).unwrap();

        let version: i64 =
            store.conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        let (source, input): (String, String) = store
            .conn
            .query_row("SELECT source, input_redacted FROM proxy_checks LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(source, "https://example.com/list");
        assert_eq!(input, "socks5://example.com:1080");
        assert!(!source.contains("secret"));
        assert!(!input.contains("secret"));
    }
}
