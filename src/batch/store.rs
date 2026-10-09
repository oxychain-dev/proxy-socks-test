use super::{interface::InterfaceTarget, BatchOptions, BatchResult, IpMetadata, StageResult};
use anyhow::{anyhow, Context, Result};
use rusqlite::{named_params, params, Connection};
use std::{path::Path, time::Duration};

const SCHEMA_VERSION: i64 = 3;

const V1_SCHEMA: &str = "
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
";

const V2_MIGRATION: &str = "
ALTER TABLE runs ADD COLUMN profile TEXT NOT NULL DEFAULT 'basic';
ALTER TABLE runs ADD COLUMN latency_samples INTEGER NOT NULL DEFAULT 1;
ALTER TABLE runs ADD COLUMN download_url TEXT;
ALTER TABLE runs ADD COLUMN upload_url TEXT;
ALTER TABLE runs ADD COLUMN download_bytes INTEGER;
ALTER TABLE runs ADD COLUMN upload_bytes INTEGER;

ALTER TABLE proxy_checks ADD COLUMN resolved_ips TEXT NOT NULL DEFAULT '';
ALTER TABLE proxy_checks ADD COLUMN reverse_dns TEXT;
ALTER TABLE proxy_checks ADD COLUMN tcp_connect_ms INTEGER;
ALTER TABLE proxy_checks ADD COLUMN latency_samples_ms TEXT;
ALTER TABLE proxy_checks ADD COLUMN latency_p50_ms REAL;
ALTER TABLE proxy_checks ADD COLUMN latency_p95_ms REAL;
ALTER TABLE proxy_checks ADD COLUMN jitter_ms REAL;
ALTER TABLE proxy_checks ADD COLUMN download_mbps REAL;
ALTER TABLE proxy_checks ADD COLUMN upload_mbps REAL;
ALTER TABLE proxy_checks ADD COLUMN exit_ip_changed INTEGER;

ALTER TABLE proxy_checks ADD COLUMN endpoint_ip_info_json TEXT;
ALTER TABLE proxy_checks ADD COLUMN endpoint_country TEXT;
ALTER TABLE proxy_checks ADD COLUMN endpoint_region TEXT;
ALTER TABLE proxy_checks ADD COLUMN endpoint_city TEXT;
ALTER TABLE proxy_checks ADD COLUMN endpoint_org TEXT;
ALTER TABLE proxy_checks ADD COLUMN endpoint_asn TEXT;
ALTER TABLE proxy_checks ADD COLUMN endpoint_timezone TEXT;

ALTER TABLE proxy_checks ADD COLUMN exit_ip_info_json TEXT;
ALTER TABLE proxy_checks ADD COLUMN exit_country TEXT;
ALTER TABLE proxy_checks ADD COLUMN exit_region TEXT;
ALTER TABLE proxy_checks ADD COLUMN exit_city TEXT;
ALTER TABLE proxy_checks ADD COLUMN exit_org TEXT;
ALTER TABLE proxy_checks ADD COLUMN exit_asn TEXT;
ALTER TABLE proxy_checks ADD COLUMN exit_timezone TEXT;

CREATE INDEX IF NOT EXISTS idx_proxy_checks_tested_ip
    ON proxy_checks(tested_ip);
CREATE INDEX IF NOT EXISTS idx_proxy_checks_exit_ip
    ON proxy_checks(exit_ip);
";
const V3_MIGRATION: &str = "
CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    source_type TEXT NOT NULL CHECK (source_type IN ('proxy-list', 'source-list')),
    source_url TEXT NOT NULL,
    source_display TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
    interface_names TEXT NOT NULL DEFAULT '',
    all_interfaces INTEGER NOT NULL DEFAULT 0 CHECK (all_interfaces IN (0, 1)),
    profile TEXT NOT NULL,
    concurrency INTEGER NOT NULL,
    timeout_seconds INTEGER NOT NULL,
    check_url TEXT NOT NULL,
    latency_samples INTEGER NOT NULL,
    download_url TEXT NOT NULL,
    upload_url TEXT NOT NULL,
    download_bytes INTEGER NOT NULL,
    upload_bytes INTEGER NOT NULL,
    ip_info_url_template TEXT,
    etag TEXT,
    last_modified TEXT,
    cached_payload TEXT,
    last_fetch_status INTEGER,
    last_fetch_at INTEGER,
    last_success_at INTEGER,
    last_error TEXT,
    item_count INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    next_run_at INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE runs ADD COLUMN subscription_id INTEGER
    REFERENCES subscriptions(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS subscription_runs (
    id INTEGER PRIMARY KEY,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    fetched_at INTEGER NOT NULL,
    http_status INTEGER,
    not_modified INTEGER NOT NULL DEFAULT 0 CHECK (not_modified IN (0, 1)),
    item_count INTEGER,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_due
    ON subscriptions(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_runs_subscription
    ON runs(subscription_id);
CREATE INDEX IF NOT EXISTS idx_subscription_runs_subscription
    ON subscription_runs(subscription_id, fetched_at);
";


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
        let mut current: i64 =
            self.conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current > SCHEMA_VERSION {
            return Err(anyhow!(
                "database schema version {current} is newer than supported version {SCHEMA_VERSION}"
            ));
        }

        if current == 0 {
            self.conn.execute_batch(V1_SCHEMA)?;
            self.conn.pragma_update(None, "user_version", 1)?;
            current = 1;
        }

        if current < 2 {
            let tx = self.conn.transaction()?;
            tx.execute_batch(V2_MIGRATION)?;
            tx.execute(
                "INSERT INTO schema_meta(key, value) VALUES ('schema_version', '2')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )?;
            tx.pragma_update(None, "user_version", 2)?;
            tx.commit()?;
            current = 2;
        }

        if current < 3 {
            let tx = self.conn.transaction()?;
            tx.execute_batch(V3_MIGRATION)?;
            tx.execute(
                "INSERT INTO schema_meta(key, value) VALUES ('schema_version', '3')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )?;
            tx.pragma_update(None, "user_version", 3)?;
            tx.commit()?;
        }

        Ok(())
    }

    pub(super) fn start_run(
        &self, options: &BatchOptions, proxy_count: usize, interface_count: usize,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO runs(
                check_url, requested_protocol, concurrency, timeout_seconds,
                proxy_count, interface_count, profile, latency_samples,
                download_url, upload_url, download_bytes, upload_bytes, subscription_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                options.check_url,
                options.default_protocol,
                usize_to_i64(options.concurrency),
                u64_to_i64(options.timeout_secs),
                usize_to_i64(proxy_count),
                usize_to_i64(interface_count),
                options.profile,
                usize_to_i64(options.latency_samples),
                options.download_url,
                options.upload_url,
                u64_to_i64(options.download_bytes),
                u64_to_i64(options.upload_bytes),
                options.subscription_id,
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
        let metrics = result.metrics.as_ref();
        let detected_protocol = metrics.map(|m| m.protocol.to_string());
        let latency_ms = metrics.map(|m| u128_to_i64(m.validation_latency_ms));
        let latency_samples_ms = metrics
            .map(|m| {
                m.latency_samples_ms.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
            })
            .unwrap_or_default();
        let exit_ip = metrics.map(|m| m.exit_ip.to_string());
        let resolved_ips =
            result.resolved_ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        let endpoint_info = result.endpoint_ip_info.as_ref();
        let exit_info = metrics.and_then(|m| m.exit_ip_info.as_ref());

        self.conn.execute(
            "INSERT INTO proxy_checks(
                interface_run_id, source, input_redacted, requested_protocol,
                detected_protocol, proxy_host, tested_ip, proxy_port, valid,
                latency_ms, exit_ip, error, resolved_ips, reverse_dns, tcp_connect_ms,
                latency_samples_ms, latency_p50_ms, latency_p95_ms, jitter_ms,
                download_mbps, upload_mbps, exit_ip_changed,
                endpoint_ip_info_json, endpoint_country, endpoint_region, endpoint_city,
                endpoint_org, endpoint_asn, endpoint_timezone,
                exit_ip_info_json, exit_country, exit_region, exit_city,
                exit_org, exit_asn, exit_timezone
             ) VALUES (
                :interface_run_id, :source, :input_redacted, :requested_protocol,
                :detected_protocol, :proxy_host, :tested_ip, :proxy_port, :valid,
                :latency_ms, :exit_ip, :error, :resolved_ips, :reverse_dns, :tcp_connect_ms,
                :latency_samples_ms, :latency_p50_ms, :latency_p95_ms, :jitter_ms,
                :download_mbps, :upload_mbps, :exit_ip_changed,
                :endpoint_ip_info_json, :endpoint_country, :endpoint_region, :endpoint_city,
                :endpoint_org, :endpoint_asn, :endpoint_timezone,
                :exit_ip_info_json, :exit_country, :exit_region, :exit_city,
                :exit_org, :exit_asn, :exit_timezone
             )",
            named_params! {
                ":interface_run_id": interface_run_id,
                ":source": result.proxy.report_source(),
                ":input_redacted": result.proxy.report_input(),
                ":requested_protocol": result.proxy.protocol.to_string(),
                ":detected_protocol": detected_protocol,
                ":proxy_host": &result.proxy.host,
                ":tested_ip": result.tested_ip.map(|ip| ip.to_string()),
                ":proxy_port": i64::from(result.proxy.port),
                ":valid": i64::from(result.valid()),
                ":latency_ms": latency_ms,
                ":exit_ip": exit_ip,
                ":error": result.error.as_deref(),
                ":resolved_ips": resolved_ips,
                ":reverse_dns": result.reverse_dns.as_deref(),
                ":tcp_connect_ms": result.endpoint_connect_ms.map(u128_to_i64),
                ":latency_samples_ms": latency_samples_ms,
                ":latency_p50_ms": metrics.and_then(|m| m.latency_p50_ms),
                ":latency_p95_ms": metrics.and_then(|m| m.latency_p95_ms),
                ":jitter_ms": metrics.and_then(|m| m.jitter_ms),
                ":download_mbps": metrics.and_then(|m| m.download_mbps),
                ":upload_mbps": metrics.and_then(|m| m.upload_mbps),
                ":exit_ip_changed": metrics.map(|m| i64::from(m.exit_ip_changed)),
                ":endpoint_ip_info_json": endpoint_info.map(|m| m.raw_json.as_str()),
                ":endpoint_country": metadata_field(endpoint_info, |m| m.country.as_deref()),
                ":endpoint_region": metadata_field(endpoint_info, |m| m.region.as_deref()),
                ":endpoint_city": metadata_field(endpoint_info, |m| m.city.as_deref()),
                ":endpoint_org": metadata_field(endpoint_info, |m| m.organization.as_deref()),
                ":endpoint_asn": metadata_field(endpoint_info, |m| m.asn.as_deref()),
                ":endpoint_timezone": metadata_field(endpoint_info, |m| m.timezone.as_deref()),
                ":exit_ip_info_json": exit_info.map(|m| m.raw_json.as_str()),
                ":exit_country": metadata_field(exit_info, |m| m.country.as_deref()),
                ":exit_region": metadata_field(exit_info, |m| m.region.as_deref()),
                ":exit_city": metadata_field(exit_info, |m| m.city.as_deref()),
                ":exit_org": metadata_field(exit_info, |m| m.organization.as_deref()),
                ":exit_asn": metadata_field(exit_info, |m| m.asn.as_deref()),
                ":exit_timezone": metadata_field(exit_info, |m| m.timezone.as_deref()),
            },
        )?;
        let check_id = self.conn.last_insert_rowid();

        for stage in &result.stages {
            self.insert_stage(check_id, stage)?;
        }
        Ok(())
    }

    fn insert_stage(&self, check_id: i64, stage: &StageResult) -> Result<()> {
        self.conn.execute(
            "INSERT INTO stage_results(
                proxy_check_id, stage, stage_name, status, duration_ms, error
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                check_id,
                i64::from(stage.stage),
                stage.name,
                stage.status.as_str(),
                stage.duration_ms.map(u128_to_i64),
                stage.error.as_deref(),
            ],
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

fn metadata_field<'a>(
    metadata: Option<&'a IpMetadata>, getter: impl FnOnce(&'a IpMetadata) -> Option<&'a str>,
) -> Option<&'a str> {
    metadata.and_then(getter)
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
    use crate::batch::{ProbeMetrics, ProxyProtocol, ProxySpec, StageResult};
    use std::net::{IpAddr, Ipv4Addr};

    fn options() -> BatchOptions {
        BatchOptions {
            proxy_files: vec!["proxies.txt".into()],
            source_lists: vec![],
            source_urls: vec![],
            inline_proxy_sources: vec![],
            inline_source_lists: vec![],
            output: "out.tsv".into(),
            write_tsv: true,
            valid_output: None,
            database: ":memory:".into(),
            interfaces: vec![],
            all_interfaces: false,
            default_protocol: "auto".into(),
            concurrency: 4,
            timeout_secs: 5,
            check_url: "http://127.0.0.1/ip".into(),
            profile: "full".into(),
            latency_samples: 3,
            download_url: "http://127.0.0.1/down?bytes={bytes}".into(),
            upload_url: "http://127.0.0.1/up".into(),
            download_bytes: 4096,
            upload_bytes: 2048,
            ip_info_url_template: None,
            subscription_id: None,
        }
    }

    #[test]
    fn schema_and_diagnostics_are_persisted_without_credentials() {
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
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            tested_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            reverse_dns: Some("proxy.example".into()),
            endpoint_connect_ms: Some(4),
            endpoint_ip_info: Some(IpMetadata {
                raw_json: r#"{"country":"AA"}"#.into(),
                country: Some("AA".into()),
                organization: Some("Example ISP".into()),
                ..IpMetadata::default()
            }),
            metrics: Some(ProbeMetrics {
                protocol: ProxyProtocol::Socks5,
                validation_latency_ms: 12,
                exit_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                latency_samples_ms: vec![12, 10, 14],
                latency_p50_ms: Some(12.0),
                latency_p95_ms: Some(14.0),
                jitter_ms: Some(3.0),
                download_mbps: Some(20.5),
                upload_mbps: Some(8.2),
                exit_ip_changed: false,
                exit_ip_info: None,
            }),
            stages: vec![
                StageResult::pass(0, "parse_deduplicate", Duration::ZERO),
                StageResult::pass(3, "proxy_http_validation", Duration::from_millis(12)),
            ],
            error: None,
        };
        store.insert_result(interface_run_id, &result).unwrap();
        store.finish_run(run_id, 1, 0).unwrap();

        let version: i64 =
            store.conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        let (source, input, profile, stage_count): (String, String, String, i64) = store
            .conn
            .query_row(
                "SELECT p.source, p.input_redacted, r.profile,
                    (SELECT COUNT(*) FROM stage_results s WHERE s.proxy_check_id = p.id)
                 FROM proxy_checks p
                 JOIN interface_runs i ON i.id = p.interface_run_id
                 JOIN runs r ON r.id = i.run_id
                 LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(source, "https://example.com/list");
        assert_eq!(input, "socks5://example.com:1080");
        assert_eq!(profile, "full");
        assert_eq!(stage_count, 2);
        assert!(!source.contains("secret"));
        assert!(!input.contains("secret"));
    }
}
