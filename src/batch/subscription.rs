use super::{
    input, redact_source, run_batch_with_outcome, store::Store, BatchOptions, BatchRunOutcome,
};
use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use reqwest::{
    header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED},
    Client, StatusCode,
};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

const RUN_LEASE_SECONDS: i64 = 6 * 60 * 60;

#[derive(Clone, Debug)]
struct Subscription {
    id: i64,
    name: String,
    source_type: String,
    source_url: String,
    source_display: String,
    enabled: bool,
    interval_seconds: u64,
    interface_names: Vec<String>,
    all_interfaces: bool,
    profile: String,
    default_protocol: String,
    concurrency: usize,
    timeout_seconds: u64,
    check_url: String,
    latency_samples: usize,
    download_url: String,
    upload_url: String,
    download_bytes: u64,
    upload_bytes: u64,
    ip_info_url_template: Option<String>,
    etag: Option<String>,
    last_modified: Option<String>,
    cached_payload: Option<String>,
    last_fetch_status: Option<u16>,
    last_fetch_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: Option<String>,
    item_count: usize,
    consecutive_failures: u32,
    next_run_at: i64,
    lease_until: i64,
}

#[derive(Clone, Debug)]
struct NewSubscription {
    name: String,
    source_type: String,
    source_url: String,
    enabled: bool,
    interval_seconds: u64,
    interface_names: Vec<String>,
    all_interfaces: bool,
    profile: String,
    default_protocol: String,
    concurrency: usize,
    timeout_seconds: u64,
    check_url: String,
    latency_samples: usize,
    download_url: String,
    upload_url: String,
    download_bytes: u64,
    upload_bytes: u64,
    ip_info_url_template: Option<String>,
}

struct SubscriptionDb {
    conn: Connection,
}

#[derive(Debug)]
struct FetchedSource {
    payload: String,
    http_status: u16,
    not_modified: bool,
    etag: Option<String>,
    last_modified: Option<String>,
}

impl SubscriptionDb {
    fn open(path: &str) -> Result<Self> {
        let conn = Store::open(path)?.into_connection();
        Ok(Self { conn })
    }

    fn create(&self, value: &NewSubscription) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO subscriptions(
                name, source_type, source_url, source_display, enabled, interval_seconds,
                interface_names, all_interfaces, profile, default_protocol, concurrency,
                timeout_seconds, check_url, latency_samples, download_url, upload_url,
                download_bytes, upload_bytes, ip_info_url_template, next_run_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, 0
             )",
                params![
                    value.name,
                    value.source_type,
                    value.source_url,
                    redact_source(&value.source_url),
                    i64::from(value.enabled),
                    u64_to_i64(value.interval_seconds),
                    value.interface_names.join(","),
                    i64::from(value.all_interfaces),
                    value.profile,
                    value.default_protocol,
                    usize_to_i64(value.concurrency),
                    u64_to_i64(value.timeout_seconds),
                    value.check_url,
                    usize_to_i64(value.latency_samples),
                    value.download_url,
                    value.upload_url,
                    u64_to_i64(value.download_bytes),
                    u64_to_i64(value.upload_bytes),
                    value.ip_info_url_template,
                ],
            )
            .with_context(|| format!("failed to create subscription {}", value.name))?;
        Ok(self.conn.last_insert_rowid())
    }

    fn list(&self) -> Result<Vec<Subscription>> {
        let mut statement = self.conn.prepare(&format!("{SUBSCRIPTION_SELECT} ORDER BY id"))?;
        let rows = statement.query_map([], subscription_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    fn get(&self, id: i64) -> Result<Subscription> {
        self.conn
            .query_row(&format!("{SUBSCRIPTION_SELECT} WHERE id = ?1"), [id], subscription_from_row)
            .optional()?
            .ok_or_else(|| anyhow!("subscription {id} not found"))
    }

    fn set_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE subscriptions
             SET enabled = ?2, next_run_at = CASE WHEN ?2 = 1 THEN 0 ELSE next_run_at END,
                 lease_until = 0, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?1",
            params![id, i64::from(enabled)],
        )?;
        if changed == 0 {
            return Err(anyhow!("subscription {id} not found"));
        }
        Ok(())
    }

    fn remove(&self, id: i64) -> Result<()> {
        let changed = self.conn.execute("DELETE FROM subscriptions WHERE id = ?1", [id])?;
        if changed == 0 {
            return Err(anyhow!("subscription {id} not found"));
        }
        Ok(())
    }

    fn claim_next_due(&mut self, now: i64) -> Result<Option<Subscription>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let subscription = {
            let mut statement = tx.prepare(&format!(
                "{SUBSCRIPTION_SELECT}
                 WHERE enabled = 1 AND next_run_at <= ?1 AND lease_until <= ?1
                 ORDER BY next_run_at, id
                 LIMIT 1"
            ))?;
            statement
                .query_row([now], subscription_from_row)
                .optional()?
        };

        if let Some(value) = subscription.as_ref() {
            tx.execute(
                "UPDATE subscriptions SET lease_until = ?2, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?1",
                params![value.id, now.saturating_add(RUN_LEASE_SECONDS)],
            )?;
        }
        tx.commit()?;
        Ok(subscription)
    }

    fn claim_one(&mut self, id: i64, now: i64) -> Result<Subscription> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let subscription = {
            let mut statement = tx.prepare(&format!("{SUBSCRIPTION_SELECT} WHERE id = ?1"))?;
            statement
                .query_row([id], subscription_from_row)
                .optional()?
                .ok_or_else(|| anyhow!("subscription {id} not found"))?
        };
        if subscription.lease_until > now {
            return Err(anyhow!(
                "subscription {id} is already running (lease active until {})",
                subscription.lease_until
            ));
        }
        tx.execute(
            "UPDATE subscriptions SET lease_until = ?2, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?1",
            params![id, now.saturating_add(RUN_LEASE_SECONDS)],
        )?;
        tx.commit()?;
        Ok(subscription)
    }

    fn save_fetch(
        &self, subscription: &Subscription, fetched: &FetchedSource, now: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE subscriptions
             SET cached_payload = CASE WHEN ?2 = 1 THEN cached_payload ELSE ?3 END,
                 etag = COALESCE(?4, etag),
                 last_modified = COALESCE(?5, last_modified),
                 last_fetch_status = ?6,
                 last_fetch_at = ?7,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?1",
            params![
                subscription.id,
                i64::from(fetched.not_modified),
                fetched.payload,
                fetched.etag,
                fetched.last_modified,
                i64::from(fetched.http_status),
                now,
            ],
        )?;
        Ok(())
    }

    fn record_success(
        &self, subscription: &Subscription, fetched: &FetchedSource, outcome: BatchRunOutcome,
        now: i64,
    ) -> Result<()> {
        let next_run_at = now.saturating_add(u64_to_i64(subscription.interval_seconds));
        self.conn.execute(
            "UPDATE subscriptions
             SET last_success_at = ?2, last_error = NULL, item_count = ?3,
                 consecutive_failures = 0, next_run_at = ?4, lease_until = 0,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?1",
            params![subscription.id, now, usize_to_i64(outcome.proxy_count), next_run_at,],
        )?;
        self.conn.execute(
            "INSERT INTO subscription_runs(
                subscription_id, run_id, fetched_at, http_status, not_modified, item_count, error
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                subscription.id,
                outcome.run_id,
                now,
                i64::from(fetched.http_status),
                i64::from(fetched.not_modified),
                usize_to_i64(outcome.proxy_count),
            ],
        )?;
        Ok(())
    }

    fn record_failure(
        &self, subscription: &Subscription, now: i64, status: Option<u16>, error: &str,
    ) -> Result<()> {
        let failures = subscription.consecutive_failures.saturating_add(1);
        let delay = retry_delay(subscription.interval_seconds, failures);
        let next_run_at = now.saturating_add(u64_to_i64(delay));
        self.conn.execute(
            "UPDATE subscriptions
             SET last_error = ?2, consecutive_failures = ?3, next_run_at = ?4,
                 lease_until = 0, last_fetch_status = COALESCE(?5, last_fetch_status),
                 last_fetch_at = CASE WHEN ?5 IS NULL THEN last_fetch_at ELSE ?6 END,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?1",
            params![
                subscription.id,
                error,
                i64::from(failures),
                next_run_at,
                status.map(i64::from),
                now,
            ],
        )?;
        self.conn.execute(
            "INSERT INTO subscription_runs(
                subscription_id, run_id, fetched_at, http_status, not_modified, item_count, error
             ) VALUES (?1, NULL, ?2, ?3, 0, NULL, ?4)",
            params![subscription.id, now, status.map(i64::from), error],
        )?;
        Ok(())
    }

    fn prune(&self, retention_days: u64, now: i64) -> Result<(usize, usize)> {
        if retention_days == 0 {
            return Ok((0, 0));
        }
        let cutoff = now.saturating_sub(u64_to_i64(retention_days.saturating_mul(86_400)));
        let subscription_runs =
            self.conn.execute("DELETE FROM subscription_runs WHERE fetched_at < ?1", [cutoff])?;
        let modifier = format!("-{retention_days} days");
        let runs = self.conn.execute(
            "DELETE FROM runs
             WHERE completed_at IS NOT NULL
               AND completed_at < datetime('now', ?1)",
            [modifier],
        )?;
        Ok((runs, subscription_runs))
    }
}

const SUBSCRIPTION_SELECT: &str = "
SELECT
    id, name, source_type, source_url, source_display, enabled, interval_seconds,
    interface_names, all_interfaces, profile, default_protocol, concurrency,
    timeout_seconds, check_url, latency_samples, download_url, upload_url,
    download_bytes, upload_bytes, ip_info_url_template, etag, last_modified,
    cached_payload, last_fetch_status, last_fetch_at, last_success_at, last_error,
    item_count, consecutive_failures, next_run_at, lease_until
FROM subscriptions
";

fn subscription_from_row(row: &Row<'_>) -> rusqlite::Result<Subscription> {
    let interface_names: String = row.get(7)?;
    let last_fetch_status: Option<i64> = row.get(23)?;
    Ok(Subscription {
        id: row.get(0)?,
        name: row.get(1)?,
        source_type: row.get(2)?,
        source_url: row.get(3)?,
        source_display: row.get(4)?,
        enabled: row.get::<_, i64>(5)? != 0,
        interval_seconds: i64_to_u64(row.get(6)?),
        interface_names: split_interfaces(&interface_names),
        all_interfaces: row.get::<_, i64>(8)? != 0,
        profile: row.get(9)?,
        default_protocol: row.get(10)?,
        concurrency: i64_to_usize(row.get(11)?),
        timeout_seconds: i64_to_u64(row.get(12)?),
        check_url: row.get(13)?,
        latency_samples: i64_to_usize(row.get(14)?),
        download_url: row.get(15)?,
        upload_url: row.get(16)?,
        download_bytes: i64_to_u64(row.get(17)?),
        upload_bytes: i64_to_u64(row.get(18)?),
        ip_info_url_template: row.get(19)?,
        etag: row.get(20)?,
        last_modified: row.get(21)?,
        cached_payload: row.get(22)?,
        last_fetch_status: last_fetch_status.and_then(|value| u16::try_from(value).ok()),
        last_fetch_at: row.get(24)?,
        last_success_at: row.get(25)?,
        last_error: row.get(26)?,
        item_count: i64_to_usize(row.get(27)?),
        consecutive_failures: u32::try_from(row.get::<_, i64>(28)?).unwrap_or(u32::MAX),
        next_run_at: row.get(29)?,
        lease_until: row.get(30)?,
    })
}

pub(super) async fn handle_subscription_command(
    matches: &ArgMatches, database: &str,
) -> Result<()> {
    let mut db = SubscriptionDb::open(database)?;
    match matches.subcommand() {
        Some(("add", args)) => {
            let new = new_subscription_from_matches(args)?;
            let id = db.create(&new)?;
            println!("subscription created: id={id} name={}", new.name);
            Ok(())
        }
        Some(("list", _)) => {
            let values = db.list()?;
            println!("id\tname\tenabled\tsource_type\tsource\tinterval_seconds\tprofile\tnext_run_at\tlast_success_at\titem_count\tlast_error");
            for value in values {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    value.id,
                    value.name,
                    value.enabled,
                    value.source_type,
                    value.source_display,
                    value.interval_seconds,
                    value.profile,
                    value.next_run_at,
                    value.last_success_at.map(|v| v.to_string()).unwrap_or_default(),
                    value.item_count,
                    value.last_error.unwrap_or_default().replace(['\t', '\r', '\n'], " "),
                );
            }
            Ok(())
        }
        Some(("show", args)) => {
            let id = parse_i64(args, "id")?;
            print_subscription(&db.get(id)?);
            Ok(())
        }
        Some(("enable", args)) => {
            let id = parse_i64(args, "id")?;
            db.set_enabled(id, true)?;
            println!("subscription enabled: id={id}");
            Ok(())
        }
        Some(("disable", args)) => {
            let id = parse_i64(args, "id")?;
            db.set_enabled(id, false)?;
            println!("subscription disabled: id={id}");
            Ok(())
        }
        Some(("remove", args)) => {
            let id = parse_i64(args, "id")?;
            db.remove(id)?;
            println!("subscription removed: id={id}");
            Ok(())
        }
        Some(("run", args)) => {
            let id = parse_i64(args, "id")?;
            let subscription = db.claim_one(id, unix_now()?)?;
            run_one(database, &db, &subscription).await
        }
        _ => Err(anyhow!("subscription subcommand is required")),
    }
}

pub(super) async fn run_service(
    database: &str, poll_seconds: u64, retention_days: u64, once: bool,
) -> Result<()> {
    if poll_seconds == 0 {
        return Err(anyhow!("--poll-seconds must be greater than zero"));
    }
    let mut db = SubscriptionDb::open(database)?;
    let now = unix_now()?;
    let (pruned_runs, pruned_subscription_runs) = db.prune(retention_days, now)?;
    if pruned_runs > 0 || pruned_subscription_runs > 0 {
        println!(
            "retention: removed {pruned_runs} historical runs and {pruned_subscription_runs} subscription run records"
        );
    }

    loop {
        while let Some(subscription) = db.claim_next_due(unix_now()?)? {
            if let Err(err) = run_one(database, &db, &subscription).await {
                eprintln!(
                    "subscription run failed: id={} name={} error={err:#}",
                    subscription.id, subscription.name
                );
            }
        }

        if once {
            return Ok(());
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(poll_seconds)) => {}
            _ = shutdown_signal() => {
                println!("service shutdown requested; no new subscription runs will start");
                return Ok(());
            }
        }
    }
}

async fn run_one(database: &str, db: &SubscriptionDb, subscription: &Subscription) -> Result<()> {
    let now = unix_now()?;
    let fetched = match fetch_subscription_source(subscription).await {
        Ok(value) => value,
        Err(err) => {
            let message = format!("source fetch failed: {err:#}");
            db.record_failure(subscription, now, None, &message)?;
            return Err(anyhow!(message));
        }
    };
    db.save_fetch(subscription, &fetched, now)?;

    let options = subscription_batch_options(database, subscription, &fetched.payload);
    match run_batch_with_outcome(options).await {
        Ok(outcome) => {
            db.record_success(subscription, &fetched, outcome, now)?;
            println!(
                "subscription run complete: id={} name={} run_id={} proxies={} tested={} valid={} http_status={} not_modified={}",
                subscription.id,
                subscription.name,
                outcome.run_id,
                outcome.proxy_count,
                outcome.tested,
                outcome.valid,
                fetched.http_status,
                fetched.not_modified,
            );
            Ok(())
        }
        Err(err) => {
            let message = format!("batch validation failed: {err:#}");
            db.record_failure(subscription, now, Some(fetched.http_status), &message)?;
            Err(anyhow!(message))
        }
    }
}

async fn fetch_subscription_source(subscription: &Subscription) -> Result<FetchedSource> {
    let client = Client::builder()
        .no_proxy()
        .user_agent(concat!("proxy-socks-test/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(subscription.timeout_seconds.max(15)))
        .build()
        .context("failed to build subscription source client")?;

    let mut request = client.get(&subscription.source_url);
    if let Some(etag) = &subscription.etag {
        request = request.header(IF_NONE_MATCH, etag);
    }
    if let Some(last_modified) = &subscription.last_modified {
        request = request.header(IF_MODIFIED_SINCE, last_modified);
    }

    let response = request.send().await.context("subscription source request failed")?;
    let status = response.status();
    let etag = header_text(response.headers().get(ETAG));
    let last_modified = header_text(response.headers().get(LAST_MODIFIED));

    if status == StatusCode::NOT_MODIFIED {
        let payload = subscription
            .cached_payload
            .clone()
            .ok_or_else(|| anyhow!("source returned 304 but no cached payload is available"))?;
        return Ok(FetchedSource {
            payload,
            http_status: status.as_u16(),
            not_modified: true,
            etag,
            last_modified,
        });
    }

    let response = response.error_for_status().context("subscription source HTTP error")?;
    let payload = input::response_text_limited(response, &subscription.source_display).await?;
    Ok(FetchedSource {
        payload,
        http_status: status.as_u16(),
        not_modified: false,
        etag,
        last_modified,
    })
}

fn subscription_batch_options(
    database: &str, subscription: &Subscription, payload: &str,
) -> BatchOptions {
    let source = subscription.source_url.clone();
    let (inline_proxy_sources, inline_source_lists) = if subscription.source_type == "source-list" {
        (Vec::new(), vec![(source, payload.to_owned())])
    } else {
        (vec![(source, payload.to_owned())], Vec::new())
    };

    BatchOptions {
        proxy_files: Vec::new(),
        source_lists: Vec::new(),
        source_urls: Vec::new(),
        inline_proxy_sources,
        inline_source_lists,
        output: "proxy-results.tsv".into(),
        write_tsv: false,
        valid_output: None,
        database: database.to_owned(),
        interfaces: subscription.interface_names.clone(),
        all_interfaces: subscription.all_interfaces,
        default_protocol: subscription.default_protocol.clone(),
        concurrency: subscription.concurrency,
        timeout_secs: subscription.timeout_seconds,
        check_url: subscription.check_url.clone(),
        profile: subscription.profile.clone(),
        latency_samples: subscription.latency_samples,
        download_url: subscription.download_url.clone(),
        upload_url: subscription.upload_url.clone(),
        download_bytes: subscription.download_bytes,
        upload_bytes: subscription.upload_bytes,
        ip_info_url_template: subscription.ip_info_url_template.clone(),
        subscription_id: Some(subscription.id),
    }
}

fn new_subscription_from_matches(matches: &ArgMatches) -> Result<NewSubscription> {
    let source_type = required_string(matches, "source-type")?;
    if !matches!(source_type.as_str(), "proxy-list" | "source-list") {
        return Err(anyhow!("unsupported subscription source type: {source_type}"));
    }
    let source_url = required_string(matches, "url")?;
    let parsed = reqwest::Url::parse(&source_url).context("invalid subscription --url")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("subscription --url must use http:// or https://"));
    }

    Ok(NewSubscription {
        name: required_string(matches, "name")?,
        source_type,
        source_url,
        enabled: !matches.get_flag("disabled"),
        interval_seconds: parse_u64(matches, "interval-seconds")?,
        interface_names: matches
            .get_many::<String>("interface")
            .map(|values| values.cloned().collect())
            .unwrap_or_default(),
        all_interfaces: matches.get_flag("all-interfaces"),
        profile: required_string(matches, "profile")?,
        default_protocol: required_string(matches, "protocol")?,
        concurrency: parse_usize(matches, "concurrency")?,
        timeout_seconds: parse_u64(matches, "timeout")?,
        check_url: required_string(matches, "check-url")?,
        latency_samples: parse_usize(matches, "latency-samples")?,
        download_url: required_string(matches, "download-url")?,
        upload_url: required_string(matches, "upload-url")?,
        download_bytes: parse_u64(matches, "download-bytes")?,
        upload_bytes: parse_u64(matches, "upload-bytes")?,
        ip_info_url_template: matches.get_one::<String>("ip-info-url-template").cloned(),
    })
}

fn print_subscription(value: &Subscription) {
    println!("id={}", value.id);
    println!("name={}", value.name);
    println!("enabled={}", value.enabled);
    println!("source_type={}", value.source_type);
    println!("source={}", value.source_display);
    println!("interval_seconds={}", value.interval_seconds);
    println!(
        "interfaces={}",
        if value.all_interfaces {
            "all".to_owned()
        } else if value.interface_names.is_empty() {
            "default".to_owned()
        } else {
            value.interface_names.join(",")
        }
    );
    println!("profile={}", value.profile);
    println!("protocol={}", value.default_protocol);
    println!(
        "last_fetch_status={}",
        value.last_fetch_status.map(|v| v.to_string()).unwrap_or_default()
    );
    println!("last_fetch_at={}", value.last_fetch_at.map(|v| v.to_string()).unwrap_or_default());
    println!(
        "last_success_at={}",
        value.last_success_at.map(|v| v.to_string()).unwrap_or_default()
    );
    println!("item_count={}", value.item_count);
    println!("consecutive_failures={}", value.consecutive_failures);
    println!("next_run_at={}", value.next_run_at);
    println!("lease_until={}", value.lease_until);
    println!(
        "last_error={}",
        value.last_error.as_deref().unwrap_or_default().replace(['\t', '\r', '\n'], " ")
    );
}

fn header_text(value: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    value.and_then(|value| value.to_str().ok()).map(str::to_owned)
}

fn split_interfaces(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned).collect()
}

fn retry_delay(interval_seconds: u64, failures: u32) -> u64 {
    let shift = failures.saturating_sub(1).min(6);
    interval_seconds.saturating_mul(1_u64 << shift).clamp(5, 86_400)
}

fn unix_now() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    Ok(u64_to_i64(seconds))
}

fn required_string(matches: &ArgMatches, name: &str) -> Result<String> {
    matches.get_one::<String>(name).cloned().ok_or_else(|| anyhow!("missing --{name}"))
}

fn parse_i64(matches: &ArgMatches, name: &str) -> Result<i64> {
    required_string(matches, name)?.parse().with_context(|| format!("invalid --{name}"))
}

fn parse_u64(matches: &ArgMatches, name: &str) -> Result<u64> {
    required_string(matches, name)?.parse().with_context(|| format!("invalid --{name}"))
}

fn parse_usize(matches: &ArgMatches, name: &str) -> Result<usize> {
    required_string(matches, name)?.parse().with_context(|| format!("invalid --{name}"))
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn i64_to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or_default()
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate =
        signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_subscription(url: &str) -> NewSubscription {
        NewSubscription {
            name: "fixture".into(),
            source_type: "proxy-list".into(),
            source_url: url.into(),
            enabled: true,
            interval_seconds: 60,
            interface_names: vec!["lo".into()],
            all_interfaces: false,
            profile: "standard".into(),
            default_protocol: "auto".into(),
            concurrency: 4,
            timeout_seconds: 5,
            check_url: "http://127.0.0.1/ip".into(),
            latency_samples: 3,
            download_url: "http://127.0.0.1/down?bytes={bytes}".into(),
            upload_url: "http://127.0.0.1/up".into(),
            download_bytes: 4096,
            upload_bytes: 2048,
            ip_info_url_template: None,
        }
    }

    #[test]
    fn subscription_crud_keeps_operational_source_private() {
        let db = SubscriptionDb::open(":memory:").unwrap();
        let source = "https://user:secret@example.com/list?token=abc";
        let id = db.create(&new_subscription(source)).unwrap();
        let stored = db.get(id).unwrap();

        assert_eq!(stored.source_url, source);
        assert_eq!(stored.source_display, "https://example.com/list");
        assert!(!stored.source_display.contains("secret"));
        assert!(!stored.source_display.contains("token"));
        assert_eq!(db.list().unwrap().len(), 1);

        db.set_enabled(id, false).unwrap();
        assert!(!db.get(id).unwrap().enabled);
        db.set_enabled(id, true).unwrap();
        assert!(db.get(id).unwrap().enabled);

        db.remove(id).unwrap();
        assert!(db.get(id).is_err());
    }

    #[test]
    fn backoff_is_bounded_and_exponential() {
        assert_eq!(retry_delay(60, 1), 60);
        assert_eq!(retry_delay(60, 2), 120);
        assert_eq!(retry_delay(60, 3), 240);
        assert_eq!(retry_delay(60, 20), 3840);
        assert_eq!(retry_delay(3600, 20), 86_400);
    }

    #[test]
    fn retention_zero_disables_pruning() {
        let db = SubscriptionDb::open(":memory:").unwrap();
        assert_eq!(db.prune(0, 1_000).unwrap(), (0, 0));
    }

    #[test]
    fn claim_lease_prevents_duplicate_concurrent_runs() {
        let mut db = SubscriptionDb::open(":memory:").unwrap();
        let id = db.create(&new_subscription("https://example.com/list")).unwrap();
        let first = db.claim_one(id, 1_000).unwrap();
        assert_eq!(first.id, id);
        let err = db.claim_one(id, 1_001).unwrap_err();
        assert!(err.to_string().contains("already running"));

        db.record_failure(&first, 1_002, None, "fixture").unwrap();
        assert!(db.claim_one(id, 1_003).is_ok());
    }
}
