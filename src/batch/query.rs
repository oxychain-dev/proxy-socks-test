use super::store::Store;
use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use rusqlite::{params_from_iter, types::Value, Connection, OptionalExtension};
use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fs::File,
    io::{BufWriter, Write},
};

const TSV_HEADER: &str = "run_id\tstarted_at\tcompleted_at\tsubscription_id\tinterface\tlocal_ips\ttester_ip\tsource\tinput\tproxy_host\tresolved_ips\ttested_ip\treverse_dns\tproxy_port\tvalid\tauth_required\tprotocol\ttcp_connect_ms\tvalidation_latency_ms\tlatency_p50_ms\tlatency_p95_ms\tjitter_ms\tdownload_mbps\tupload_mbps\texit_ip\texit_ip_changed\tendpoint_country\tendpoint_asn\tendpoint_org\texit_country\texit_asn\texit_org\tstages\terror\n";

#[derive(Default)]
struct QueryFilters {
    run_id: Option<i64>,
    subscription_id: Option<i64>,
    interface: Option<String>,
    protocol: Option<String>,
    valid: Option<bool>,
    since: Option<String>,
    until: Option<String>,
}

#[derive(Debug)]
struct ExportRow {
    run_id: i64,
    started_at: String,
    completed_at: Option<String>,
    subscription_id: Option<i64>,
    interface_name: String,
    local_ips: String,
    tester_ip: Option<String>,
    source: String,
    input: String,
    proxy_host: String,
    resolved_ips: String,
    tested_ip: Option<String>,
    reverse_dns: Option<String>,
    proxy_port: i64,
    valid: bool,
    auth_required: bool,
    protocol: String,
    tcp_connect_ms: Option<i64>,
    validation_latency_ms: Option<i64>,
    latency_p50_ms: Option<f64>,
    latency_p95_ms: Option<f64>,
    jitter_ms: Option<f64>,
    download_mbps: Option<f64>,
    upload_mbps: Option<f64>,
    exit_ip: Option<String>,
    exit_ip_changed: Option<bool>,
    endpoint_country: Option<String>,
    endpoint_asn: Option<String>,
    endpoint_org: Option<String>,
    exit_country: Option<String>,
    exit_asn: Option<String>,
    exit_org: Option<String>,
    stages: String,
    error: Option<String>,
}

#[derive(Debug)]
struct RankedProxy {
    interface_name: String,
    protocol: String,
    proxy_host: String,
    proxy_port: i64,
    auth_required: bool,
    latency_ms: Option<f64>,
    download_mbps: Option<f64>,
    upload_mbps: Option<f64>,
    exit_ip: Option<String>,
    score: f64,
}

pub(super) fn handle_export_command(matches: &ArgMatches, database: &str) -> Result<()> {
    let store = Store::open(database)?;
    let conn = store.into_connection();

    match matches.subcommand() {
        Some(("tsv", args)) => export_tsv(&conn, args),
        Some(("valid", args)) => export_valid(&conn, args),
        _ => Err(anyhow!("export subcommand is required")),
    }
}

pub(super) fn handle_report_command(matches: &ArgMatches, database: &str) -> Result<()> {
    let store = Store::open(database)?;
    let conn = store.into_connection();
    let run_id = match matches.get_one::<String>("run-id") {
        Some(value) => value.parse::<i64>().context("invalid --run-id")?,
        None => conn
            .query_row("SELECT id FROM runs ORDER BY id DESC LIMIT 1", [], |row| row.get(0))
            .optional_context("no runs are stored in the database")?,
    };
    let limit = matches
        .get_one::<String>("limit")
        .expect("limit")
        .parse::<usize>()
        .context("invalid --limit")?;
    if limit == 0 {
        return Err(anyhow!("--limit must be greater than zero"));
    }

    print_run_report(&conn, run_id, limit)
}

fn export_tsv(conn: &Connection, matches: &ArgMatches) -> Result<()> {
    let output = required(matches, "output")?;
    let filters = filters_from_matches(matches)?;
    validate_time_filters(conn, &filters)?;

    let (where_sql, values) = build_filter_sql(&filters);
    let sql = format!(
        "SELECT
            r.id, r.started_at, r.completed_at, r.subscription_id,
            i.interface_name, i.local_ips, i.tester_ip,
            p.source, p.input_redacted, p.proxy_host, p.resolved_ips,
            p.tested_ip, p.reverse_dns, p.proxy_port, p.valid, p.auth_required,
            COALESCE(p.detected_protocol, p.requested_protocol),
            p.tcp_connect_ms, p.latency_ms, p.latency_p50_ms, p.latency_p95_ms,
            p.jitter_ms, p.download_mbps, p.upload_mbps, p.exit_ip,
            p.exit_ip_changed, p.endpoint_country, p.endpoint_asn, p.endpoint_org,
            p.exit_country, p.exit_asn, p.exit_org,
            COALESCE((
                SELECT group_concat(stage_line, ',')
                FROM (
                    SELECT printf('%d:%s=%s', s.stage, s.stage_name, s.status) AS stage_line
                    FROM stage_results s
                    WHERE s.proxy_check_id = p.id
                    ORDER BY s.stage, s.id
                )
            ), ''),
            p.error
         FROM proxy_checks p
         JOIN interface_runs i ON i.id = p.interface_run_id
         JOIN runs r ON r.id = i.run_id
         {where_sql}
         ORDER BY r.id, i.id, p.id"
    );

    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), export_row_from_sql)?;
    let file = File::create(&output).with_context(|| format!("failed to create {output}"))?;
    let mut writer = BufWriter::new(file);
    writer.write_all(TSV_HEADER.as_bytes())?;
    let mut count = 0usize;
    for row in rows {
        writer.write_all(export_row_to_tsv(&row?).as_bytes())?;
        count += 1;
    }
    writer.flush()?;
    println!("SQLite TSV export complete: rows={count} output={output}");
    Ok(())
}

fn export_valid(conn: &Connection, matches: &ArgMatches) -> Result<()> {
    let output = required(matches, "output")?;
    let run_id = required(matches, "run-id")?
        .parse::<i64>()
        .context("invalid --run-id")?;
    let interface = matches.get_one::<String>("interface").cloned();
    let protocol = matches.get_one::<String>("protocol").cloned();

    let mut sql = String::from(
        "SELECT
            COALESCE(p.detected_protocol, p.requested_protocol),
            p.proxy_host, p.proxy_port, p.auth_required
         FROM proxy_checks p
         JOIN interface_runs i ON i.id = p.interface_run_id
         WHERE i.run_id = ?1 AND p.valid = 1",
    );
    let mut values = vec![Value::Integer(run_id)];
    if let Some(interface) = interface {
        sql.push_str(" AND i.interface_name = ?");
        values.push(Value::Text(interface));
    }
    if let Some(protocol) = protocol {
        sql.push_str(" AND COALESCE(p.detected_protocol, p.requested_protocol) = ?");
        values.push(Value::Text(protocol));
    }
    sql.push_str(" ORDER BY p.id");

    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)? != 0,
        ))
    })?;

    let mut links = BTreeSet::new();
    let mut skipped_auth = 0usize;
    for row in rows {
        let (protocol, host, port, auth_required) = row?;
        if auth_required {
            skipped_auth += 1;
            continue;
        }
        let host = bracket_host(&host);
        links.insert(format!("{protocol}://{host}:{port}"));
    }

    let file = File::create(&output).with_context(|| format!("failed to create {output}"))?;
    let mut writer = BufWriter::new(file);
    for link in &links {
        writeln!(writer, "{link}")?;
    }
    writer.flush()?;

    println!(
        "valid-link export complete: run_id={run_id} links={} skipped_auth_required={} output={output}",
        links.len(),
        skipped_auth
    );
    Ok(())
}

fn print_run_report(conn: &Connection, run_id: i64, limit: usize) -> Result<()> {
    let run = conn
        .query_row(
            "SELECT
                id, started_at, completed_at, subscription_id, profile,
                proxy_count, interface_count, valid_count, invalid_count
             FROM runs WHERE id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .with_context(|| format!("run {run_id} not found"))?;

    println!("run_id={}", run.0);
    println!("started_at={}", run.1);
    println!("completed_at={}", run.2.unwrap_or_default());
    println!("subscription_id={}", run.3.map(|v| v.to_string()).unwrap_or_default());
    println!("profile={}", run.4);
    println!("proxy_count={}", run.5);
    println!("interface_count={}", run.6);
    println!("valid_count={}", run.7);
    println!("invalid_count={}", run.8);

    println!("\n[interfaces]");
    let mut statement = conn.prepare(
        "SELECT
            i.interface_name,
            COUNT(p.id) AS tested,
            COALESCE(SUM(p.valid), 0) AS valid,
            ROUND(AVG(CASE WHEN p.valid = 1 THEN COALESCE(p.latency_p50_ms, p.latency_ms) END), 3),
            ROUND(AVG(CASE WHEN p.valid = 1 THEN p.download_mbps END), 3),
            ROUND(AVG(CASE WHEN p.valid = 1 THEN p.upload_mbps END), 3),
            COUNT(DISTINCT CASE WHEN p.valid = 1 THEN p.exit_ip END)
         FROM interface_runs i
         LEFT JOIN proxy_checks p ON p.interface_run_id = i.id
         WHERE i.run_id = ?1
         GROUP BY i.id, i.interface_name
         ORDER BY i.id",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<f64>>(3)?,
            row.get::<_, Option<f64>>(4)?,
            row.get::<_, Option<f64>>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    println!("interface\ttested\tvalid\tlatency_avg_ms\tdownload_avg_mbps\tupload_avg_mbps\tunique_exit_ips");
    for row in rows {
        let row = row?;
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.0,
            row.1,
            row.2,
            metric(row.3),
            metric(row.4),
            metric(row.5),
            row.6
        );
    }

    println!("\n[failures]");
    let mut statement = conn.prepare(
        "SELECT s.stage, s.stage_name, COUNT(*)
         FROM stage_results s
         JOIN proxy_checks p ON p.id = s.proxy_check_id
         JOIN interface_runs i ON i.id = p.interface_run_id
         WHERE i.run_id = ?1 AND s.status = 'fail'
         GROUP BY s.stage, s.stage_name
         ORDER BY s.stage",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
    })?;
    let mut failures = 0usize;
    for row in rows {
        let (stage, name, count) = row?;
        failures += usize::try_from(count).unwrap_or_default();
        println!("stage={stage} name={name} count={count}");
    }
    if failures == 0 {
        println!("none");
    }

    let unique_exit_ips: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT p.exit_ip)
         FROM proxy_checks p
         JOIN interface_runs i ON i.id = p.interface_run_id
         WHERE i.run_id = ?1 AND p.valid = 1 AND p.exit_ip IS NOT NULL",
        [run_id],
        |row| row.get(0),
    )?;
    let changed_exit_checks: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM proxy_checks p
         JOIN interface_runs i ON i.id = p.interface_run_id
         WHERE i.run_id = ?1 AND p.valid = 1 AND p.exit_ip_changed = 1",
        [run_id],
        |row| row.get(0),
    )?;
    println!("\n[exit_ips]");
    println!("unique_exit_ips={unique_exit_ips}");
    println!("exit_ip_changed_checks={changed_exit_checks}");

    println!("\n[best_proxies]");
    let mut candidates = load_ranked_candidates(conn, run_id)?;
    score_candidates(&mut candidates);
    candidates.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.interface_name.cmp(&right.interface_name))
            .then_with(|| left.proxy_host.cmp(&right.proxy_host))
            .then_with(|| left.proxy_port.cmp(&right.proxy_port))
    });
    println!("rank\tscore\tinterface\tprotocol\tproxy\tauth_required\tlatency_ms\tdownload_mbps\tupload_mbps\texit_ip");
    for (index, candidate) in candidates.into_iter().take(limit).enumerate() {
        println!(
            "{}\t{:.3}\t{}\t{}\t{}:{}\t{}\t{}\t{}\t{}\t{}",
            index + 1,
            candidate.score,
            candidate.interface_name,
            candidate.protocol,
            bracket_host(&candidate.proxy_host),
            candidate.proxy_port,
            candidate.auth_required,
            metric(candidate.latency_ms),
            metric(candidate.download_mbps),
            metric(candidate.upload_mbps),
            candidate.exit_ip.unwrap_or_default(),
        );
    }
    println!(
        "score_formula=weighted normalized components: latency 40% (lower is better), download 35%, upload 25%; missing components are omitted and remaining weights are renormalized"
    );
    Ok(())
}

fn load_ranked_candidates(conn: &Connection, run_id: i64) -> Result<Vec<RankedProxy>> {
    let mut statement = conn.prepare(
        "SELECT
            i.interface_name,
            COALESCE(p.detected_protocol, p.requested_protocol),
            p.proxy_host, p.proxy_port, p.auth_required,
            COALESCE(p.latency_p50_ms, CAST(p.latency_ms AS REAL)),
            p.download_mbps, p.upload_mbps, p.exit_ip
         FROM proxy_checks p
         JOIN interface_runs i ON i.id = p.interface_run_id
         WHERE i.run_id = ?1 AND p.valid = 1",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok(RankedProxy {
            interface_name: row.get(0)?,
            protocol: row.get(1)?,
            proxy_host: row.get(2)?,
            proxy_port: row.get(3)?,
            auth_required: row.get::<_, i64>(4)? != 0,
            latency_ms: row.get(5)?,
            download_mbps: row.get(6)?,
            upload_mbps: row.get(7)?,
            exit_ip: row.get(8)?,
            score: 0.0,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

fn score_candidates(candidates: &mut [RankedProxy]) {
    let max_latency = candidates.iter().filter_map(|p| p.latency_ms).reduce(f64::max);
    let max_download = candidates.iter().filter_map(|p| p.download_mbps).reduce(f64::max);
    let max_upload = candidates.iter().filter_map(|p| p.upload_mbps).reduce(f64::max);

    for candidate in candidates {
        let mut weighted = 0.0;
        let mut weights = 0.0;

        if let (Some(latency), Some(max_latency)) = (candidate.latency_ms, max_latency) {
            let component = if max_latency <= 0.0 {
                1.0
            } else {
                1.0 - (latency / max_latency).clamp(0.0, 1.0)
            };
            weighted += component * 0.40;
            weights += 0.40;
        }
        if let (Some(download), Some(max_download)) = (candidate.download_mbps, max_download) {
            let component =
                if max_download <= 0.0 { 0.0 } else { (download / max_download).clamp(0.0, 1.0) };
            weighted += component * 0.35;
            weights += 0.35;
        }
        if let (Some(upload), Some(max_upload)) = (candidate.upload_mbps, max_upload) {
            let component =
                if max_upload <= 0.0 { 0.0 } else { (upload / max_upload).clamp(0.0, 1.0) };
            weighted += component * 0.25;
            weights += 0.25;
        }

        candidate.score = if weights > 0.0 { weighted / weights * 100.0 } else { 0.0 };
    }
}

fn filters_from_matches(matches: &ArgMatches) -> Result<QueryFilters> {
    Ok(QueryFilters {
        run_id: parse_optional_i64(matches, "run-id")?,
        subscription_id: parse_optional_i64(matches, "subscription-id")?,
        interface: matches.get_one::<String>("interface").cloned(),
        protocol: matches.get_one::<String>("protocol").cloned(),
        valid: matches
            .get_one::<String>("valid")
            .map(|value| value == "true"),
        since: matches.get_one::<String>("since").cloned(),
        until: matches.get_one::<String>("until").cloned(),
    })
}

fn build_filter_sql(filters: &QueryFilters) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut values = Vec::new();

    if let Some(run_id) = filters.run_id {
        clauses.push("r.id = ?");
        values.push(Value::Integer(run_id));
    }
    if let Some(subscription_id) = filters.subscription_id {
        clauses.push("r.subscription_id = ?");
        values.push(Value::Integer(subscription_id));
    }
    if let Some(interface) = &filters.interface {
        clauses.push("i.interface_name = ?");
        values.push(Value::Text(interface.clone()));
    }
    if let Some(protocol) = &filters.protocol {
        clauses.push("COALESCE(p.detected_protocol, p.requested_protocol) = ?");
        values.push(Value::Text(protocol.clone()));
    }
    if let Some(valid) = filters.valid {
        clauses.push("p.valid = ?");
        values.push(Value::Integer(i64::from(valid)));
    }
    if let Some(since) = &filters.since {
        clauses.push("r.started_at >= datetime(?)");
        values.push(Value::Text(since.clone()));
    }
    if let Some(until) = &filters.until {
        clauses.push("r.started_at <= datetime(?)");
        values.push(Value::Text(until.clone()));
    }

    let sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    (sql, values)
}

fn validate_time_filters(conn: &Connection, filters: &QueryFilters) -> Result<()> {
    for (flag, value) in [("--since", filters.since.as_deref()), ("--until", filters.until.as_deref())]
    {
        if let Some(value) = value {
            let valid: i64 =
                conn.query_row("SELECT datetime(?1) IS NOT NULL", [value], |row| row.get(0))?;
            if valid == 0 {
                return Err(anyhow!(
                    "{flag} is not a SQLite-compatible date/time (example: 2026-10-10T15:30:00Z)"
                ));
            }
        }
    }
    Ok(())
}

fn export_row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExportRow> {
    Ok(ExportRow {
        run_id: row.get(0)?,
        started_at: row.get(1)?,
        completed_at: row.get(2)?,
        subscription_id: row.get(3)?,
        interface_name: row.get(4)?,
        local_ips: row.get(5)?,
        tester_ip: row.get(6)?,
        source: row.get(7)?,
        input: row.get(8)?,
        proxy_host: row.get(9)?,
        resolved_ips: row.get(10)?,
        tested_ip: row.get(11)?,
        reverse_dns: row.get(12)?,
        proxy_port: row.get(13)?,
        valid: row.get::<_, i64>(14)? != 0,
        auth_required: row.get::<_, i64>(15)? != 0,
        protocol: row.get(16)?,
        tcp_connect_ms: row.get(17)?,
        validation_latency_ms: row.get(18)?,
        latency_p50_ms: row.get(19)?,
        latency_p95_ms: row.get(20)?,
        jitter_ms: row.get(21)?,
        download_mbps: row.get(22)?,
        upload_mbps: row.get(23)?,
        exit_ip: row.get(24)?,
        exit_ip_changed: row.get::<_, Option<i64>>(25)?.map(|v| v != 0),
        endpoint_country: row.get(26)?,
        endpoint_asn: row.get(27)?,
        endpoint_org: row.get(28)?,
        exit_country: row.get(29)?,
        exit_asn: row.get(30)?,
        exit_org: row.get(31)?,
        stages: row.get(32)?,
        error: row.get(33)?,
    })
}

fn export_row_to_tsv(row: &ExportRow) -> String {
    [
        row.run_id.to_string(),
        row.started_at.clone(),
        row.completed_at.clone().unwrap_or_default(),
        row.subscription_id.map(|v| v.to_string()).unwrap_or_default(),
        tsv(&row.interface_name),
        tsv(&row.local_ips),
        tsv(row.tester_ip.as_deref().unwrap_or_default()),
        tsv(&row.source),
        tsv(&row.input),
        tsv(&row.proxy_host),
        tsv(&row.resolved_ips),
        tsv(row.tested_ip.as_deref().unwrap_or_default()),
        tsv(row.reverse_dns.as_deref().unwrap_or_default()),
        row.proxy_port.to_string(),
        row.valid.to_string(),
        row.auth_required.to_string(),
        row.protocol.clone(),
        optional_i64(row.tcp_connect_ms),
        optional_i64(row.validation_latency_ms),
        metric(row.latency_p50_ms),
        metric(row.latency_p95_ms),
        metric(row.jitter_ms),
        metric(row.download_mbps),
        metric(row.upload_mbps),
        row.exit_ip.clone().unwrap_or_default(),
        row.exit_ip_changed.map(|v| v.to_string()).unwrap_or_default(),
        tsv(row.endpoint_country.as_deref().unwrap_or_default()),
        tsv(row.endpoint_asn.as_deref().unwrap_or_default()),
        tsv(row.endpoint_org.as_deref().unwrap_or_default()),
        tsv(row.exit_country.as_deref().unwrap_or_default()),
        tsv(row.exit_asn.as_deref().unwrap_or_default()),
        tsv(row.exit_org.as_deref().unwrap_or_default()),
        tsv(&row.stages),
        tsv(row.error.as_deref().unwrap_or_default()),
    ]
    .join("\t")
        + "\n"
}

fn required(matches: &ArgMatches, name: &str) -> Result<String> {
    matches
        .get_one::<String>(name)
        .cloned()
        .ok_or_else(|| anyhow!("missing --{name}"))
}

fn parse_optional_i64(matches: &ArgMatches, name: &str) -> Result<Option<i64>> {
    matches
        .get_one::<String>(name)
        .map(|value| value.parse::<i64>().with_context(|| format!("invalid --{name}")))
        .transpose()
}

fn bracket_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn tsv(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

fn optional_i64(value: Option<i64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn metric(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.3}")).unwrap_or_default()
}

trait OptionalContext<T> {
    fn optional_context(self, message: &str) -> Result<T>;
}

impl<T> OptionalContext<T> for rusqlite::Result<T> {
    fn optional_context(self, message: &str) -> Result<T> {
        self.optional()?.ok_or_else(|| anyhow!(message.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoring_prefers_balanced_faster_proxy() {
        let mut candidates = vec![
            RankedProxy {
                interface_name: "a".into(),
                protocol: "socks5".into(),
                proxy_host: "1.1.1.1".into(),
                proxy_port: 1080,
                auth_required: false,
                latency_ms: Some(10.0),
                download_mbps: Some(100.0),
                upload_mbps: Some(50.0),
                exit_ip: None,
                score: 0.0,
            },
            RankedProxy {
                interface_name: "a".into(),
                protocol: "socks5".into(),
                proxy_host: "2.2.2.2".into(),
                proxy_port: 1080,
                auth_required: false,
                latency_ms: Some(100.0),
                download_mbps: Some(10.0),
                upload_mbps: Some(5.0),
                exit_ip: None,
                score: 0.0,
            },
        ];
        score_candidates(&mut candidates);
        assert!(candidates[0].score > candidates[1].score);
    }

    #[test]
    fn ipv6_links_are_bracketed() {
        assert_eq!(bracket_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(bracket_host("example.com"), "example.com");
    }
}
