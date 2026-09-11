use crate::deaddrop::{GetReplicaStatus, GetResult, PutReplicaStatus, PutResult};
use crate::storage::DeaddropServerStat;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub const ACTIVE_DEADDROP_REPLICA_COUNT: usize = 3;
pub const DEADDROP_EXPLORATION_INTERVAL_OPERATIONS: u64 = 10;
pub const DEADDROP_LATENCY_EMA_ALPHA: f64 = 0.30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeaddropSelection {
    pub active: Vec<String>,
    pub operation: Vec<String>,
    pub candidate: Option<String>,
}

pub fn record_put_result(
    stats: &mut BTreeMap<String, DeaddropServerStat>,
    result: &PutResult,
    now_ms: u64,
) {
    for replica in &result.replicas {
        let Some(stat) = stats.get_mut(&replica.server) else {
            continue;
        };
        let success = matches!(
            replica.status,
            PutReplicaStatus::Stored | PutReplicaStatus::Exists
        );
        update_stat(
            stat,
            OperationKind::Put,
            success,
            replica.latency_ms,
            now_ms,
        );
    }
}

pub fn record_get_result(
    stats: &mut BTreeMap<String, DeaddropServerStat>,
    result: &GetResult,
    now_ms: u64,
) {
    for replica in &result.replicas {
        let Some(stat) = stats.get_mut(&replica.server) else {
            continue;
        };
        let success = matches!(
            replica.status,
            GetReplicaStatus::Hit | GetReplicaStatus::Miss
        );
        update_stat(
            stat,
            OperationKind::Get,
            success,
            replica.latency_ms,
            now_ms,
        );
    }
}

pub fn ranked_deaddrop_servers(
    servers: &[String],
    stats: &BTreeMap<String, DeaddropServerStat>,
) -> Vec<String> {
    let original_order = servers
        .iter()
        .enumerate()
        .map(|(index, server)| (server.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut ranked = servers.to_vec();
    ranked.sort_by(|left, right| {
        deaddrop_server_score(stats.get(right))
            .partial_cmp(&deaddrop_server_score(stats.get(left)))
            .unwrap_or(Ordering::Equal)
            .then_with(|| {
                original_order
                    .get(left.as_str())
                    .copied()
                    .unwrap_or(usize::MAX)
                    .cmp(
                        &original_order
                            .get(right.as_str())
                            .copied()
                            .unwrap_or(usize::MAX),
                    )
            })
    });
    ranked
}

pub fn select_deaddrop_servers(
    servers: &[String],
    stats: &BTreeMap<String, DeaddropServerStat>,
    operation_sequence: u64,
) -> DeaddropSelection {
    let ranked = ranked_deaddrop_servers(servers, stats);
    let active = ranked
        .iter()
        .take(ACTIVE_DEADDROP_REPLICA_COUNT)
        .cloned()
        .collect::<Vec<_>>();
    let active_set = active.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let standby = servers
        .iter()
        .filter(|server| !active_set.contains(server.as_str()))
        .collect::<Vec<_>>();
    let candidate = if !standby.is_empty()
        && operation_sequence % DEADDROP_EXPLORATION_INTERVAL_OPERATIONS == 0
    {
        let exploration_round = operation_sequence / DEADDROP_EXPLORATION_INTERVAL_OPERATIONS;
        let untested = standby
            .iter()
            .filter(|server| {
                stats
                    .get(server.as_str())
                    .is_none_or(|stat| total_samples(stat) == 0)
            })
            .collect::<Vec<_>>();
        if untested.is_empty() {
            let index = (exploration_round % standby.len() as u64) as usize;
            Some(standby[index].clone())
        } else {
            let index = (exploration_round % untested.len() as u64) as usize;
            Some((*untested[index]).clone())
        }
    } else {
        None
    };
    let mut operation = active.clone();
    if let Some(candidate) = &candidate {
        operation.push(candidate.clone());
    }
    DeaddropSelection {
        active,
        operation,
        candidate,
    }
}

fn deaddrop_server_score(stat: Option<&DeaddropServerStat>) -> f64 {
    let Some(stat) = stat.filter(|stat| total_samples(stat) > 0) else {
        return 0.0;
    };
    let successes = stat.put_ok.saturating_add(stat.get_ok) as f64;
    let failures = stat.put_fail.saturating_add(stat.get_fail) as f64;
    let total = successes + failures;
    let success_ratio = successes / total;
    let latency_penalty = if stat.latency_ema_ms.is_finite() {
        stat.latency_ema_ms.max(0.0)
    } else {
        f64::MAX
    };
    let failure_penalty = failures * 2_500.0;
    let recency_bonus = stat.last_success_ms as f64 / 1_000_000_000.0;
    (success_ratio * 100_000.0) - latency_penalty - failure_penalty + recency_bonus
}

#[derive(Debug, Clone, Copy)]
enum OperationKind {
    Put,
    Get,
}

fn update_stat(
    stat: &mut DeaddropServerStat,
    operation: OperationKind,
    success: bool,
    latency_ms: u64,
    now_ms: u64,
) {
    match (operation, success) {
        (OperationKind::Put, true) => stat.put_ok = stat.put_ok.saturating_add(1),
        (OperationKind::Put, false) => stat.put_fail = stat.put_fail.saturating_add(1),
        (OperationKind::Get, true) => stat.get_ok = stat.get_ok.saturating_add(1),
        (OperationKind::Get, false) => stat.get_fail = stat.get_fail.saturating_add(1),
    }
    if success {
        stat.last_success_ms = now_ms;
    }
    if latency_ms > 0 {
        let latency_ms = latency_ms as f64;
        stat.latency_ema_ms = if stat.latency_samples == 0
            || !stat.latency_ema_ms.is_finite()
            || stat.latency_ema_ms <= 0.0
        {
            latency_ms
        } else {
            (DEADDROP_LATENCY_EMA_ALPHA * latency_ms)
                + ((1.0 - DEADDROP_LATENCY_EMA_ALPHA) * stat.latency_ema_ms)
        };
        stat.latency_samples = stat.latency_samples.saturating_add(1);
    }
}

fn total_samples(stat: &DeaddropServerStat) -> u64 {
    stat.put_ok
        .saturating_add(stat.put_fail)
        .saturating_add(stat.get_ok)
        .saturating_add(stat.get_fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deaddrop::{GetReplicaResult, PutReplicaResult, PutStatus};

    fn servers(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("server-{index}")).collect()
    }

    #[test]
    fn records_protocol_misses_and_existing_puts_as_successes() {
        let mut stats = BTreeMap::from([
            ("put".into(), DeaddropServerStat::default()),
            ("get".into(), DeaddropServerStat::default()),
        ]);
        record_put_result(
            &mut stats,
            &PutResult {
                status: PutStatus::Exists,
                successful_servers: vec!["put".into()],
                replicas: vec![PutReplicaResult {
                    server: "put".into(),
                    status: PutReplicaStatus::Exists,
                    latency_ms: 100,
                    detail: "EXISTS".into(),
                }],
            },
            1_000,
        );
        record_get_result(
            &mut stats,
            &GetResult {
                replicas: vec![GetReplicaResult {
                    server: "get".into(),
                    status: GetReplicaStatus::Miss,
                    blob: None,
                    latency_ms: 200,
                    detail: "MISS".into(),
                }],
            },
            2_000,
        );

        assert_eq!(stats["put"].put_ok, 1);
        assert_eq!(stats["put"].put_fail, 0);
        assert_eq!(stats["put"].last_success_ms, 1_000);
        assert_eq!(stats["get"].get_ok, 1);
        assert_eq!(stats["get"].get_fail, 0);
        assert_eq!(stats["get"].last_success_ms, 2_000);
    }

    #[test]
    fn records_failures_and_updates_latency_ema() {
        let mut stats = BTreeMap::from([("drop".into(), DeaddropServerStat::default())]);
        let first = PutResult {
            status: PutStatus::Failed,
            successful_servers: Vec::new(),
            replicas: vec![PutReplicaResult {
                server: "drop".into(),
                status: PutReplicaStatus::Failed,
                latency_ms: 100,
                detail: "failed".into(),
            }],
        };
        let second = PutResult {
            replicas: vec![PutReplicaResult {
                latency_ms: 200,
                ..first.replicas[0].clone()
            }],
            ..first.clone()
        };
        record_put_result(&mut stats, &first, 1_000);
        record_put_result(&mut stats, &second, 2_000);

        assert_eq!(stats["drop"].put_fail, 2);
        assert_eq!(stats["drop"].latency_samples, 2);
        assert!((stats["drop"].latency_ema_ms - 130.0).abs() < f64::EPSILON);
        assert_eq!(stats["drop"].last_success_ms, 0);
    }

    #[test]
    fn ranking_is_deterministic_and_prefers_successful_servers() {
        let servers = servers(4);
        let mut stats = BTreeMap::new();
        for server in &servers {
            stats.insert(server.clone(), DeaddropServerStat::default());
        }
        stats.get_mut(&servers[2]).expect("stat").get_ok = 5;
        stats.get_mut(&servers[3]).expect("stat").get_fail = 5;

        assert_eq!(
            ranked_deaddrop_servers(&servers, &stats),
            vec![
                servers[2].clone(),
                servers[0].clone(),
                servers[1].clone(),
                servers[3].clone()
            ]
        );
    }

    #[test]
    fn untested_servers_rank_ahead_of_known_failures() {
        let servers = servers(2);
        let mut stats = BTreeMap::from([
            (servers[0].clone(), DeaddropServerStat::default()),
            (servers[1].clone(), DeaddropServerStat::default()),
        ]);
        stats.get_mut(&servers[0]).expect("stat").put_fail = 1;

        assert_eq!(
            ranked_deaddrop_servers(&servers, &stats),
            vec![servers[1].clone(), servers[0].clone()]
        );
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut stats = BTreeMap::from([(
            "drop".into(),
            DeaddropServerStat {
                put_ok: u64::MAX,
                ..DeaddropServerStat::default()
            },
        )]);
        record_put_result(
            &mut stats,
            &PutResult {
                status: PutStatus::Stored,
                successful_servers: vec!["drop".into()],
                replicas: vec![PutReplicaResult {
                    server: "drop".into(),
                    status: PutReplicaStatus::Stored,
                    latency_ms: 1,
                    detail: "OK".into(),
                }],
            },
            1,
        );

        assert_eq!(stats["drop"].put_ok, u64::MAX);
    }

    #[test]
    fn exploration_adds_a_candidate_without_replacing_active_replicas() {
        let servers = servers(5);
        let stats = BTreeMap::new();
        let selection = select_deaddrop_servers(&servers, &stats, 0);

        assert_eq!(selection.active, servers[..3]);
        assert_eq!(selection.operation[..3], servers[..3]);
        assert_eq!(selection.operation.len(), 4);
        assert_eq!(selection.candidate.as_deref(), Some(servers[3].as_str()));

        let ordinary = select_deaddrop_servers(&servers, &stats, 1);
        assert_eq!(ordinary.operation, ordinary.active);
        assert!(ordinary.candidate.is_none());
    }

    #[test]
    fn exploration_rotates_across_untested_standby_servers() {
        let servers = servers(5);
        let stats = BTreeMap::new();

        assert_eq!(
            select_deaddrop_servers(&servers, &stats, 0)
                .candidate
                .as_deref(),
            Some(servers[3].as_str())
        );
        assert_eq!(
            select_deaddrop_servers(&servers, &stats, DEADDROP_EXPLORATION_INTERVAL_OPERATIONS,)
                .candidate
                .as_deref(),
            Some(servers[4].as_str())
        );
    }
}
