use crate::{AppWindow, VaultAnimationNode};
use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NODE_COUNT: usize = 25;
const MAX_TRANSITIONAL_NODE_COUNT: usize = 4;
const MAX_RECEIVER_COUNT: usize = 10;
const FRAME_INTERVAL: Duration = Duration::from_millis(33);
const HOP_REVEAL_INTERVAL: Duration = Duration::from_millis(140);
const COMPLETED_TRANSMISSION_HOLD: Duration = Duration::from_millis(450);
const IDLE_COOLDOWN: Duration = Duration::from_millis(400);
const DRIFT_FACTOR: f32 = 0.005;
const TARGET_REACHED_DISTANCE: f32 = 5.0;
const NODE_SIZE: f32 = 5.0; //7.0
const ACTIVE_NODE_SIZE_MULTIPLIER: f32 = 1.2;
const MAX_ACTIVE_EDGE_CURVATURE: f32 = 0.3;
const ACTIVE_EDGE_MAX_CURVE_OFFSET: f32 = 36.0;
const CANVAS_WIDTH: f32 = 720.0;
const CANVAS_HEIGHT: f32 = 680.0;
const CANVAS_MARGIN: f32 = 40.0;

struct PhysicsNode {
    x: f32,
    y: f32,
    target_x: f32,
    target_y: f32,
    state: NodeState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeState {
    Default,
    Sender,
    Receiver,
}

struct AnimationRng {
    state: u64,
}

impl AnimationRng {
    fn new() -> Self {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let seed = time ^ u64::from(std::process::id()).rotate_left(32);
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn range_f32(&mut self, start: f32, end: f32) -> f32 {
        let unit = (self.next_u64() >> 40) as f32 / ((1_u32 << 24) - 1) as f32;
        start + (end - start) * unit
    }

    fn range_usize_inclusive(&mut self, start: usize, end: usize) -> usize {
        start + self.next_u64() as usize % (end - start + 1)
    }

    fn shuffle(&mut self, values: &mut [usize]) {
        for index in (1..values.len()).rev() {
            let replacement = self.range_usize_inclusive(0, index);
            values.swap(index, replacement);
        }
    }
}

impl NodeState {
    fn presentation_value(self) -> i32 {
        match self {
            Self::Default => 0,
            Self::Sender => 1,
            Self::Receiver => 2,
        }
    }
}

pub(crate) struct VaultAnimationController {
    timer: Timer,
}

impl VaultAnimationController {
    pub(crate) fn stop(&self) {
        self.timer.stop();
    }
}

pub(crate) fn start(ui: &AppWindow) -> VaultAnimationController {
    assert!(NODE_COUNT >= MAX_TRANSITIONAL_NODE_COUNT.saturating_add(2));
    assert!(MAX_RECEIVER_COUNT > 0);

    let mut rng = AnimationRng::new();
    let mut nodes = (0..NODE_COUNT)
        .map(|_| PhysicsNode {
            x: random_x(&mut rng),
            y: random_y(&mut rng),
            target_x: random_x(&mut rng),
            target_y: random_y(&mut rng),
            state: NodeState::Default,
        })
        .collect::<Vec<_>>();
    let mut last_state_change = Instant::now();
    let mut last_hop_reveal = Instant::now();
    let mut transmitting = false;
    let mut active_paths: Vec<Vec<usize>> = Vec::new();
    let mut revealed_edge_count = 0;
    let mut maximum_edge_count = 0;

    publish_frame(
        ui,
        &nodes,
        &active_paths,
        transmitting,
        revealed_edge_count,
        configured_curvature(ui),
    );

    let ui = ui.as_weak();
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, FRAME_INTERVAL, move || {
        let Some(ui) = ui.upgrade() else {
            return;
        };
        if ui.get_screen() >= 2 {
            return;
        }

        if transmitting {
            if revealed_edge_count < maximum_edge_count
                && last_hop_reveal.elapsed() >= HOP_REVEAL_INTERVAL
            {
                revealed_edge_count += 1;
                mark_reached_receivers(&mut nodes, &active_paths, revealed_edge_count);
                last_hop_reveal = Instant::now();
                if revealed_edge_count == maximum_edge_count {
                    last_state_change = last_hop_reveal;
                }
            } else if revealed_edge_count == maximum_edge_count
                && last_state_change.elapsed() > COMPLETED_TRANSMISSION_HOLD
            {
                transmitting = false;
                for node in &mut nodes {
                    node.state = NodeState::Default;
                }
                active_paths.clear();
                revealed_edge_count = 0;
                maximum_edge_count = 0;
                last_state_change = Instant::now();
            }
        } else if last_state_change.elapsed() > IDLE_COOLDOWN {
            transmitting = true;
            select_transmission(
                &mut nodes,
                &mut active_paths,
                &mut rng,
                configured_transitional_node_count(&ui),
            );
            maximum_edge_count = active_paths
                .iter()
                .map(|path| path.len().saturating_sub(1))
                .max()
                .unwrap_or(0);
            revealed_edge_count = maximum_edge_count.min(1);
            mark_reached_receivers(&mut nodes, &active_paths, revealed_edge_count);
            last_hop_reveal = Instant::now();
            last_state_change = Instant::now();
        }

        for node in &mut nodes {
            node.x += (node.target_x - node.x) * DRIFT_FACTOR;
            node.y += (node.target_y - node.y) * DRIFT_FACTOR;
            if (node.x - node.target_x).abs() < TARGET_REACHED_DISTANCE {
                node.target_x = random_x(&mut rng);
                node.target_y = random_y(&mut rng);
            }
        }

        publish_frame(
            &ui,
            &nodes,
            &active_paths,
            transmitting,
            revealed_edge_count,
            configured_curvature(&ui),
        );
        ui.window().request_redraw();
    });

    VaultAnimationController { timer }
}

fn select_transmission(
    nodes: &mut [PhysicsNode],
    active_paths: &mut Vec<Vec<usize>>,
    rng: &mut AnimationRng,
    transitional_node_count: usize,
) {
    let mut candidates = (0..nodes.len()).collect::<Vec<_>>();
    rng.shuffle(&mut candidates);

    let sender = candidates[0];
    nodes[sender].state = NodeState::Sender;
    let receiver_capacity =
        nodes.len().saturating_sub(1) / transitional_node_count.saturating_add(1);
    let receiver_count = rng.range_usize_inclusive(1, MAX_RECEIVER_COUNT.min(receiver_capacity));
    let mut offset = 1;

    for _ in 0..receiver_count {
        let transition_end = offset + transitional_node_count;
        let receiver = candidates[transition_end];
        let mut path = Vec::with_capacity(transitional_node_count + 2);
        path.push(sender);
        path.extend_from_slice(&candidates[offset..transition_end]);
        path.push(receiver);
        active_paths.push(path);
        offset = transition_end + 1;
    }
}

fn mark_reached_receivers(
    nodes: &mut [PhysicsNode],
    active_paths: &[Vec<usize>],
    revealed_edge_count: usize,
) {
    for path in active_paths {
        if revealed_edge_count >= path.len().saturating_sub(1)
            && let Some(receiver) = path.last()
        {
            nodes[*receiver].state = NodeState::Receiver;
        }
    }
}

fn publish_frame(
    ui: &AppWindow,
    nodes: &[PhysicsNode],
    active_paths: &[Vec<usize>],
    transmitting: bool,
    revealed_edge_count: usize,
    active_edge_curvature: f32,
) {
    let mut background_edges = String::new();
    let mut active_edges = String::new();
    for first in 0..nodes.len() {
        for second in (first + 1)..nodes.len() {
            let active = transmitting
                && active_paths.iter().any(|path| {
                    path.windows(2).take(revealed_edge_count).any(|edge| {
                        (edge[0] == first && edge[1] == second)
                            || (edge[0] == second && edge[1] == first)
                    })
                });
            if active {
                active_edges.push_str(&active_edge_command(
                    first,
                    second,
                    nodes,
                    active_edge_curvature,
                ));
            } else {
                background_edges.push_str(&straight_edge_command(first, second, nodes));
            }
        }
    }

    let presented_nodes = nodes
        .iter()
        .map(|node| VaultAnimationNode {
            x: node.x,
            y: node.y,
            size: NODE_SIZE
                * if node.state == NodeState::Default {
                    1.0
                } else {
                    ACTIVE_NODE_SIZE_MULTIPLIER
                },
            state: node.state.presentation_value(),
        })
        .collect::<Vec<_>>();
    ui.set_vault_animation_nodes(ModelRc::new(VecModel::from(presented_nodes)));
    ui.set_vault_animation_background_edges(background_edges.into());
    ui.set_vault_animation_active_edges(active_edges.into());
}

fn configured_transitional_node_count(ui: &AppWindow) -> usize {
    usize::try_from(ui.get_vault_animation_hop_count())
        .unwrap_or_default()
        .min(MAX_TRANSITIONAL_NODE_COUNT)
}

fn configured_curvature(ui: &AppWindow) -> f32 {
    (ui.get_vault_animation_curve_percent().clamp(0, 30) as f32 / 100.0)
        .min(MAX_ACTIVE_EDGE_CURVATURE)
}

fn straight_edge_command(first: usize, second: usize, nodes: &[PhysicsNode]) -> String {
    format!(
        "M {} {} L {} {} ",
        nodes[first].x, nodes[first].y, nodes[second].x, nodes[second].y
    )
}

fn active_edge_command(
    first: usize,
    second: usize,
    nodes: &[PhysicsNode],
    curvature: f32,
) -> String {
    if curvature <= 0.0 {
        return straight_edge_command(first, second, nodes);
    }

    let start = &nodes[first];
    let end = &nodes[second];
    let delta_x = end.x - start.x;
    let delta_y = end.y - start.y;
    let length = delta_x.hypot(delta_y);
    if length <= f32::EPSILON {
        return straight_edge_command(first, second, nodes);
    }

    let direction = if edge_curve_direction(first, second) {
        1.0
    } else {
        -1.0
    };
    let offset = (length * curvature).min(ACTIVE_EDGE_MAX_CURVE_OFFSET) * direction;
    let control_x = (start.x + end.x) * 0.5 - delta_y / length * offset;
    let control_y = (start.y + end.y) * 0.5 + delta_x / length * offset;
    format!(
        "M {} {} Q {} {} {} {} ",
        start.x, start.y, control_x, control_y, end.x, end.y
    )
}

fn edge_curve_direction(first: usize, second: usize) -> bool {
    first
        .wrapping_mul(31)
        .wrapping_add(second.wrapping_mul(17))
        % 2
        == 0
}

fn random_x(rng: &mut AnimationRng) -> f32 {
    rng.range_f32(CANVAS_MARGIN, CANVAS_WIDTH - CANVAS_MARGIN)
}

fn random_y(rng: &mut AnimationRng) -> f32 {
    rng.range_f32(CANVAS_MARGIN, CANVAS_HEIGHT - CANVAS_MARGIN)
}
