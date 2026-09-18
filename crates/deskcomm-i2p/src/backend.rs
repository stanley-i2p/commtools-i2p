use commtools_core::{ApplicationPhase, VaultLease, VaultRepository};
use commtools_runtime::{
    ApplicationDriver, ApplicationDriverConfig, CommToolsCommand, CommToolsCommandResult,
    CommToolsSnapshot, FrontendEvent,
};
use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc as tokio_mpsc;
use zeroize::Zeroizing;

const DRIVER_TICK_INTERVAL: Duration = Duration::from_millis(100);

pub enum BackendCommand {
    OpenVault {
        passphrase: Zeroizing<String>,
        create: bool,
    },
    Runtime(CommToolsCommand),
    Shutdown,
}

#[derive(Debug)]
pub enum BackendEvent {
    GateFailed(String),
    Ready(CommToolsSnapshot),
    Snapshot(CommToolsSnapshot),
    Frontend(FrontendEvent),
    CommandCompleted(CommToolsCommandResult),
    CommandFailed(String),
    SamLivenessShutdown,
    Fatal(String),
    Stopped,
}

#[derive(Clone)]
pub struct BackendSender {
    commands: tokio_mpsc::UnboundedSender<BackendCommand>,
}

impl BackendSender {
    pub fn send(&self, command: BackendCommand) -> Result<(), String> {
        self.commands
            .send(command)
            .map_err(|_| "DeskComm backend is no longer available".to_string())
    }
}

pub struct BackendHandle {
    sender: BackendSender,
    thread: Option<thread::JoinHandle<()>>,
}

impl BackendHandle {
    pub fn spawn(
        repository: VaultRepository,
        lease: VaultLease,
    ) -> io::Result<(Self, mpsc::Receiver<BackendEvent>)> {
        let (commands_tx, commands_rx) = tokio_mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("deskcomm-runtime".into())
            .spawn(move || run_backend(repository, lease, commands_rx, events_tx))?;
        Ok((
            Self {
                sender: BackendSender {
                    commands: commands_tx,
                },
                thread: Some(thread),
            },
            events_rx,
        ))
    }

    pub fn sender(&self) -> BackendSender {
        self.sender.clone()
    }

    pub fn join(mut self) -> thread::Result<()> {
        drop(self.sender);
        self.thread
            .take()
            .expect("backend thread is present")
            .join()
    }
}

fn run_backend(
    repository: VaultRepository,
    _lease: VaultLease,
    commands: tokio_mpsc::UnboundedReceiver<BackendCommand>,
    events: mpsc::Sender<BackendEvent>,
) {
    let driver_config = ApplicationDriverConfig::new("deskcomm")
        .expect("DeskComm SAM session prefix is a valid constant");
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("deskcomm-io")
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = events.send(BackendEvent::Fatal(format!(
                "Could not start the asynchronous runtime: {error}"
            )));
            return;
        }
    };
    runtime.block_on(backend_loop(repository, driver_config, commands, events));
}

async fn backend_loop(
    repository: VaultRepository,
    driver_config: ApplicationDriverConfig,
    mut commands: tokio_mpsc::UnboundedReceiver<BackendCommand>,
    events: mpsc::Sender<BackendEvent>,
) {
    let mut driver: Option<ApplicationDriver> = None;
    let mut last_snapshot: Option<CommToolsSnapshot> = None;
    let mut shutting_down = false;
    let mut wipe_after_shutdown = false;
    let mut tick = tokio::time::interval(DRIVER_TICK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(BackendCommand::OpenVault { passphrase, create }) if driver.is_none() && !shutting_down => {
                        let result = if create {
                            repository.create(passphrase.as_bytes())
                        } else {
                            repository.unlock(passphrase.as_bytes())
                        };
                        match result {
                            Ok(vault) => {
                                let active_driver =
                                    ApplicationDriver::with_config(vault, driver_config.clone());
                                match active_driver.snapshot() {
                                    Ok(snapshot) => {
                                        last_snapshot = Some(snapshot.clone());
                                        driver = Some(active_driver);
                                        if events.send(BackendEvent::Ready(snapshot)).is_err() {
                                            shutting_down = true;
                                        }
                                    }
                                    Err(error) => {
                                        let _ = events.send(BackendEvent::Fatal(format!(
                                            "Could not read application state: {error}"
                                        )));
                                        driver = Some(active_driver);
                                        shutting_down = true;
                                    }
                                }
                            }
                            Err(error) => {
                                let _ = events.send(BackendEvent::GateFailed(error.to_string()));
                            }
                        }
                    }
                    Some(BackendCommand::OpenVault { .. }) => {}
                    Some(BackendCommand::Runtime(command)) if driver.is_some() && !shutting_down => {
                        let active_driver = driver.as_mut().expect("driver checked above");
                        match active_driver.dispatch_command(command) {
                            Ok(result) => {
                                if matches!(&result, CommToolsCommandResult::WipeAllAuthorized) {
                                    wipe_after_shutdown = true;
                                    shutting_down = true;
                                }
                                let _ = events.send(BackendEvent::CommandCompleted(result));
                                if let Ok(snapshot) = active_driver.snapshot() {
                                    last_snapshot = Some(snapshot.clone());
                                    let _ = events.send(BackendEvent::Snapshot(snapshot));
                                }
                            }
                            Err(error) => {
                                let _ = events.send(BackendEvent::CommandFailed(error.to_string()));
                            }
                        }
                    }
                    Some(BackendCommand::Runtime(_)) => {
                        let _ = events.send(BackendEvent::CommandFailed(
                            "Application runtime is not ready".into(),
                        ));
                    }
                    Some(BackendCommand::Shutdown) | None => {
                        shutting_down = true;
                    }
                }
            }
            _ = tick.tick(), if driver.is_some() => {
                let active_driver = driver.as_mut().expect("driver checked above");
                if let Err(error) = active_driver.tick() {
                    let _ = events.send(BackendEvent::Fatal(format!(
                        "CommTools runtime failed: {error}"
                    )));
                    shutting_down = true;
                }
                loop {
                    match active_driver.try_next_frontend_event() {
                        Ok(Some(event)) => {
                            if events.send(BackendEvent::Frontend(event)).is_err() {
                                shutting_down = true;
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let _ = events.send(BackendEvent::Fatal(format!(
                                "Could not process a CommTools event: {error}"
                            )));
                            shutting_down = true;
                            break;
                        }
                    }
                }
                let sam_liveness_shutdown_requested =
                    active_driver.take_sam_liveness_shutdown_request();
                if let Ok(snapshot) = active_driver.snapshot()
                    && last_snapshot.as_ref() != Some(&snapshot)
                {
                    last_snapshot = Some(snapshot.clone());
                    let _ = events.send(BackendEvent::Snapshot(snapshot));
                }
                if sam_liveness_shutdown_requested {
                    let _ = events.send(BackendEvent::SamLivenessShutdown);
                    shutting_down = true;
                }
            }
        }

        if shutting_down {
            let Some(active_driver) = driver.as_mut() else {
                let _ = events.send(BackendEvent::Stopped);
                return;
            };
            if active_driver.application_phase() == ApplicationPhase::Running
                && let Err(error) = active_driver.begin_shutdown()
            {
                let _ = events.send(BackendEvent::Fatal(format!(
                    "Could not begin graceful shutdown: {error}"
                )));
                return;
            }
            if active_driver.application_phase() == ApplicationPhase::Stopped {
                drop(driver.take());
                if wipe_after_shutdown
                    && let Err(error) = repository.wipe_all()
                {
                    let _ = events.send(BackendEvent::Fatal(format!(
                        "Could not wipe local application data: {error}"
                    )));
                    return;
                }
                let _ = events.send(BackendEvent::Stopped);
                return;
            }
        }
    }
}
