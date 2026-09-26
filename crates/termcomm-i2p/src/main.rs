#![forbid(unsafe_code)]

//! Ratatui shell for the CommTools runtime.
//!


mod cli;
mod gate;
mod image_media;
mod shell;
mod terminal;
mod workspace;

use cli::{ParseOutcome, StartupOptions};
use commtools_core::{ApplicationPhase, VaultError, VaultRepository};
use commtools_runtime::{
    ApplicationDriver, CommToolsCommand, DriverError, FrontendEvent, RuntimeOperationEvent,
};
use crossterm::event::EventStream;
use futures_util::StreamExt;
use shell::{ShellAction, ShellState};
use std::io;
use std::process::ExitCode;
use std::time::Duration;
use terminal::TerminalSession;
use thiserror::Error;

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Arguments(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Gate(#[from] gate::GateError),
    #[error(transparent)]
    Driver(#[from] DriverError),
    #[error("terminal event stream ended")]
    EventStreamEnded,
    #[error("shutdown failed during {operation}: {reason}")]
    Shutdown { operation: String, reason: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("TermComm-I2P: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), AppError> {
    let options = match cli::parse_process_args().map_err(AppError::Arguments)? {
        ParseOutcome::Run(options) => options,
        ParseOutcome::Print(output) => {
            println!("{output}");
            return Ok(());
        }
    };
    run_terminal(options).await
}

async fn run_terminal(options: StartupOptions) -> Result<(), AppError> {
    let repository = VaultRepository::new(&options.data_dir)?;
    let lease = repository.try_acquire_lease()?;
    let mut terminal = TerminalSession::enter()?;
    let mut events = EventStream::new();
    let Some(vault) = gate::run(&mut terminal, &mut events, &repository).await? else {
        terminal.restore()?;
        return Ok(());
    };

    let mut driver = ApplicationDriver::new(vault);
    let shell_result = run_shell(&mut terminal, &mut events, &mut driver, &options).await;
    let shutdown_result = shutdown_driver(&mut driver).await;
    drop(driver);
    let wipe_result =
        if matches!(&shell_result, Ok(ShellAction::WipeAll)) && shutdown_result.is_ok() {
            repository.wipe_all()
        } else {
            Ok(())
        };
    drop(lease);
    let restore_result = terminal.restore();
    shell_result?;
    shutdown_result?;
    wipe_result?;
    restore_result?;
    Ok(())
}

async fn run_shell(
    terminal: &mut TerminalSession,
    events: &mut EventStream,
    driver: &mut ApplicationDriver,
    options: &StartupOptions,
) -> Result<ShellAction, AppError> {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut animation_tick = tokio::time::interval(Duration::from_millis(125));
    animation_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shell = ShellState::new(driver, &options.data_dir);
    draw_shell(terminal, &mut shell, driver, options)?;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                driver.tick()?;
                while let Some(event) = driver.try_next_frontend_event()? {
                    shell.handle_frontend_event(&event, driver);
                }
                if driver.take_sam_liveness_shutdown_request() {
                    return Ok(ShellAction::Quit);
                }
                draw_shell(terminal, &mut shell, driver, options)?;
            }
            _ = animation_tick.tick() => {
                if shell.advance_animation() {
                    draw_shell(terminal, &mut shell, driver, options)?;
                }
            }
            event = events.next() => {
                let event = event.ok_or(AppError::EventStreamEnded)??;
                let action = shell.handle_event(event, driver);
                if action != ShellAction::Continue {
                    return Ok(action);
                }
                if let Some(invite) = shell.take_pending_clipboard() {
                    let result = terminal.copy_to_clipboard(invite.as_str());
                    shell.record_clipboard_result(result);
                }
                draw_shell(terminal, &mut shell, driver, options)?;
            }
        }
    }
}

async fn shutdown_driver(driver: &mut ApplicationDriver) -> Result<(), AppError> {

    driver.dispatch_command(CommToolsCommand::BeginShutdown)?;
    while driver.application_phase() != ApplicationPhase::Stopped {
        if let FrontendEvent::Operation(RuntimeOperationEvent::Failed {
            session_id: None,
            operation,
            reason,
        }) = driver.next_frontend_event().await?
        {
            return Err(AppError::Shutdown { operation, reason });
        }
    }
    Ok(())
}

fn draw_shell(
    terminal: &mut TerminalSession,
    shell: &mut ShellState,
    driver: &ApplicationDriver,
    options: &StartupOptions,
) -> io::Result<()> {
    terminal
        .terminal_mut()
        .draw(|frame| shell.render(frame, driver, options))?;
    Ok(())
}
