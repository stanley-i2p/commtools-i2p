use std::ffi::OsString;
use std::path::PathBuf;

const DATA_DIRECTORY_NAME: &str = ".deskcomm-i2p";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupOptions {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Run(StartupOptions),
    Print(String),
}

pub fn parse_process_args() -> Result<ParseOutcome, String> {
    parse_args(std::env::args_os().skip(1), default_home_directory())
}

fn parse_args(
    args: impl IntoIterator<Item = OsString>,
    home: Option<PathBuf>,
) -> Result<ParseOutcome, String> {
    let mut args = args.into_iter();
    let mut data_dir = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--help" | "-h") => return Ok(ParseOutcome::Print(help_text())),
            Some("--version" | "-V") => {
                return Ok(ParseOutcome::Print(format!(
                    "DeskComm-I2P {}",
                    env!("CARGO_PKG_VERSION")
                )));
            }
            Some("--data-dir") => {
                if data_dir.is_some() {
                    return Err("--data-dir may be specified only once".into());
                }
                let value = args
                    .next()
                    .ok_or_else(|| "--data-dir requires a path".to_string())?;
                if value.is_empty() {
                    return Err("--data-dir must not be empty".into());
                }
                data_dir = Some(PathBuf::from(value));
            }
            Some(value) => return Err(format!("unknown argument: {value}")),
            None => return Err("command-line options must contain valid UTF-8".into()),
        }
    }

    let data_dir = match data_dir {
        Some(path) => absolute_path(path)?,
        None => home
            .map(|path| path.join(DATA_DIRECTORY_NAME))
            .ok_or_else(|| "could not determine the current user's home directory".to_string())?,
    };
    Ok(ParseOutcome::Run(StartupOptions { data_dir }))
}

fn absolute_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path);
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .map_err(|error| format!("could not resolve --data-dir: {error}"))
}

fn default_home_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            if drive.is_empty() || path.is_empty() {
                return None;
            }
            let mut home = PathBuf::from(drive);
            home.push(path);
            Some(home)
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        });

    #[cfg(not(windows))]
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        });

    home
}

fn help_text() -> String {
    format!(
        "DeskComm-I2P {}\n\nUsage: deskcomm-i2p [--data-dir PATH]\n\nOptions:\n  --data-dir PATH  Use an independent application vault\n  -h, --help        Print help\n  -V, --version     Print version",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_directory_is_below_the_user_home() {
        let outcome = parse_args(Vec::<OsString>::new(), Some(PathBuf::from("/home/test")))
            .expect("arguments");
        assert_eq!(
            outcome,
            ParseOutcome::Run(StartupOptions {
                data_dir: Path::new("/home/test").join(DATA_DIRECTORY_NAME),
            })
        );
    }

    #[test]
    fn explicit_absolute_directory_is_preserved() {
        let path = std::env::temp_dir().join("deskcomm-explicit-vault");
        let outcome = parse_args(
            [OsString::from("--data-dir"), path.clone().into_os_string()],
            None,
        )
        .expect("arguments");
        assert_eq!(
            outcome,
            ParseOutcome::Run(StartupOptions { data_dir: path })
        );
    }
}
