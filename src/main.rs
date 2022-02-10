use log::{debug, error, info, warn};

mod error;

use error::Error;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

use async_std::fs::File;
use async_std::io::{self, ReadExt, WriteExt};
use async_std::sync::Mutex;
use async_std::task;
use futures::try_join;

use nix::sys::ptrace::{self, Event, Options};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use nix::unistd::{self, ForkResult};

struct Child {
    pid: Pid,

    stdin: File,
    stdout: File,
    stderr: File,
}

struct ProcessDescription {
    state: ProcessState,
    parent: Option<Pid>,

    name: Option<String>,
}

enum ProcessState {
    Traced,
    Completed(u8),
}

fn main() -> Result<(), Error> {
    let env = env_logger::Env::new().filter_or("LOG", "info");
    env_logger::init_from_env(env);

    info!("forking child process...");

    let child = spawn_child()?;
    task::block_on(async_main(child))
}

fn spawn_child() -> Result<Child, Error> {
    let child_stdin = unistd::pipe().map_err(|e| Error::Nix {
        msg: "pipe",
        src: e,
    })?;

    let child_stdout = unistd::pipe().map_err(|e| Error::Nix {
        msg: "pipe",
        src: e,
    })?;

    let child_stderr = unistd::pipe().map_err(|e| Error::Nix {
        msg: "pipe",
        src: e,
    })?;

    let pid = unsafe {
        match nix::unistd::fork().map_err(|e| Error::Nix {
            msg: "fork",
            src: e,
        })? {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                let err = run_child(
                    vec!["/bin/sh", "-c", "/bin/true"],
                    child_stdin.0,
                    child_stdout.1,
                    child_stderr.1,
                );
                error!("error spawning child: {}", err);
                std::process::exit(1);
            }
        }
    };

    Ok(Child {
        pid,
        stdin: unsafe { File::from_raw_fd(child_stdin.1) },
        stdout: unsafe { File::from_raw_fd(child_stdout.0) },
        stderr: unsafe { File::from_raw_fd(child_stderr.0) },
    })
}

fn run_child(args: Vec<&str>, stdin: RawFd, stdout: RawFd, stderr: RawFd) -> Error {
    enum Never {}

    fn int(args: Vec<&str>, stdin: RawFd, stdout: RawFd, stderr: RawFd) -> Result<Never, Error> {
        // swap 3 main fds
        unistd::dup2(stdin, 0).map_err(|e| Error::Nix {
            msg: "dup2",
            src: e,
        })?;
        unistd::dup2(stdout, 1).map_err(|e| Error::Nix {
            msg: "dup2",
            src: e,
        })?;
        unistd::dup2(stderr, 2).map_err(|e| Error::Nix {
            msg: "dup2",
            src: e,
        })?;

        // ask to be traced (stops process)
        ptrace::traceme().map_err(|e| Error::Nix {
            msg: "PTRACE_TRACEME",
            src: e,
        })?;

        unistd::execve::<_, &CStr>(
            &CString::new(args[0]).unwrap(),
            args.into_iter()
                .map(CString::new)
                .map(Result::unwrap)
                .collect::<Vec<_>>()
                .as_slice(),
            &[],
        )
        .map_err(|e| Error::Nix {
            msg: "execve",
            src: e,
        })?;

        unreachable!("execve doesn't return on success")
    }

    match int(args, stdin, stdout, stderr) {
        Ok(s) => match s {},
        Err(e) => e,
    }
}

async fn async_main(child: Child) -> Result<(), Error> {
    let child_stdin = child.stdin;
    let child_stdout = child.stdout;
    let child_stderr = child.stderr;
    let child = child.pid;

    let children = Arc::new(Mutex::new({
        let mut m = HashMap::new();
        m.insert(
            child,
            ProcessDescription {
                state: ProcessState::Traced,
                parent: None,
                name: Some("main".to_string()),
            },
        );
        m
    }));

    let wait_loop = task::spawn(wait_loop(children.clone()));

    ptrace::setoptions(
        child,
        Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEEXIT
            | Options::PTRACE_O_TRACEVFORK,
    )
    .map_err(|e| Error::Nix {
        msg: "PTRACE_SETOPTIONS",
        src: e,
    })?;

    ptrace::cont(child, None).map_err(|e| Error::Nix {
        msg: "PTRACE_CONT",
        src: e,
    })?;

    try_join!(wait_loop, task::spawn(handle_input(child_stdin)))?;
    Ok(())
}

async fn handle_input(mut stdin_pipe: File) -> Result<(), Error> {
    let mut stdin = io::stdin();

    let mut bytes_in = vec![0 as u8; 128];
    let mut bytes_out = vec![0 as u8; 128];
    loop {
        let num_read = stdin.read(&mut bytes_in).await?;

        for i in 0..num_read {
            debug!("forwarded byte: {}", i);
            bytes_out[i] = bytes_in[i];
        }

        stdin_pipe.write_all(&bytes_out[0..num_read]).await?;
    }
}

async fn wait_loop(children: Arc<Mutex<HashMap<Pid, ProcessDescription>>>) -> Result<(), Error> {
    while !children.lock().await.is_empty() {
        let wait_result = wait().map_err(|e| Error::Nix {
            msg: "wait",
            src: e,
        })?;

        match &wait_result {
            WaitStatus::PtraceEvent(pid, _, event) => match match_event(*event) {
                Some(Event::PTRACE_EVENT_FORK) => info!("process {} forked", pid),
                Some(Event::PTRACE_EVENT_VFORK) => info!("process {} vforked", pid),
                Some(Event::PTRACE_EVENT_CLONE) => info!("process {} cloned", pid),
                Some(Event::PTRACE_EVENT_EXEC) => info!("process {} execed", pid),
                Some(Event::PTRACE_EVENT_VFORK_DONE) => {
                    info!("process {} returned from vfork", pid)
                }
                Some(Event::PTRACE_EVENT_EXIT) => info!("process {} exited", pid),
                Some(Event::PTRACE_EVENT_SECCOMP) => {
                    info!("process {} triggered a seccomp rule", pid)
                }
                Some(Event::PTRACE_EVENT_STOP) => info!("process {} stopped", pid),

                Some(e) => warn!("new ptrace event added: {:?}", e),
                None => warn!("unrecognised ptrace event: {}", event),
            },
            WaitStatus::Stopped(pid, signal) => {
                info!("process {} stopped with signal {}", pid, signal)
            }
            s => warn!("unhandled signal: {:?}", s),
        };
    }

    Ok(())
}

fn match_event(v: i32) -> Option<Event> {
    match v {
        1 => Some(Event::PTRACE_EVENT_FORK),
        2 => Some(Event::PTRACE_EVENT_VFORK),
        3 => Some(Event::PTRACE_EVENT_CLONE),
        4 => Some(Event::PTRACE_EVENT_EXEC),
        5 => Some(Event::PTRACE_EVENT_VFORK_DONE),
        6 => Some(Event::PTRACE_EVENT_EXIT),
        7 => Some(Event::PTRACE_EVENT_SECCOMP),
        128 => Some(Event::PTRACE_EVENT_STOP),
        _ => None,
    }
}
