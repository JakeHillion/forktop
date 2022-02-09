use log::{error, info};

mod error;

use error::Error;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::Arc;

use async_std::sync::Mutex;
use async_std::task;

use nix::sys::ptrace::{self, Options};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use nix::unistd::{self, ForkResult};

struct ProcessDescription {
    parent: Option<Pid>,
    name: Option<String>,
}

enum ProcessState {
    Traced,
    Completed(u8),
}

fn main() -> Result<(), Error> {
    env_logger::init();

    info!("forking child process...");

    let child = unsafe {
        match nix::unistd::fork().map_err(|e| Error::Nix {
            msg: "fork",
            src: e,
        })? {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                let err = spawn_child();
                error!("error spawning child: {}", err);
                std::process::exit(1);
            }
        }
    };

    task::block_on(async_main(child))
}

async fn async_main(child: Pid) -> Result<(), Error> {
    let children = Arc::new(Mutex::new({
        let mut m = HashMap::new();
        m.insert(
            child,
            ProcessDescription {
                parent: None,
                name: Some("main".to_string()),
            },
        );
        m
    }));

    ptrace::setoptions(
        child,
        Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEEXIT
            | Options::PTRACE_O_TRACEVFORK,
    )
    .map_err(|e| Error::Nix {
        msg: "ptrace_setoptions",
        src: e,
    })?;

    while !children.lock().await.is_empty() {
        let wait_result = wait().map_err(|e| Error::Nix {
            msg: "wait",
            src: e,
        })?;

        match &wait_result {
            WaitStatus::Signaled(pid, Signal::SIGTRAP, _) => {
                ptrace::cont(*pid, None).map_err(|e| Error::Nix {
                    msg: "ptrace_cont",
                    src: e,
                })?;
            }
            _ => unimplemented!(),
        };
    }

    Ok(())
}

fn spawn_child() -> Error {
    fn int() -> Result<(), Error> {
        ptrace::traceme().map_err(|e| Error::Nix {
            msg: "traceme",
            src: e,
        })?;

        let sh = CString::new("/bin/sh").unwrap();

        unistd::execve::<_, &CStr>(&sh, vec![&sh].as_slice(), &[]).map_err(|e| Error::Nix {
            msg: "execve",
            src: e,
        })?;

        unreachable!()
    }

    int().expect_err("execve doesn't return on success")
}

async fn wait_loop(desc: &mut HashMap<Pid, ProcessDescription>) {}
