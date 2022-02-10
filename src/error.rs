use async_std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{msg}: {src}")]
    Nix { msg: &'static str, src: nix::Error },

    #[error("io: {0}")]
    Io(#[from] io::Error),
}
