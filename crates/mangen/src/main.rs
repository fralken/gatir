//! `gatir-mangen DIRECTORY` writes the manual pages of gatir into DIRECTORY.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(directory) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: gatir-mangen DIRECTORY");
        return ExitCode::from(2);
    };
    let written = gatir_mangen::pages().and_then(|pages| {
        std::fs::create_dir_all(&directory)?;
        for (name, text) in &pages {
            std::fs::write(directory.join(name), text)?;
        }
        Ok(pages.len())
    });
    match written {
        Ok(count) => {
            println!("{count} pages in {}", directory.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("cannot write the manual pages: {err}");
            ExitCode::FAILURE
        }
    }
}
