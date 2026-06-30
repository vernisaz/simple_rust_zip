extern crate simcli;
extern crate simcolor;
use crate::simcolor::Colorized;
use simcli::{CLI, OptTyp, OptVal};
use std::error::Error;
use std::ffi::OsStr;
use std::fs::File;
use std::path::PathBuf;
use tzip::{Archive, Compression};
fn main() -> Result<(), Box<dyn Error>> {
    let mut cli = CLI::new();
    cli.description("Where opts are:")
        .opt("v", OptTyp::None)?
        .description("Version of the product")
        .opt("h", OptTyp::None)?
        .description("This help screen")
        .opt("l", OptTyp::None)?
        .alias("-list")?
        .description("Show the archive directory");
    if cli.get_opt("v").unwrap() == Some(&OptVal::Empty) {
        println!(
            "Zipdir version {} © {} D. Rogatkin",
            env!("VERSION"),
            year_now()
        );
        return Ok(());
    }
    if cli.args().is_empty() || cli.get_opt("h").unwrap() == Some(&OptVal::Empty) {
        println!("Usage: zipdir [opts] <file>");
        println!("{}", cli.get_description().unwrap());
        return Ok(());
    }
    let zip_file = File::open(&cli.args()[0])?;
    let arc = Archive::try_from(zip_file)?;
    let mut scratch = [0u8; 1024];
    for entry in arc.entries() {
        let entry = entry?;
        let path = entry.read_path(&mut scratch)?;
        let path = PathBuf::from(String::from_utf8_lossy(path).to_string());
        if !entry.path_is_utf8() {
            print!("!")
        }
        match path
            .extension()
            .unwrap_or(OsStr::new(""))
            .to_ascii_lowercase()
            .to_str()
            .unwrap_or("")
        {
            "tar" | "gz" | "xz" | "bz2" | "zip" | "7z" => {
                println!("{}", path.to_string_lossy().red())
            }
            // Images
            "jpg" | "jpeg" | "bmp" | "gif" | "png" => {
                println!("{}", path.to_string_lossy().yellow())
            }
            "html" | "htm" | "css" | "js" | "ico" => {
                println!("{}", path.to_string_lossy().blue().bright())
            }
            "7b" | "sh" | "rb" | "bat" => {
                println!("{}", path.to_string_lossy().gray(12))
            }
            "doc" | "md" | "txt" | "docx" | "pdf" => {
                println!("{}", path.to_string_lossy().green())
            }
            // Default: no color for other extensions
            _ => println!("{}", path.to_string_lossy()),
        }
    }

    Ok(())
}

use std::time::{SystemTime, UNIX_EPOCH};
#[inline]
pub fn year_now() -> u64 {
    // TODO -> small crate
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 31556952
        + 1970
}
