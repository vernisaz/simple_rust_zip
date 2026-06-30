extern crate simcli;
extern crate simcolor;
use simcli::{CLI, OptTyp, OptVal};
use crate::simcolor::Colorized;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use std::ffi::OsStr;
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
    if cli.args().is_empty() || cli.get_opt("h").unwrap() == Some(&OptVal::Empty) {
        println!("Usage: tzip [opts] <file>");
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
        
        match path.extension().unwrap_or(OsStr::new("")).to_ascii_lowercase().to_str().unwrap_or("") {
            "tar" | "gz" | "xz" | "bz2" | "zip" | "7z" => println!("-> {}", path.to_string_lossy().red()),
            // Images
            "jpg" | "jpeg" | "bmp" | "gif" | "png" => println!("-> {}", path.to_string_lossy().yellow()),
            "html" | "htm" | "css" | "js" | "ico" => println!("-> {}", path.to_string_lossy().blue().bright()),
            // Default: no color for other extensions
            _ => println!("-> {}", path.to_string_lossy()),
        }
    }

    Ok(())
}
