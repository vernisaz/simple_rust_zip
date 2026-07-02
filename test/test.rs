extern crate libdeflater;
extern crate simcli;
extern crate simcolor;
use crate::simcolor::Colorized;
use libdeflater::Decompressor;
#[cfg(target_os = "windows")]
use simcli::WildCardExpansion;
use simcli::{CLI, OptTyp, OptVal};
use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::io::Read;
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
        .description("Show the archive directory")
        .opt("m", OptTyp::Num)?
        .alias("-max")?
        .description("Max size (in meg) of an extracted file. Should be specified with with -e. Default 32MB.")
        .opt("e", OptTyp::None)?
        .alias("-extract")?
        .description("Extract file if its size is less the max.")
        .opt("w", OptTyp::None)?
        .alias("-overwrite")?
        .description("Overwrite existing files.")
        .opt("o", OptTyp::Str)?
        .alias("-outdir")?
        .description("Output directory for extracted files.")
        .opt("x", OptTyp::None)?
        .alias("-exclude")?
        .description("Provided content entry patterns are considered for exclusion from extraction.");
    #[cfg(target_os = "windows")]
    cli.process_wildcard(WildCardExpansion::Once);
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
    let extract = cli.get_opt("e").unwrap() == Some(&OptVal::Empty);
    let max = if let Some(OptVal::Num(max)) = cli.get_opt("m").unwrap()
        && *max > 1
    {
        (*max as usize) * 1024 * 1024
    } else {
        32_000_000usize
    };
    let dest = if let Some(OptVal::Str(dest)) = cli.get_opt("o").unwrap() {
        if let dest = PathBuf::from(dest)
            && dest.exists()
            && dest.is_dir()
        {
            dest
        } else {
            return Err("Destination path doesn't exist or invalid".into());
        }
    } else {
        if let Ok(dest) = env::current_dir() {
            dest
        } else {
            return Err("No current directory".into());
        }
    };
    let over = cli.get_opt("w").unwrap() == Some(&OptVal::Empty);
    let exclud = cli.get_opt("x").unwrap() == Some(&OptVal::Empty);
    for entry in arc.entries() {
        let entry = entry?;
        let path = entry.read_path(&mut scratch)?;
        let path = if entry.path_is_utf8() {
            String::from_utf8(path.to_vec())?
        } else {
            String::from_utf8_lossy(path).to_string()
        };
        let dir = path.ends_with("/");
        let mut path = PathBuf::from(path);
        if dir {
            println!("{}", path.to_string_lossy().magenta())
        } else {
            match path
                .extension()
                .unwrap_or(OsStr::new(""))
                .to_ascii_lowercase()
                .to_str()
                .unwrap_or("")
            {
                "tar" | "gz" | "xz" | "bz2" | "zip" | "7z" => {
                    print!("{}", path.to_string_lossy().red())
                }
                // Images
                "jpg" | "jpeg" | "bmp" | "gif" | "png" => {
                    print!("{}", path.to_string_lossy().yellow())
                }
                "html" | "htm" | "css" | "js" | "ico" => {
                    print!("{}", path.to_string_lossy().blue().bright())
                }
                "7b" | "sh" | "rb" | "bat" => {
                    print!("{}", path.to_string_lossy().gray(12))
                }
                "doc" | "md" | "txt" | "docx" | "pdf" => {
                    print!("{}", path.to_string_lossy().green())
                }
                // Default: no color for other extensions
                _ => print!("{}", path.to_string_lossy()),
            }
            println!(" {}", entry.uncompressed_size());
            if extract {
                if !cli.args()[1..].is_empty() {
                    if cli.args()[1..]
                        .contains(&path.file_name().unwrap().to_str().unwrap().to_string())
                    {
                        if exclud {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                let size = entry.uncompressed_size();
                if size < max.try_into().unwrap() {
                    let mut writer = File::options()
                        .truncate(over)
                        .write(true)
                        .create_new(!over)
                        .create(over)
                        .open(&path)?;
                    match entry.compression()? {
                        Compression::Deflated => {
                            let mut inbuf = Vec::new();
                            if let Ok(_comp_size) = entry.reader()?.read_to_end(&mut inbuf) {
                                let mut decompressor = Decompressor::new();
                                let mut outbuf = vec![0; size.try_into().unwrap()];
                                decompressor
                                    .deflate_decompress(&inbuf, &mut outbuf)
                                    .unwrap();
                                path = path.join(&dest);
                                let parent = path.parent().unwrap();
                                if !parent.exists() {
                                    fs::create_dir_all(parent)?
                                }
                                io::copy(&mut outbuf.as_slice(), &mut writer)?;
                            } else {
                                eprintln!("File {path:?} can't be read from the archive")
                            }
                        }
                        Compression::Stored => {
                            io::copy(&mut entry.reader()?, &mut writer)?;
                        }
                    }
                } else {
                    eprintln!("File {path:?} isn't extracted since the big size")
                }
            }
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
