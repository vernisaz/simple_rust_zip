extern crate libdeflater;
extern crate simcli;
extern crate simcolor;
extern crate simtime;
use crate::simcolor::Colorized;
use libdeflater::Decompressor;
#[cfg(target_os = "windows")]
use simcli::WildCardExpansion;
use simcli::{CLI, OPT_PREFIX, OptTyp, OptVal};
use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File, FileTimes};
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;
const MAX_NAME_LEN: usize = 1024;
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
        .opt("s", OptTyp::Num)?
        .alias("-max")?
        .description(&format!("Max size (in MB) of an extracted file. Should be specified with with {OPT_PREFIX}e. Default 32MB"))
        .opt("e", OptTyp::None)?
        .alias("-extract")?
        .description("Extract a file if its size is less than the max")
        .opt("w", OptTyp::None)?
        .alias("-overwrite")?
        .description("Overwrite existing files")
        .opt("o", OptTyp::Str)?
        .alias("-outdir")?
        .description("Output directory for extracted files")
        .opt("x", OptTyp::None)?
        .alias("-exclude")?
        .description("Provided content entry patterns are considered for exclusion from the extraction")
        .opt("m", OptTyp::None)?
        .description("Don't restore modification times");
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
        println!("Usage: zipdir [opts] <file> [<content_file>...]");
        println!("{}", cli.get_description().unwrap());
        return Ok(());
    }
    let mut zip_file = PathBuf::from(&cli.args()[0]);
    if zip_file.extension().is_none() {
        zip_file.set_extension("zip");
    }
    let zip_file = File::open(&zip_file)?;
    let arc = Archive::try_from(zip_file)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let extract = cli.get_opt("e").unwrap() == Some(&OptVal::Empty);
    let max = if let Some(OptVal::Num(max)) = cli.get_opt("s").unwrap()
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
    } else if let Ok(dest) = env::current_dir() {
        dest
    } else {
        return Err("No current directory".into());
    };
    let over = cli.get_opt("w").unwrap() == Some(&OptVal::Empty);
    let exclud = cli.get_opt("x").unwrap() == Some(&OptVal::Empty);
    let listing = cli.get_opt("l").unwrap() == Some(&OptVal::Empty) || !extract;
    let no_time_restore = cli.get_opt("m").unwrap() == Some(&OptVal::Empty);
    if listing {
        println!("  Length      Date    Time    Name");
        println!("---------  ---------- -----   ----");
    }
    let mut tot_size = 0;
    let mut tot_count = 0;
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
        let size = entry.uncompressed_size();
        let date = entry.date();
        let (day, month, year) = if date > 0 {
            (date & 0x1f, (date >> 5) & 0xf, ((date >> 9) & 0x7f) + 1980)
        } else {
            (0, 0, 0)
        };
        let time = entry.time();
        let (h, m, s) = if time > 0 {
            (time >> 11, (time >> 5) & 0x3f, (time & 0x1f) >> 1)
        } else {
            (0, 0, 0)
        };

        if listing {
            tot_count += 1;
            if dir {
                println!("{}{}", " ".repeat(30), path.to_string_lossy().magenta())
            } else {
                tot_size += size;
                print!("{:>9}  ", size);

                if date > 0 {
                    print!("{year:>4}-{month:>02}-{day:>02} ")
                } else {
                    print!("           ");
                }
                if time > 0 {
                    print!("{h:>2}:{m:>02}   ")
                } else {
                    print!("{}", " ".repeat(8));
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
        }
        if extract {
            if !cli.args()[1..].is_empty() {
                if cli.args()[1..]
                    .contains(&path.file_name().unwrap().to_str().unwrap().to_string())
                {
                    if exclud {
                        continue;
                    }
                } else if !exclud {
                    continue;
                }
            }
            let dest_dir = if let Some(parent) = path.parent() {
                dest.join(parent)
            } else {
                dest.clone()
            };
            if !dest_dir.exists() {
                fs::create_dir_all(dest_dir)?
            } else if !dest_dir.is_dir() {
                eprintln!("{dest_dir:?} is a file, entry {path:?} is skipped")
            }
            path = dest.join(path);
            if size < max.try_into().unwrap() {
                let Ok(mut writer) = File::options()
                    .truncate(over)
                    .write(true)
                    .create_new(!over)
                    .create(over)
                    .open(&path)
                else {
                    eprintln!(
                        "File {} can't be created.",
                        path.to_string_lossy().red().bold()
                    );
                    continue;
                };
                match entry.compression()? {
                    Compression::Deflated => {
                        let mut inbuf = Vec::new();
                        if let Ok(_comp_size) = entry.reader()?.read_to_end(&mut inbuf) {
                            let mut decompressor = Decompressor::new();
                            let mut outbuf = vec![0; size.try_into().unwrap()];
                            decompressor
                                .deflate_decompress(&inbuf, &mut outbuf)
                                .unwrap();
                            io::copy(&mut outbuf.as_slice(), &mut writer)?;
                        } else {
                            eprintln!("File {path:?} can't be read from the archive")
                        }
                    }
                    Compression::Stored => {
                        io::copy(&mut entry.reader()?, &mut writer)?;
                    }
                }
                // update timestamp
                if !no_time_restore && year > 0 {
                    let (timezone_offset_min, _dst) = simtime::get_local_timezone_offset_dst();
                    let upd_time = UNIX_EPOCH
                        + Duration::from_secs(
                            (simtime::seconds_from_epoch(
                                1970,
                                year as u32,
                                month as u32,
                                day as u32,
                                h as u32,
                                m as u32,
                                s as u32,
                            )
                            .unwrap() as i64
                                - (timezone_offset_min * 60) as i64)
                                as u64,
                        );
                    let times = FileTimes::new()
                        .set_accessed(upd_time)
                        .set_modified(upd_time);
                    // Apply the timestamps
                    writer.set_times(times)?;
                }
            } else {
                eprintln!("File {path:?} isn't extracted since the size is greater than allowed")
            }
        }
    }
    if listing {
        println!("---------                     -------");
        println!("{tot_size:>9}                     {tot_count} files");
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
