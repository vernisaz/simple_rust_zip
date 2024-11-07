use std::collections::HashSet;
use crate::simzip::Location::Mem;
use std::path::Path;
use std::fs::{self, File};
use std::io::{Write, Seek};
use std::time::{SystemTime};
use crate::crc32;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Compression {
    #[default]
    Store,
    Shrink,
    Reduction1,
    Reduction2,
    Reduction3,
    Reduction4,
    Implode,
    Deflate,
    Deflat64,
    BZIP2,
    LZMA, 
    PPMd ,
}

pub enum Location {
    Disk(Box<Path>),
    Mem(Vec<u8>),
}

pub enum Attribute {
    Exec,
    Write
}

pub struct ZipEntry {
    pub name: String,
    pub path: Option<String>,
    pub len: usize,
    pub attributes: HashSet<Attribute>,
    data: Location,
}

pub struct ZipInfo {
    pub zip_name: String,
    pub flags: u16,
    pub compression: Compression,
    pub comment: Option<String>,
    entries: Vec<ZipEntry>,
}

impl Compression {
    fn value(&self) -> u16 {
        match *self {
            Compression::Store => 0,
            Compression::Shrink => 1,
            Compression::Reduction1 => 2,
            Compression::Reduction2 => 3,
            Compression::Reduction3 => 4,
            Compression::Reduction4 => 5,
            Compression::Implode => 6,
            Compression::Deflate => 8,
            Compression::Deflat64 => 9,
            Compression::BZIP2 => 12,
            Compression::LZMA => 14, 
            Compression::PPMd => 98
        }
    }
}

// info: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
// https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html
impl ZipInfo {
    pub fn new(name: String) -> ZipInfo {
        ZipInfo {
            zip_name: name,
            flags: 0,
            compression: Compression::Store,
            comment: None,
            entries: vec![]
        }
    }
    
    pub fn add(&mut self, entry: ZipEntry) {
        self.entries.push(entry)
    }
    
    pub fn store(&self) -> Result<(), String> {
        // consider to create with zip_name.<8 random digits>  and rename to zip_name at the end
        let mut zip_file = File::create(&self.zip_name).map_err(|e| format!("{e}"))?;
        for entry in &self.entries {
            let mut len = zip_file.write(&(0x06054b50_u32 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
            assert_eq!(len, 4);
            len = zip_file.write(&0x14_u16.to_ne_bytes()).map_err(|e| format!("{e}"))?; // version 2.0
            assert_eq!(len, 2);
            len = zip_file.write(&self.flags.to_ne_bytes()).map_err(|e| format!("{e}"))?; // flags
            assert_eq!(len, 2);
            len = zip_file.write(&Compression::Store.value().to_ne_bytes()).map_err(|e| format!("{e}"))?; 
            assert_eq!(len, 2);
            
            let (y,m,d,h,min,s,_) = match &entry.data { 
                Location::Mem(mem) => time::get_datetime(1970, SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                Location::Disk(ref path) => time::get_datetime(1970, fs::metadata(&*path).map_err(|e| "no metadata".to_string())?.
                      modified().map_err(|e| "no modified".to_string())?.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                };
            let time: u16 = (s/2 + (min << 4) + (h << 11)).try_into().unwrap();
            len = zip_file.write(&time.to_ne_bytes()).map_err(|e| format!("{e}"))?;
            assert_eq!(len, 2);
            let date: u16 = (d + (m << 4) + ((y-1980) << 9)).try_into().unwrap();
            len = zip_file.write(&date.to_ne_bytes()).map_err(|e| format!("{e}"))?;
            assert_eq!(len, 2);
            let mut crc: u32 = crc32::update_slow(0xdebb20e3, &0_i32.to_ne_bytes());
            let crc_pos = zip_file.seek(std::io::SeekFrom::Current(0)).map_err(|e| format!("{e}"))?;
            len = zip_file.write(&crc.to_ne_bytes()).map_err(|e| format!("{e}"))?; 
            assert_eq!(len, 4);
            let mut size_compressed = 0_u64;
            len = zip_file.write(&(size_compressed as u32).to_ne_bytes()).map_err(|e| format!("{e}"))?; 
            assert_eq!(len, 4);
            let size = 0_u64;
            len = zip_file.write(&(size as u32).to_ne_bytes()).map_err(|e| format!("{e}"))?; 
            assert_eq!(len, 4);
            let name_bytes = entry.name.as_bytes();
            len = zip_file.write(&(name_bytes.len() as u16).to_ne_bytes()).map_err(|e| format!("{e}"))?;
            assert_eq!(len, 2);
            let extra_len = 0_u16;
            len = zip_file.write(&extra_len.to_ne_bytes()).map_err(|e| format!("{e}"))?;
            assert_eq!(len, 2);
            len = zip_file.write(&name_bytes).map_err(|e| format!("{e}"))?;
            assert_eq!(len, name_bytes.len());
            // writing content 
            match &entry.data {
                Location::Mem(mem) => {
                    len = zip_file.write(&mem).map_err(|e| format!("{e}"))?;
                    crc = crc32::update_slow(crc, &mem)
                }
                Location::Disk(_path) => {
                    
                }
            }
            // update crc 
            let current_pos = zip_file.seek(std::io::SeekFrom::Current(0)).map_err(|e| format!("{e}"))?;
            zip_file.seek(std::io::SeekFrom::Start(crc_pos)).map_err(|e| format!("{e}"))?;
            len = zip_file.write(&crc.to_ne_bytes()).map_err(|e| format!("{e}"))?; 
            assert_eq!(len, 4);
            zip_file.seek(std::io::SeekFrom::Start(current_pos)).map_err(|e| format!("{e}"))?;
        }
        Ok(())
    }
}

impl ZipEntry {
    pub fn new(name: String, data: Vec<u8>) -> ZipEntry {
        ZipEntry {
            name: name,
            path: None,
            len: 0,
            attributes: HashSet::new(),
            data: Mem(data)
        }
    }
}