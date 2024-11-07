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
    pub len: usize, // compressed
    pub attributes: HashSet<Attribute>,
    pub compression: Compression,
    data: Location, // includes len uncompressed (original)
}

pub struct ZipInfo {
    pub zip_name: String,
    
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
impl ZipEntry {
    fn store(&self, mut zip_file: &File) -> Result<usize, String> {
        let mut res = 0_usize;
        let mut len = zip_file.write(&(0x06054b50_u32 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&0x14_u16.to_ne_bytes()).map_err(|e| format!("{e}"))?; // version 2.0
        assert_eq!(len, 2);
        res += len;
        // flags
        len = zip_file.write(&0_u16.to_ne_bytes()).map_err(|e| format!("{e}"))?; // flags
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&Compression::Store.value().to_ne_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 2);
        res += len;
        let (y,m,d,h,min,s,_) = match &self.data { 
            Location::Mem(mem) => time::get_datetime(1970, SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
            Location::Disk(ref path) => time::get_datetime(1970, fs::metadata(&*path).map_err(|e| "no metadata".to_string())?.
                  modified().map_err(|e| "no modified".to_string())?.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
            };
        let time: u16 = (s/2 + (min << 4) + (h << 11)).try_into().unwrap();
        len = zip_file.write(&time.to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        let date: u16 = (d + (m << 4) + ((y-1980) << 9)).try_into().unwrap();
        len = zip_file.write(&date.to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        let mut crc: u32 = crc32::update_slow(0xdebb20e3, &0_i32.to_ne_bytes());
        let crc_pos = zip_file.seek(std::io::SeekFrom::Current(0)).map_err(|e| format!("{e}"))?;
        len = zip_file.write(&crc.to_ne_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 4);
        res += len;
        // preserve the position to update size after finishing data
        let mut size_compressed = match &self.data { 
            Location::Mem(mem) => mem.len() as u64,
            Location::Disk(ref path) => fs::metadata(&*path).map_err(|e| "no metadata".to_string())?.
                  len()
        };
        len = zip_file.write(&(size_compressed as u32).to_ne_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 4);
        res += len;
        let size = size_compressed;
        len = zip_file.write(&(size as u32).to_ne_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 4);
        res += len;
        let name_bytes = self.name.as_bytes();
        len = zip_file.write(&(name_bytes.len() as u16).to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        let extra_len = 0_u16;
        len = zip_file.write(&extra_len.to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&name_bytes).map_err(|e| format!("{e}"))?;
        assert_eq!(len, name_bytes.len());
        res += len;
        // writing content 
        match &self.data {
            Location::Mem(mem) => {
                len = zip_file.write(&mem).map_err(|e| format!("{e}"))?;
                assert_eq!(len, size_compressed as usize);
                res += len;
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
        res += len;
        zip_file.seek(std::io::SeekFrom::Start(current_pos)).map_err(|e| format!("{e}"))?;
        Ok(res)
    }
    
    fn store_dir(&self, mut zip_file: &File) -> Result<u64, String> {
        let mut len = zip_file.write(&(0x02014b50_u32 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        Ok(0)
    }
}

impl ZipInfo {
    pub fn new(name: String) -> ZipInfo {
        ZipInfo {
            zip_name: name,
            comment: None,
            entries: vec![]
        }
    }
    
    pub fn add(&mut self, entry: ZipEntry) {
        self.entries.push(entry)
    }
    
    pub fn store(&self) -> Result<(), String> {
        // consider to create with zip_name.<8 random digits>  and rename to zip_name at the end
        // use : little-endian byte order
        let mut zip_file = File::create(&self.zip_name).map_err(|e| format!("{e}"))?;
        
        for entry in &self.entries {
            entry.store(&zip_file)?;
        }
        for entry in &self.entries {
            entry.store_dir(&zip_file)?;
        }
        let mut len_central = 0_u32;
        // add - end of central directory record
        let mut len = zip_file.write(&(0x06054b50_u32 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        // disk
        len = zip_file.write(&(0_u16 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        //
        len = zip_file.write(&(0_u16 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        // entries # this disk
        len = zip_file.write(&(self.entries.len() as u16) .to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        // entries # all
        len = zip_file.write(&(self.entries.len() as u16) .to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        // len central
        len= zip_file.write(&(len_central .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        // offset central
        len = zip_file.write(&(0_u32 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        let comment_bytes = if let Some(comment) = &self.comment {
           comment.as_bytes() } else { &[] };
        len = zip_file.write(&(comment_bytes.len() .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        if comment_bytes.len() > 0 {
            len = zip_file.write(&comment_bytes).map_err(|e| format!("{e}"))?;
            assert_eq!(len, comment_bytes.len())
        }
        Ok(())
    }
}

impl ZipEntry {
    pub fn new(name: String, data: Vec<u8>) -> ZipEntry {
        ZipEntry {
            name: name,
            path: None,
            compression: Default::default(),
            len: 0,
            attributes: HashSet::new(),
            data: Mem(data)
        }
    }
}