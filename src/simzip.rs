use std::collections::HashSet;
use crate::simzip::Location::Mem;
use std::path::Path;
use std::fs::{self, File};
use std::io::{Write, Seek, Read};
use std::time::{SystemTime};
use crate::crc32;
use crate::simzip::Location::Disk;

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

#[derive(Debug)]
pub enum Location {
    Disk(String),
    Mem(Vec<u8>),
}

impl Default for Location {
    fn default() -> Location {
        Location::Mem(vec![])
    }
}

#[derive(Debug)]
pub enum Attribute {
    Exec,
    Write
}

#[derive(Debug, Default)]
pub struct ZipEntry {
    pub name: String,
    pub path: Option<String>,
    len: u32, // compressed
    crc: u32, // crc32
    offset: u32, // a header offset in zip
    pub attributes: HashSet<Attribute>,
    pub compression: Compression,
    data: Location, // includes len uncompressed (original)
}

pub struct ZipInfo {
    pub zip_name: String,
    
    pub comment: Option<String>,
    entries: Vec<ZipEntry>,
}

static VER_EXTRACT: u16 = 0x14;

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
    fn store(&mut self, mut zip_file: &File) -> Result<usize, String> {
        let mut res = 0_usize;
        // TODO impl zip64
        self.offset = zip_file.seek(std::io::SeekFrom::Current(0)).map_err(|e| format!("{e}"))? as u32;
        let mut len = zip_file.write(&(0x504b0304_u32 .to_be_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&VER_EXTRACT.to_ne_bytes()).map_err(|e| format!("{e}"))?; // version 2.0
        assert_eq!(len, 2);
        res += len;
        // flags
        // set to 0x08 and then add data descriptor after data 3x4 bytes
        len = zip_file.write(&0_u16.to_ne_bytes()).map_err(|e| format!("{e}"))?; // flags
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&self.compression.value().to_ne_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 2);
        res += len;
        let (comm_len,crc_pos) = self.write_common(&zip_file)?;
        len = comm_len;
        res += len;
        let combined_name = match &self.path {
            Some(path) => path.to_owned() + "/" + &self.name,
            None => self.name.clone()
        };
        let name_bytes = combined_name.as_bytes();
        len = zip_file.write(&(name_bytes.len() as u16).to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        let extra_len = 0_u16;
        len = zip_file.write(&extra_len.to_ne_bytes()).map_err(|e| format!("{e}"))?; // extra fields
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&name_bytes).map_err(|e| format!("{e}"))?;
        assert_eq!(len, name_bytes.len());
        res += len;
        
        // writing content 
        match &self.data {
            Location::Mem(mem) => {
                len = zip_file.write(&mem).map_err(|e| format!("{e}"))?;
                // compressed len
                self.len = len as u32;
                assert_eq!(len, self.len as usize);
                res += len;
                self.crc = crc32::update_slow(0/*u32::MAX*/, &mem)
            }
            Location::Disk(path) => {
            // TODO consider a streaming way
                let mut f = File::open(&**path).map_err(|e| format!("{e}"))?;
                let mut mem = vec![];
                  f.read_to_end(&mut mem).map_err(|e| format!("{e}"))?;
                len = zip_file.write(&mem).map_err(|e| format!("{e}"))?;
                self.len = len as u32;
                assert_eq!(len, self.len as usize);
                res += len;
                self.crc = crc32::update_slow(0/*u32::MAX*/, &mem)
            }
        }
        // update crc , save current pos
        let current_pos = zip_file.seek(std::io::SeekFrom::Current(0)).map_err(|e| format!("{e}"))?;
        
        zip_file.seek(std::io::SeekFrom::Start(crc_pos)).map_err(|e| format!("{e}"))?;
        len = zip_file.write(&self.crc.to_ne_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 4);
        len = zip_file.write(&self.len.to_ne_bytes()).map_err(|e| format!("{e}"))?; // compressed len
        assert_eq!(len, 4);
        
        zip_file.seek(std::io::SeekFrom::Start(current_pos)).map_err(|e| format!("{e}"))?;
        Ok(res)
    }
    
    fn store_dir(&self, mut zip_file: &File) -> Result<u32, String> {
        let mut res = 0_usize;
        let mut len = zip_file.write(&(0x02014b50_u32 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&(0x0300_u16 .to_ne_bytes())).map_err(|e| format!("{e}"))?; // OS
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&VER_EXTRACT.to_ne_bytes()).map_err(|e| format!("{e}"))?; // version 2.0
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&0_u16.to_ne_bytes()).map_err(|e| format!("{e}"))?; // 
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&self.compression.value().to_ne_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 2);
        res += len;
        res += self.write_common(zip_file)?.0;
        // TODO reuse previous calculation
        let combined_name = match &self.path {
            Some(path) => path.to_owned() + "/" + &self.name,
            None => self.name.clone()
        };
        let name_bytes = combined_name.as_bytes();
        len = zip_file.write(&(name_bytes.len() as u16).to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        let extra_len = 0_u16;
        len = zip_file.write(&extra_len.to_ne_bytes()).map_err(|e| format!("{e}"))?; // extra fields
        assert_eq!(len, 2);
        res += len;
        let comment_len = 0_u16;
        len = zip_file.write(&comment_len.to_ne_bytes()).map_err(|e| format!("{e}"))?; // extra fields
        assert_eq!(len, 2);
        res += len;
        let disk_no = 0_u16;
        len = zip_file.write(&disk_no.to_ne_bytes()).map_err(|e| format!("{e}"))?; // extra fields
        assert_eq!(len, 2);
        res += len;
        let intern_attr = 0_u16;
        len = zip_file.write(&intern_attr.to_ne_bytes()).map_err(|e| format!("{e}"))?; // extra fields
        assert_eq!(len, 2);
        res += len;
        let ext_attr = 0_u32;
        len = zip_file.write(&ext_attr.to_ne_bytes()).map_err(|e| format!("{e}"))?; // extra fields
        assert_eq!(len, 4);
        res += len;
        // no calculation based on multi disks
        len = zip_file.write(&self.offset.to_ne_bytes()).map_err(|e| format!("{e}"))?; // extra fields
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&name_bytes).map_err(|e| format!("{e}"))?;
        assert_eq!(len, name_bytes.len());
        res += len;
        // probably write extra here
        
        Ok(res as u32)
    }
    
    fn write_common(&self, mut zip_file: &File) -> Result<(usize, u64), String> {
        let mut res = 0_usize;
        let (y,m,d,h,min,s,_) = match &self.data { 
            Location::Mem(_) => time::get_datetime(1970, SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
            Location::Disk(ref path) => time::get_datetime(1970, fs::metadata(&*path).map_err(|e| format!{"no metadata {e}"})?.
                  modified().map_err(|e| format!{"no modified {e}"})?.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
            };
        let time: u16 = (s/2 + (min << 4) + (h << 11)).try_into().unwrap();
        let mut len = zip_file.write(&time.to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        let date: u16 = (d + (m << 5) + ((y-1980) << 9)).try_into().unwrap();
        len = zip_file.write(&date.to_ne_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        res += len;
        let crc_pos = zip_file.seek(std::io::SeekFrom::Current(0)).map_err(|e| format!("{e}"))?;
        len = zip_file.write(&(self.crc.to_ne_bytes())).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 4);
        res += len;
        // preserve the position to update size after finishing data
        let size_orig = match &self.data { 
            Location::Mem(mem) => mem.len() as u64,
            Location::Disk(ref path) => fs::metadata(&*path).map_err(|e| format!{"no metadata {e}"})?.
                  len()
        };
        len = zip_file.write(&(self.len as u32).to_le_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&(size_orig as u32).to_le_bytes()).map_err(|e| format!("{e}"))?; 
        assert_eq!(len, 4);
        res += len;
        
        
        Ok((res,crc_pos))
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
    
    pub fn new_with_comment(name: String, comment: String) -> ZipInfo {
        ZipInfo {
            zip_name: name,
            comment: Some(comment),
            entries: vec![]
        }
    }
    
    pub fn add(&mut self, entry: ZipEntry) {
        self.entries.push(entry)
    }
    
    pub fn store(&mut self) -> Result<(), String> {
        // consider to create with zip_name.<8 random digits>  and rename to zip_name at the end
        // use : little-endian byte order
        let mut zip_file = File::create(&self.zip_name).map_err(|e| format!("{e}"))?;
        
        for entry in &mut self.entries {
            entry.store(&zip_file)?;
        }
        let mut len_central = 0_u32;
        let offset_central_dir = zip_file.seek(std::io::SeekFrom::Current(0)).map_err(|e| format!("{e}"))?;
        for entry in &self.entries {
            len_central += entry.store_dir(&zip_file)?;
        }
        
        // add - end of central directory record
        let mut len = zip_file.write(&(0x06054b50_u32 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        // disk
        len = zip_file.write(&(0_u16 .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 2);
        // disk # the dir starts
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
        len = zip_file.write(&((offset_central_dir as u32) .to_ne_bytes())).map_err(|e| format!("{e}"))?;
        assert_eq!(len, 4);
        let comment_bytes = if let Some(comment) = &self.comment {
           comment.as_bytes() } else { &[] };
        len = zip_file.write(&((comment_bytes.len() as u16).to_ne_bytes())).map_err(|e| format!("{e}"))?;
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
            attributes: HashSet::new(),
            data: Mem(data), ..Default::default()
        }
    }
    
    pub fn from_file(path: &String, zip_path: Option<&String>) -> ZipEntry {
        let p = Path::new(path);
        ZipEntry {
            name: p.file_name().unwrap().to_str().unwrap().to_string(),
            path: zip_path.cloned(),
            attributes: HashSet::new(),
            data: Disk(path.to_owned()), ..Default::default()
        }
    }
}