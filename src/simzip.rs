use std::collections::HashSet;
use crate::simzip::Location::Mem;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Compression {
    #[default]
    Store,
    Shrink,
    Reduction(u8) , //(This implies compression factors ranging from level 1 to level 4)
    Implode,
    Deflate,
    Deflat64,
    BZIP2,
    LZMA, 
    WavPack,
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
    pub compression: Compression,
    pub comment: Option<String>,
    entries: Vec<ZipEntry>,
}



impl ZipInfo {
    pub fn new(name: String) -> ZipInfo {
        ZipInfo {
            zip_name: name,
            compression: Compression::Store,
            comment: None,
            entries: vec![]
        }
    }
    
    pub fn add(&mut self, entry: ZipEntry) {
        self.entries.push(entry)
    }
    
    pub fn store(&self) -> Result<(), String> {
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