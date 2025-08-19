#[cfg(feature = "deflate")]
extern crate libdeflater;
#[cfg(feature = "deflate")]
use libdeflater::{Compressor, CompressionLvl};
use std::{collections::HashSet,
path::{Path,PathBuf},
fs::{self, File},
io::{self, Write, Seek, Read, Error, ErrorKind},
time::{SystemTime},
hash::{Hash, Hasher},
cell::Cell,
};
use crate::simzip::Location::Mem;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt,MetadataExt};
use crate::crc32;
use crate::simzip::Location::Disk;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Compression {
    #[cfg_attr(not(feature = "deflate"), default)]
    Store,
    Shrink,
    Reduction1,
    Reduction2,
    Reduction3,
    Reduction4,
    Implode,
    #[cfg_attr(feature = "deflate", default)]
    Deflate,
    Deflat64,
    BZIP2,
    LZMA, 
    PPMd ,
}

#[derive(Debug)]
pub enum Location {
    Disk(PathBuf),
    Mem(Vec<u8>),
}

impl Default for Location {
    fn default() -> Location {
        Location::Mem(vec![])
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Attribute {
    Exec,
    NoWrite
}

#[derive(PartialEq, Eq, Hash)]
struct DirEntry {
    name: String,
    path: Option<String>,
}

#[derive(Debug, Default)]
pub struct ZipEntry {
    pub name: String,
    pub path: Option<String>,
    pub comment: Option<String>,
    pub attributes: HashSet<Attribute>,
    pub compression: Compression,
    data: Location, // includes len uncompressed (original)
    len: u32, // compressed
    crc: Cell<u32>, // crc32
    offset: u32, // the header offset in a zip
    modified: u64, // in secs since epoch
    #[cfg(any(unix, target_os = "redox"))]
    uid: u32,
    #[cfg(any(unix, target_os = "redox"))]
    gid: u32,
    #[cfg(any(unix, target_os = "redox"))]
    created: u64,
    #[cfg(any(unix, target_os = "redox"))]
    times_mask: Cell<u8>, // times field mask
    // #[cfg(target_os = "windows")]
}

#[derive(Default)]
pub struct ZipInfo {
    pub zip_name: PathBuf,
    directory: Option<HashSet<DirEntry>>,
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
    fn store(&mut self, mut zip_file: &File) -> io::Result<usize> {
        let mut res = 0_usize;
        // TODO impl zip64
        self.offset = zip_file.seek(std::io::SeekFrom::Current(0))? as u32;
        let mut len = zip_file.write(&(0x504b0304_u32 .to_be_bytes()))?;
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&VER_EXTRACT.to_ne_bytes())?; // version 2.0
        assert_eq!(len, 2);
        res += len;
        // flags
        // set to 0x08 and then add a data descriptor after data 3x4 bytes
        len = zip_file.write(&0_u16.to_ne_bytes())?; // flags
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&self.compression.value().to_ne_bytes())?; 
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
        len = zip_file.write(&(name_bytes.len() as u16).to_ne_bytes())?;
        assert_eq!(len, 2);
        res += len;
        #[cfg(any(unix, target_os = "redox"))]
        let mut time_headers = 0;
        #[cfg(any(unix, target_os = "redox"))]
        let mut mask = 0_u8;
        #[cfg(any(unix, target_os = "redox"))]
         // TODO improve by reading metadata only once
        let (atime,ctime,mtime) = match &self.data { 
            Location::Mem(_) => {
                self.created = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
                (0, self.created, 0)
            }
            Location::Disk(path) => {
                let metadata = fs::metadata(&*path)?;
                (metadata.atime() as _,metadata.ctime() as _,metadata.mtime() as _)
            }
        };
        #[cfg(any(unix, target_os = "redox"))]
        {
            if mtime >  0 {
                time_headers += 1;
                mask |= 0b0000_0001
            }
            if atime >  0 {
                time_headers += 1;
                mask |= 0b0000_0010
            }
            if ctime >  0 {
                time_headers += 1;
                mask |= 0b0000_0100
            }
        }
        #[cfg(any(unix, target_os = "redox"))]
        self.times_mask.set(mask);
        #[cfg(any(unix, target_os = "redox"))]
        let extra_len = (2 + 2 + 1 + time_headers*4) as u16;
        #[cfg(target_os = "windows")] 
        let extra_len = 0_u16;
        len = zip_file.write(&extra_len.to_ne_bytes())?; // extra fields
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&name_bytes)?;
        assert_eq!(len, name_bytes.len());
        res += len;
        // write extra headers here
        #[cfg(any(unix, target_os = "redox"))]
        {
            len = zip_file.write(&(0x5455_u16 .to_ne_bytes()))?; // OS
            assert_eq!(len, 2);
            res += len;

            len = zip_file.write(&(((1+time_headers*4) as u16) .to_ne_bytes()))?; // OS
            assert_eq!(len, 2);
            res += len;
            len = zip_file.write(&(mask .to_ne_bytes()))?; // OS
            assert_eq!(len, 1);
            res += len;
            if mtime > 0 {
                len = zip_file.write(&(mtime as u32) .to_ne_bytes())?; // OS
                assert_eq!(len, 4);
                res += len;
            }
            if atime > 0 {
                len = zip_file.write(&(atime as u32) .to_ne_bytes())?; // OS
                assert_eq!(len, 4);
                res += len;
            }
            if ctime > 0 {
                len = zip_file.write(&(ctime as u32) .to_ne_bytes())?; // OS
                assert_eq!(len, 4);
                res += len;
            }
        }
        
        // writing content 
        match &self.data {
            Location::Mem(mem) => {
                match self.compression {
                    Compression::Store => {
                        len = zip_file.write(&mem)?;
                        assert_eq!(len, mem.len());
                        self.crc = crc32::update_fast_16(0/*u32::MAX*/, &mem).into()
                    }
                    #[cfg(feature = "deflate")]
                    Compression::Deflate => {
                        let mut compressor = Compressor::new(CompressionLvl::default());
                        let max_sz = compressor.deflate_compress_bound(mem.len());
                        let mut compressed_data = Vec::new();
                        compressed_data.resize(max_sz, 0);
                        let actual_sz = compressor.deflate_compress(&mem, &mut compressed_data).unwrap();
                        compressed_data.resize(actual_sz, 0);
                        len = zip_file.write(&compressed_data)?;
                        assert_eq!(len, compressed_data.len()); 
                        self.crc = crc32::update_slow(0/*u32::MAX*/, &mem).into()
                    }
                    _ => return Err(Error::new(ErrorKind::Other, format!{"compression {:?} isn't supported yet", self.compression}))
                }
                // compressed len
                self.len = len as u32;
                res += len;
            }
            Location::Disk(path) => {
            // TODO consider a streaming way
                let mut f = File::open(&**path)?;
                let mut mem = vec![];
                f.read_to_end(&mut mem)?;
                match self.compression {
                    Compression::Store => {
                          len = zip_file.write(&mem)?;
                          assert_eq!(len, mem.len());
                          self.crc = crc32::update_slow(0/*u32::MAX*/, &mem).into()  
                    }
                    #[cfg(feature = "deflate")]
                    Compression::Deflate => {
                        let mut compressor = Compressor::new(CompressionLvl::default());
                        let max_sz = compressor.deflate_compress_bound(mem.len());
                        let mut compressed_data = Vec::new();
                        compressed_data.resize(max_sz, 0);
                        let actual_sz = compressor.deflate_compress(&mem, &mut compressed_data).unwrap();
                        compressed_data.resize(actual_sz, 0);
                        len = zip_file.write(&compressed_data)?;
                        assert_eq!(len, compressed_data.len());
                        self.crc = crc32::update_slow(0/*u32::MAX*/, &mem).into()
                    }
                    _ => return Err(Error::new(ErrorKind::Other, format!{"compression {:?} isn't supported yet", self.compression}))
                }
                self.len = len as u32;
                res += len;
            }
        }
        // update crc , save current pos
        let current_pos = zip_file.seek(std::io::SeekFrom::Current(0))?;
        
        zip_file.seek(std::io::SeekFrom::Start(crc_pos))?;
        len = zip_file.write(&self.crc.get().to_ne_bytes())?; 
        assert_eq!(len, 4);
        len = zip_file.write(&self.len.to_ne_bytes())?; // compressed len
        assert_eq!(len, 4);
        
        zip_file.seek(std::io::SeekFrom::Start(current_pos))?;
        Ok(res)
    }
    
    fn store_dir(&mut self, mut zip_file: &File) -> io::Result<u32> {
        let mut res = 0_usize;
        let mut len = zip_file.write(&(0x02014b50_u32 .to_ne_bytes()))?;
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&(0x033F_u16 .to_ne_bytes()))?; // OS
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&VER_EXTRACT.to_ne_bytes())?; // version 2.0
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&0_u16.to_ne_bytes())?; // 
        assert_eq!(len, 2);
        res += len;
        len = zip_file.write(&self.compression.value().to_ne_bytes())?; 
        assert_eq!(len, 2);
        res += len;
        res += self.write_common(zip_file)?.0;
        // TODO reuse previous calculation
        let combined_name = match &self.path {
            Some(path) => path.to_owned() + "/" + &self.name,
            None => self.name.clone()
        };
        let name_bytes = combined_name.as_bytes();
        len = zip_file.write(&(name_bytes.len() as u16).to_ne_bytes())?;
        assert_eq!(len, 2);
        res += len;
        #[cfg(target_os = "windows")]
        let extra_len = 0_u16; // no extra len
        #[cfg(any(unix, target_os = "redox"))]
        let mut extra_len = 0_u16; 
        #[cfg(any(unix, target_os = "redox"))]
        if  self.gid != 0 || self.uid != 0 { // ("ux")
            extra_len += 4 + 1 + 1 + 2 + 1 + 2
        }
        #[cfg(any(unix, target_os = "redox"))]
        if  self.modified != 0 || self.created != 0 { // ("UT")
            extra_len += 9
        }
        // https://libzip.org/specifications/extrafld.txt
        len = zip_file.write(&extra_len.to_ne_bytes())?; // extra fields
        assert_eq!(len, 2);
        res += len;
        
        let comment = match &self.comment {
            Some(comment) => {comment.clone()},
            None => "".to_string()
        };
        let comment_bytes = comment.as_bytes();
        len = zip_file.write(&(comment_bytes.len() as u16).to_ne_bytes())?; // extra fields
        assert_eq!(len, 2);
        res += len;
        let disk_no = 0_u16;
        len = zip_file.write(&disk_no.to_ne_bytes())?; // extra fields
        assert_eq!(len, 2);
        res += len;
        let intern_attr = 0_u16;
        len = zip_file.write(&intern_attr.to_ne_bytes())?; // extra fields
        assert_eq!(len, 2);
        res += len;
        let mut ext_attr = 0x81000000_u32;
        let mut perm = 0o266_u8;
        if self.attributes.contains(&Attribute::NoWrite) {
            perm &= 0o155;
        }
        if self.attributes.contains(&Attribute::Exec) {
            perm |= 0o111;
        }
        ext_attr |= (perm as u32) << 16;
        len = zip_file.write(&ext_attr.to_ne_bytes())?; // extra fields
        assert_eq!(len, 4);
        res += len;
        // no calculation based on multi disks
        len = zip_file.write(&self.offset.to_ne_bytes())?; // extra fields
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&name_bytes)?;
        assert_eq!(len, name_bytes.len());
        res += len;
        //  writing extra headers
        if extra_len > 0 {
            #[cfg(any(unix, target_os = "redox"))]
            if  self.gid != 0 || self.uid != 0 { // ("ux")
                len = zip_file.write(&0x7875_u16.to_ne_bytes())?; // uid/gid
                assert_eq!(len, 2);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&((1 + 1 + 2 + 1 + 2) as u16).to_ne_bytes())?; // len
                assert_eq!(len, 2);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&1_u8.to_ne_bytes())?; // ver
                assert_eq!(len, 1);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&2_u8.to_ne_bytes())?; // size
                assert_eq!(len, 1);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&(self.uid as u16).to_ne_bytes())?; // uid
                assert_eq!(len, 2);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&2_u8.to_ne_bytes())?; // size
                assert_eq!(len, 1);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&(self.gid as u16).to_ne_bytes())?; // gid
                assert_eq!(len, 2);
                res += len;
                extra_len -= len as u16;
            }
            #[cfg(any(unix, target_os = "redox"))]
            if extra_len > 0 && (self.modified > 0 || self.created > 0) { // ("UT")
                // this header appeared if 5455 (UT) present in the file header
                len = zip_file.write(&0x5455_u16.to_ne_bytes())?; // len
                assert_eq!(len, 2);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&5_u16.to_ne_bytes())?; // len
                assert_eq!(len, 2);
                res += len;
                extra_len -= len as u16;
                // the below mask has to be in sync with the local header mask
                len = zip_file.write(&self.times_mask.get().to_ne_bytes())?; // atime, ctime & mtime
                assert_eq!(len, 1);
                res += len;
                extra_len -= len as u16;
                len = zip_file.write(&((if self.modified > 0 {self.modified} else {self.created}) as u32).to_ne_bytes())?; // len
                assert_eq!(len, 4);
                res += len;
                extra_len -= len as u16;
            }
            if extra_len > 0 {
                return Err(Error::new(ErrorKind::Other, format!{"not correct extra headers len calculation, {extra_len} extra"}))
            }
        }
        // comment
        if comment_bytes.len() > 0 {
           len = zip_file.write(&comment_bytes)?;
            assert_eq!(len, comment_bytes.len());
            res += len; 
        }
        Ok(res as u32)
    }
    
    fn write_common(&mut self, mut zip_file: &File) -> io::Result<(usize, u64)> {
        let mut res = 0_usize;
        let (y,m,d,h,min,s,_) = match &self.data { 
            Location::Mem(_) => {
                let current = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                self.modified = current.as_secs() as _;
                simtime::get_datetime(1970, self.modified)
            }
            Location::Disk(path) => {
                let metadata = fs::metadata(&*path)?;
                if metadata.permissions().readonly() {
                    self.attributes.insert(Attribute::NoWrite);
                }
                #[cfg(unix)]
                if metadata.permissions().mode() & 0o111 != 0 {
                    self.attributes.insert(Attribute::Exec);
                }
                #[cfg(unix)]
                {
                self.uid = metadata.uid();
                self.gid = metadata.gid();
                self.created = metadata.
                  created()? .duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as _;
                }
                let timestamp = metadata.
                  modified()? .duration_since(SystemTime::UNIX_EPOCH).unwrap();
                self.modified =  timestamp.as_secs();
                simtime::get_datetime(1970, self.modified)
            }
        };
        let time: u16 = (s/2 + (min << 4) + (h << 11)).try_into().unwrap();
        let mut len = zip_file.write(&time.to_ne_bytes())?;
        assert_eq!(len, 2);
        res += len;
        let date: u16 = (d + (m << 5) + ((y-1980) << 9)).try_into().unwrap();
        len = zip_file.write(&date.to_ne_bytes())?;
        assert_eq!(len, 2);
        res += len;
        let crc_pos = zip_file.seek(std::io::SeekFrom::Current(0))?;
        len = zip_file.write(&(self.crc.get().to_ne_bytes()))?; 
        assert_eq!(len, 4);
        res += len;
        // preserve the position to update size after finishing data
        let size_orig = match &self.data { 
            Location::Mem(mem) => mem.len() as _,
            Location::Disk(path) => fs::metadata(&*path)?.
                  len()
        };
        len = zip_file.write(&(self.len as u32).to_le_bytes())?; 
        assert_eq!(len, 4);
        res += len;
        len = zip_file.write(&(size_orig as u32).to_le_bytes())?; 
        assert_eq!(len, 4);
        res += len;
        
        
        Ok((res,crc_pos))
    }
}

impl ZipInfo {
    pub fn new<P: AsRef<Path>>(name: P) -> ZipInfo {
        ZipInfo {
            zip_name: name.as_ref().into(),
            comment: None,
            ..Default::default()
        }
    }
    
    pub fn new_with_comment<P: AsRef<Path>>(name: P, comment: &str) -> ZipInfo {
        ZipInfo {
            zip_name: name.as_ref().into(),
            comment: Some(comment.to_string()),
            ..Default::default()
        }
    }
    
    pub fn prohibit_duplicates(&mut self) {
        self.directory = Some(HashSet::new())
    }
    
    pub fn add(&mut self, entry: ZipEntry) -> bool {
        match &mut self.directory {
            None => {
                self.entries.push(entry);
                true
            }
            Some(dir) => {
                let dir_entry = DirEntry {
                    name: entry.name.to_owned(),
                    path: entry.path.to_owned()
                };
                if dir.insert(dir_entry) {
                    self.entries.push(entry);
                    true
                } else {false}
            }
        }
    }
    
    pub fn store(&mut self) -> io::Result<()> {
        // consider to create with zip_name.<8 random digits>  and rename to zip_name at the end
        // use : little-endian byte order
        let mut zip_file = File::create(&self.zip_name)?;
        
        for entry in &mut self.entries {
            entry.store(&zip_file)?;
        }
        let mut len_central = 0_u32;
        let offset_central_dir = zip_file.seek(std::io::SeekFrom::Current(0))?;
        for entry in &mut self.entries {
            len_central += entry.store_dir(&zip_file)?;
        }
        
        // add - end of central directory record
        let mut len = zip_file.write(&(0x06054b50_u32 .to_ne_bytes()))?;
        assert_eq!(len, 4);
        // disk
        len = zip_file.write(&(0_u16 .to_ne_bytes()))?;
        assert_eq!(len, 2);
        // disk # the dir starts
        len = zip_file.write(&(0_u16 .to_ne_bytes()))?;
        assert_eq!(len, 2);
        // entries # this disk
        len = zip_file.write(&(self.entries.len() as u16) .to_ne_bytes())?;
        assert_eq!(len, 2);
        // entries # all
        len = zip_file.write(&(self.entries.len() as u16) .to_ne_bytes())?;
        assert_eq!(len, 2);
        // len central
        len= zip_file.write(&(len_central .to_ne_bytes()))?;
        assert_eq!(len, 4);
        // offset central
        len = zip_file.write(&((offset_central_dir as u32) .to_ne_bytes()))?;
        assert_eq!(len, 4);
        let comment_bytes = if let Some(comment) = &self.comment {
           comment.as_bytes() } else { &[] };
        len = zip_file.write(&((comment_bytes.len() as u16).to_ne_bytes()))?;
        assert_eq!(len, 2);
        if comment_bytes.len() > 0 {
            len = zip_file.write(&comment_bytes)?;
            assert_eq!(len, comment_bytes.len())
        }
        Ok(())
    }
}

impl ZipEntry {
    pub fn new(name: impl AsRef<str>, data: Vec<u8>) -> ZipEntry {
        ZipEntry {
            name: name.as_ref().into(),
            path: None,
            attributes: HashSet::new(),
            data: Mem(data), ..Default::default()
        }
    }
    
    pub fn from_file<P: AsRef<Path>>(path: P, zip_path: Option<impl AsRef<str>>) -> ZipEntry {
        let path = path.as_ref();
        ZipEntry {
            name: path.file_name().unwrap().to_str().unwrap().to_string(),
            path: zip_path.map(|s| s.as_ref().into()),
            attributes: HashSet::new(),
            data: Disk(path.into()), ..Default::default()
        }
    }
}

impl PartialEq for ZipEntry {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.path == other.path
    }
}

impl Eq for ZipEntry {}


impl Hash for ZipEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.path.hash(state);
    }
}


