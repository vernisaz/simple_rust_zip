#[cfg(feature = "deflate")]
extern crate libdeflater;
use crate::crc32;
use crate::simzip::Location::Disk;
use crate::simzip::Location::Mem;
#[cfg(feature = "deflate")]
use libdeflater::{CompressionLvl, Compressor};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    cell::Cell,
    collections::HashSet,
    fs::{self, File},
    hash::{Hash, Hasher},
    io::{self, Error, Read, Seek, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
    PPMd,
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
    NoWrite,
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
    len: u32,       // compressed TODO change to usize or a custom type
    crc: Cell<u32>, // crc32
    offset: u32,    // the header offset in a zip
    modified: u64,  // in secs since epoch
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
            Compression::PPMd => 98,
        }
    }
}

// info: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
// https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html
impl ZipEntry {
    /// stores zip file on disk
    fn store(&mut self, mut zip_file: &File) -> io::Result<usize> {
        let mut res = 0_usize;
        // TODO impl zip64
        self.offset = zip_file.stream_position()? as u32;
        zip_file.write_all(&(0x504b0304_u32.to_be_bytes()))?;
        res += 4;
        zip_file.write_all(&VER_EXTRACT.to_ne_bytes())?; // version 2.0
        res += 2;
        // flags
        // set to 0x08 and then add a data descriptor after data 3x4 bytes
        zip_file.write_all(&0_u16.to_ne_bytes())?; // flags
        res += 2;
        zip_file.write_all(&self.compression.value().to_ne_bytes())?;
        res += 2;
        let (comm_len, crc_pos) = self.write_common(zip_file)?;
        res += comm_len;
        let combined_name = match &self.path {
            Some(path) => path.to_owned() + "/" + &self.name,
            None => self.name.clone(),
        };
        let name_bytes = combined_name.as_bytes();
        zip_file.write_all(&(name_bytes.len() as u16).to_ne_bytes())?;
        res += 2;
        #[cfg(any(unix, target_os = "redox"))]
        let mut time_headers = 0;
        #[cfg(any(unix, target_os = "redox"))]
        let mut mask = 0_u8;
        #[cfg(any(unix, target_os = "redox"))]
        // TODO improve by reading metadata only once
        let (atime, ctime, mtime) = match &self.data {
            Location::Mem(_) => {
                self.created = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                (0, self.created, 0)
            }
            Location::Disk(path) => {
                let metadata = fs::metadata(path)?;
                (
                    metadata.atime() as _,
                    metadata.ctime() as _,
                    metadata.mtime() as _,
                )
            }
        };
        #[cfg(any(unix, target_os = "redox"))]
        {
            if mtime > 0 {
                time_headers += 1;
                mask |= 0b0000_0001
            }
            if atime > 0 {
                time_headers += 1;
                mask |= 0b0000_0010
            }
            if ctime > 0 {
                time_headers += 1;
                mask |= 0b0000_0100
            }
        }
        #[cfg(any(unix, target_os = "redox"))]
        self.times_mask.set(mask);
        #[cfg(any(unix, target_os = "redox"))]
        let extra_len = (2 + 2 + 1 + time_headers * 4) as u16;
        #[cfg(target_os = "windows")]
        let extra_len = 0_u16;
        zip_file.write_all(&extra_len.to_ne_bytes())?; // extra fields
        res += 2;
        zip_file.write_all(name_bytes)?;
        res += name_bytes.len();
        // write extra headers here
        #[cfg(any(unix, target_os = "redox"))]
        {
            zip_file.write_all(&(0x5455_u16.to_ne_bytes()))?; // OS
            res += 2;

            zip_file.write_all(&(((1 + time_headers * 4) as u16).to_ne_bytes()))?; // OS
            res += 2;
            zip_file.write_all(&(mask.to_ne_bytes()))?; // OS
            res += 1;
            if mtime > 0 {
                zip_file.write_all(&(mtime as u32).to_ne_bytes())?; // OS
                res += 4;
            }
            if atime > 0 {
                zip_file.write_all(&(atime as u32).to_ne_bytes())?; // OS
                res += 4;
            }
            if ctime > 0 {
                zip_file.write_all(&(ctime as u32).to_ne_bytes())?; // OS
                res += 4;
            }
        }

        // writing content
        match &self.data {
            Location::Mem(mem) => {
                match self.compression {
                    Compression::Store => {
                        zip_file.write_all(mem)?;
                        self.len = mem.len() as u32;
                        self.crc = crc32::update_fast_16(0 /*u32::MAX*/, mem).into()
                    }
                    #[cfg(feature = "deflate")]
                    Compression::Deflate => {
                        let mut compressor = Compressor::new(CompressionLvl::default());
                        let max_sz = compressor.deflate_compress_bound(mem.len());
                        let mut compressed_data = Vec::new();
                        compressed_data.resize(max_sz, 0);
                        let actual_sz = compressor
                            .deflate_compress(&mem, &mut compressed_data)
                            .map_err(|e| Error::other(format!("because {e}")))?;
                        compressed_data.resize(actual_sz, 0);
                        zip_file.write_all(&compressed_data)?;
                        self.len = compressed_data.len() as u32;
                        self.crc = crc32::update_slow(0 /*u32::MAX*/, &mem).into()
                    }
                    _ => {
                        return Err(Error::other(
                            format! {"compression {:?} isn't supported yet", self.compression},
                        ))
                    }
                }
                res += self.len as usize;
            }
            Location::Disk(path) => {
                // TODO consider a streaming way
                let mut f = File::open(&**path)?;
                let mut mem = vec![];
                f.read_to_end(&mut mem)?;
                match self.compression {
                    Compression::Store => {
                        zip_file.write_all(&mem)?;
                        self.len = mem.len() as u32;
                        self.crc = crc32::update_slow(0 /*u32::MAX*/, &mem).into()
                    }
                    #[cfg(feature = "deflate")]
                    Compression::Deflate => {
                        let mut compressor = Compressor::new(CompressionLvl::default());
                        let max_sz = compressor.deflate_compress_bound(mem.len());
                        let mut compressed_data = Vec::new();
                        compressed_data.resize(max_sz, 0);
                        let actual_sz = compressor
                            .deflate_compress(&mem, &mut compressed_data)
                            .map_err(|e| Error::other(format!("because {e}")))?;
                        compressed_data.resize(actual_sz, 0);
                        zip_file.write_all(&compressed_data)?;
                        self.len = compressed_data.len() as u32;
                        self.crc = crc32::update_slow(0 /*u32::MAX*/, &mem).into()
                    }
                    _ => {
                        return Err(Error::other(
                            format! {"compression {:?} isn't supported yet", self.compression},
                        ))
                    }
                }
                res += self.len as usize;
            }
        }
        // update crc , save current pos
        let current_pos = zip_file.stream_position()?;

        zip_file.seek(std::io::SeekFrom::Start(crc_pos))?;
        zip_file.write_all(&self.crc.get().to_ne_bytes())?;
        zip_file.write_all(&self.len.to_ne_bytes())?; // compressed len

        zip_file.seek(std::io::SeekFrom::Start(current_pos))?;
        Ok(res)
    }

    fn store_dir(&mut self, mut zip_file: &File) -> io::Result<u32> {
        let mut res = 0_usize;
        zip_file.write_all(&(0x02014b50_u32.to_ne_bytes()))?;
        res += 4;
        zip_file.write_all(&(0x033F_u16.to_ne_bytes()))?; // OS
        res += 2;
        zip_file.write_all(&VER_EXTRACT.to_ne_bytes())?; // version 2.0
        res += 2;
        zip_file.write_all(&0_u16.to_ne_bytes())?; //
        res += 2;
        zip_file.write_all(&self.compression.value().to_ne_bytes())?;
        res += 2;
        res += self.write_common(zip_file)?.0;
        // TODO reuse previous calculation
        let combined_name = match &self.path {
            Some(path) => path.to_owned() + "/" + &self.name,
            None => self.name.clone(),
        };
        let name_bytes = combined_name.as_bytes();
        zip_file.write_all(&(name_bytes.len() as u16).to_ne_bytes())?;
        res += 2;
        #[cfg(target_os = "windows")]
        let extra_len = 0_u16; // no extra len
        #[cfg(any(unix, target_os = "redox"))]
        let mut extra_len = 0_u16;
        #[cfg(any(unix, target_os = "redox"))]
        if self.gid != 0 || self.uid != 0 {
            // ("ux")
            extra_len += 4 + 1 + 1 + 2 + 1 + 2
        }
        #[cfg(any(unix, target_os = "redox"))]
        if self.modified != 0 || self.created != 0 {
            // ("UT")
            extra_len += 9
        }
        // https://libzip.org/specifications/extrafld.txt
        zip_file.write_all(&extra_len.to_ne_bytes())?; // extra fields
        res += 2;

        let comment = match &self.comment {
            Some(comment) => comment.clone(),
            None => "".to_string(),
        };
        let comment_bytes = comment.as_bytes();
        zip_file.write_all(&(comment_bytes.len() as u16).to_ne_bytes())?; // extra fields
        res += 2;
        let disk_no = 0_u16;
        zip_file.write_all(&disk_no.to_ne_bytes())?; // extra fields
        res += 2;
        let intern_attr = 0_u16;
        zip_file.write_all(&intern_attr.to_ne_bytes())?; // extra fields
        res += 2;
        let mut ext_attr = 0x81000000_u32;
        let mut perm = 0o266_u8;
        if self.attributes.contains(&Attribute::NoWrite) {
            perm &= 0o155;
        }
        if self.attributes.contains(&Attribute::Exec) {
            perm |= 0o111;
        }
        ext_attr |= (perm as u32) << 16;
        zip_file.write_all(&ext_attr.to_ne_bytes())?; // extra fields
        res += 4;
        // no calculation based on multi disks
        zip_file.write_all(&self.offset.to_ne_bytes())?; // extra fields
        res += 4;
        zip_file.write_all(name_bytes)?;
        res += name_bytes.len();
        //  writing extra headers
        if extra_len > 0 {
            #[cfg(any(unix, target_os = "redox"))]
            if self.gid != 0 || self.uid != 0 {
                // ("ux")
                zip_file.write_all(&0x7875_u16.to_ne_bytes())?; // uid/gid
                res += 2;
                extra_len -= 2;
                zip_file.write_all(&((1 + 1 + 2 + 1 + 2) as u16).to_ne_bytes())?; // len
                res += 2;
                extra_len -= 2;
                zip_file.write_all(&1_u8.to_ne_bytes())?; // ver
                res += 1;
                extra_len -= 1;
                zip_file.write_all(&2_u8.to_ne_bytes())?; // size
                res += 1;
                extra_len -= 1;
                zip_file.write_all(&(self.uid as u16).to_ne_bytes())?; // uid
                res += 2;
                extra_len -= 2;
                zip_file.write_all(&2_u8.to_ne_bytes())?; // size
                res += 1;
                extra_len -= 1;
                zip_file.write_all(&(self.gid as u16).to_ne_bytes())?; // gid
                res += 2;
                extra_len -= 2;
            }
            #[cfg(any(unix, target_os = "redox"))]
            if extra_len > 0 && (self.modified > 0 || self.created > 0) {
                // ("UT")
                // this header appeared if 5455 (UT) present in the file header
                zip_file.write_all(&0x5455_u16.to_ne_bytes())?; // len
                res += 2;
                extra_len -= 2;
                zip_file.write_all(&5_u16.to_ne_bytes())?; // len
                res += 2;
                extra_len -= 2;
                // the below mask has to be in sync with the local header mask
                zip_file.write_all(&self.times_mask.get().to_ne_bytes())?; // atime, ctime & mtime
                res += 1;
                extra_len -= 1;
                zip_file.write_all(
                    &((if self.modified > 0 {
                        self.modified
                    } else {
                        self.created
                    }) as u32)
                        .to_ne_bytes(),
                )?; // len
                res += 4;
                extra_len -= 4;
            }
            if extra_len > 0 {
                return Err(Error::other(
                    format! {"not correct extra headers len calculation, {extra_len} extra"},
                ));
            }
        }
        // comment
        if !comment_bytes.is_empty() {
            zip_file.write_all(comment_bytes)?;
            res += comment_bytes.len();
        }
        Ok(res as u32)
    }

    fn write_common(&mut self, mut zip_file: &File) -> io::Result<(usize, u64)> {
        let mut res = 0_usize;
        let (y, m, d, h, min, s, _) = match &self.data {
            Location::Mem(_) => {
                let current = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default();
                self.modified = current.as_secs() as _;
                simtime::get_datetime(1970, self.modified)
            }
            Location::Disk(path) => {
                let metadata = fs::metadata(path)?;
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
                    self.created = metadata
                        .created()?
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_err(|e| Error::other(format!("because {e}")))?
                        .as_secs() as _;
                }
                let timestamp = metadata
                    .modified()?
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|e| Error::other(format!("because {e}")))?;
                self.modified = timestamp.as_secs();
                simtime::get_datetime(1970, self.modified)
            }
        };
        let time: u16 = (s / 2 + (min << 4) + (h << 11))
            .try_into()
            .map_err(|e| Error::other(format!("because {e}")))?;
        zip_file.write_all(&time.to_ne_bytes())?;
        res += 2;
        let date: u16 = (d + (m << 5) + ((y - 1980) << 9))
            .try_into()
            .map_err(|e| Error::other(format!("because {e}")))?;
        zip_file.write_all(&date.to_ne_bytes())?;
        res += 2;
        let crc_pos = zip_file.stream_position()?;
        zip_file.write_all(&(self.crc.get().to_ne_bytes()))?;
        res += 4;
        // preserve the position to update size after finishing data
        let size_orig = match &self.data {
            Location::Mem(mem) => mem.len() as _,
            Location::Disk(path) => fs::metadata(path)?.len(),
        };
        zip_file.write_all(&(self.len).to_le_bytes())?;
        res += 4;
        zip_file.write_all(&(size_orig as u32).to_le_bytes())?;
        res += 4;

        Ok((res, crc_pos))
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
                    path: entry.path.to_owned(),
                };
                if dir.insert(dir_entry) {
                    self.entries.push(entry);
                    true
                } else {
                    false
                }
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
        let offset_central_dir = zip_file.stream_position()?;
        for entry in &mut self.entries {
            len_central += entry.store_dir(&zip_file)?;
        }

        // add - end of central directory record
        zip_file.write_all(&(0x06054b50_u32.to_ne_bytes()))?;
        // disk
        zip_file.write_all(&(0_u16.to_ne_bytes()))?;
        // disk # the dir starts
        zip_file.write_all(&(0_u16.to_ne_bytes()))?;
        // entries # this disk
        zip_file.write_all(&(self.entries.len() as u16).to_ne_bytes())?;
        // entries # all
        zip_file.write_all(&(self.entries.len() as u16).to_ne_bytes())?;
        // len central
        zip_file.write_all(&(len_central.to_ne_bytes()))?;
        // offset central
        zip_file.write_all(&((offset_central_dir as u32).to_ne_bytes()))?;
        let comment_bytes = if let Some(comment) = &self.comment {
            comment.as_bytes()
        } else {
            &[]
        };
        zip_file.write_all(&((comment_bytes.len() as u16).to_ne_bytes()))?;
        if !comment_bytes.is_empty() {
            zip_file.write_all(comment_bytes)?;
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
            data: Mem(data),
            ..Default::default()
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P, zip_path: Option<impl AsRef<str>>) -> ZipEntry {
        let path = path.as_ref();
        ZipEntry {
            name: path.file_name().unwrap().display().to_string(), // TODO handle the situation when no file name
            path: zip_path.map(|s| s.as_ref().into()),
            attributes: HashSet::new(),
            data: Disk(path.into()),
            ..Default::default()
        }
    }

    pub fn created_on(mut self, time: SystemTime) -> Self {
        self.modified = time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self
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
