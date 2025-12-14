mod simzip;
mod crc32;
mod crctabl;
pub use simzip::{ZipInfo, ZipEntry, Attribute, Compression};
pub const VERSION: &str = env!("VERSION");
extern crate simtime;