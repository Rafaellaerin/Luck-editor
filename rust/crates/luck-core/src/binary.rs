use crate::error::{LuckError, Result};
use crate::model::{Cookie, CookieCollection, SameSite};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAGIC: &[u8; 8] = b"LUCKCK01";
const VERSION: u16 = 1;
const FLAG_SECURE: u16 = 1 << 0;
const FLAG_HTTP_ONLY: u16 = 1 << 1;
const FLAG_SESSION: u16 = 1 << 2;
const FLAG_HOST_ONLY: u16 = 1 << 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryLimits {
    pub maximum_bytes: usize,
    pub maximum_cookies: usize,
    pub maximum_string_bytes: usize,
    pub maximum_metadata_entries: usize,
}

impl Default for BinaryLimits {
    fn default() -> Self {
        Self {
            maximum_bytes: 16 * 1024 * 1024,
            maximum_cookies: 100_000,
            maximum_string_bytes: 2 * 1024 * 1024,
            maximum_metadata_entries: 1_024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryHeader {
    pub version: u16,
    pub cookie_count: u32,
    pub payload_bytes: u64,
    pub checksum: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryDecodeReport {
    pub header: BinaryHeader,
    pub collection: CookieCollection,
    pub trailing_bytes: usize,
}

pub fn encode_binary(collection: &CookieCollection) -> Result<Vec<u8>> {
    if collection.len() > u32::MAX as usize {
        return Err(LuckError::TooManyCookies { actual: collection.len(), limit: u32::MAX as usize });
    }
    let mut payload = Writer::default();
    for cookie in collection {
        encode_cookie(&mut payload, cookie)?;
    }
    let checksum = checksum64(&payload.bytes);
    let mut output = Writer::default();
    output.bytes.extend_from_slice(MAGIC);
    output.u16(VERSION);
    output.u16(0);
    output.u32(collection.len() as u32);
    output.u64(payload.bytes.len() as u64);
    output.u64(checksum);
    output.bytes.extend_from_slice(&payload.bytes);
    Ok(output.bytes)
}

pub fn decode_binary(input: &[u8], limits: &BinaryLimits) -> Result<BinaryDecodeReport> {
    if input.len() > limits.maximum_bytes {
        return Err(LuckError::InputTooLarge { actual: input.len(), limit: limits.maximum_bytes });
    }
    let mut reader = Reader::new(input);
    let magic = reader.take(MAGIC.len())?;
    if magic != MAGIC {
        return Err(LuckError::InvalidArgument("binary cookie file has invalid magic".into()));
    }
    let version = reader.u16()?;
    if version != VERSION {
        return Err(LuckError::InvalidArgument(format!("unsupported binary cookie version {version}")));
    }
    let reserved = reader.u16()?;
    if reserved != 0 {
        return Err(LuckError::InvalidArgument("binary cookie header reserved bits are non-zero".into()));
    }
    let count = reader.u32()? as usize;
    if count > limits.maximum_cookies {
        return Err(LuckError::TooManyCookies { actual: count, limit: limits.maximum_cookies });
    }
    let payload_bytes = usize::try_from(reader.u64()?)
        .map_err(|_| LuckError::InvalidArgument("payload length does not fit this platform".into()))?;
    let checksum = reader.u64()?;
    if payload_bytes > reader.remaining() {
        return Err(LuckError::InvalidArgument("binary payload length exceeds input".into()));
    }
    let payload = reader.take(payload_bytes)?;
    if checksum64(payload) != checksum {
        return Err(LuckError::Validation("binary payload checksum mismatch".into()));
    }
    let mut payload_reader = Reader::new(payload);
    let mut cookies = Vec::with_capacity(count);
    for _ in 0..count {
        cookies.push(decode_cookie(&mut payload_reader, limits)?);
    }
    if payload_reader.remaining() != 0 {
        return Err(LuckError::InvalidArgument(format!(
            "binary payload contains {} unconsumed bytes",
            payload_reader.remaining()
        )));
    }
    Ok(BinaryDecodeReport {
        header: BinaryHeader {
            version,
            cookie_count: count as u32,
            payload_bytes: payload_bytes as u64,
            checksum,
        },
        collection: CookieCollection::new(cookies),
        trailing_bytes: reader.remaining(),
    })
}

fn encode_cookie(writer: &mut Writer, cookie: &Cookie) -> Result<()> {
    writer.string(&cookie.name)?;
    writer.string(&cookie.value)?;
    writer.string(&cookie.domain)?;
    writer.string(&cookie.path)?;
    writer.string(cookie.store_id.as_deref().unwrap_or_default())?;
    writer.string(cookie.partition_site.as_deref().unwrap_or_default())?;
    let mut flags = 0u16;
    flags |= if cookie.secure { FLAG_SECURE } else { 0 };
    flags |= if cookie.http_only { FLAG_HTTP_ONLY } else { 0 };
    flags |= if cookie.session { FLAG_SESSION } else { 0 };
    flags |= if cookie.host_only { FLAG_HOST_ONLY } else { 0 };
    writer.u16(flags);
    writer.u8(match cookie.same_site {
        SameSite::Unspecified => 0,
        SameSite::None => 1,
        SameSite::Lax => 2,
        SameSite::Strict => 3,
    });
    match cookie.expiration_date {
        Some(value) => {
            writer.u8(1);
            writer.f64(value);
        }
        None => writer.u8(0),
    }
    if cookie.metadata.len() > u32::MAX as usize {
        return Err(LuckError::Serialization("too many metadata entries".into()));
    }
    writer.u32(cookie.metadata.len() as u32);
    for (key, value) in &cookie.metadata {
        writer.string(key)?;
        writer.string(value)?;
    }
    Ok(())
}

fn decode_cookie(reader: &mut Reader<'_>, limits: &BinaryLimits) -> Result<Cookie> {
    let name = reader.string(limits.maximum_string_bytes)?;
    let value = reader.string(limits.maximum_string_bytes)?;
    let domain = reader.string(limits.maximum_string_bytes)?;
    let path = reader.string(limits.maximum_string_bytes)?;
    let store_id = optional_string(reader.string(limits.maximum_string_bytes)?);
    let partition_site = optional_string(reader.string(limits.maximum_string_bytes)?);
    let flags = reader.u16()?;
    let same_site = match reader.u8()? {
        0 => SameSite::Unspecified,
        1 => SameSite::None,
        2 => SameSite::Lax,
        3 => SameSite::Strict,
        value => return Err(LuckError::InvalidArgument(format!("invalid SameSite tag {value}"))),
    };
    let expiration_date = match reader.u8()? {
        0 => None,
        1 => Some(reader.f64()?),
        value => return Err(LuckError::InvalidArgument(format!("invalid expiration tag {value}"))),
    };
    let metadata_count = reader.u32()? as usize;
    if metadata_count > limits.maximum_metadata_entries {
        return Err(LuckError::InvalidArgument(format!(
            "metadata entry count {metadata_count} exceeds limit {}",
            limits.maximum_metadata_entries
        )));
    }
    let mut metadata = BTreeMap::new();
    for _ in 0..metadata_count {
        let key = reader.string(limits.maximum_string_bytes)?;
        let value = reader.string(limits.maximum_string_bytes)?;
        if metadata.insert(key.clone(), value).is_some() {
            return Err(LuckError::InvalidArgument(format!("duplicate metadata key {key:?}")));
        }
    }
    Ok(Cookie {
        name,
        value,
        domain,
        path,
        secure: flags & FLAG_SECURE != 0,
        http_only: flags & FLAG_HTTP_ONLY != 0,
        same_site,
        expiration_date,
        session: flags & FLAG_SESSION != 0,
        host_only: flags & FLAG_HOST_ONLY != 0,
        store_id,
        partition_site,
        metadata,
    })
}

fn optional_string(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

#[derive(Debug, Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn f64(&mut self, value: f64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) -> Result<()> {
        if value.len() > u32::MAX as usize {
            return Err(LuckError::Serialization("string is too large for binary format".into()));
        }
        self.u32(value.len() as u32);
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

#[derive(Debug)]
struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| LuckError::InvalidArgument("binary position overflow".into()))?;
        if end > self.input.len() {
            return Err(LuckError::InvalidArgument(format!(
                "unexpected end of binary input at byte {}",
                self.position
            )));
        }
        let value = &self.input[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.take(2)?.try_into().expect("fixed slice length");
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("fixed slice length");
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("fixed slice length");
        Ok(u64::from_le_bytes(bytes))
    }

    fn f64(&mut self) -> Result<f64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("fixed slice length");
        Ok(f64::from_le_bytes(bytes))
    }

    fn string(&mut self, maximum: usize) -> Result<String> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(LuckError::InvalidArgument(format!("binary string length {length} exceeds limit {maximum}")));
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| LuckError::InvalidArgument("binary string is not valid UTF-8".into()))
    }
}

fn checksum64(input: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
