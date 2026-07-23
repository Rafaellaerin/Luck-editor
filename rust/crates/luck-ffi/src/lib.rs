use luck_core::{parse_cookies, serialize_cookies, OutputFormat, ParseOptions, SerializeOptions};
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuckStatus {
    Ok = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    ParseError = 3,
    SerializationError = 4,
    Panic = 255,
}

#[repr(C)]
#[derive(Debug)]
pub struct LuckBuffer {
    pub data: *mut c_char,
    pub length: usize,
    pub status: LuckStatus,
}

impl LuckBuffer {
    fn empty(status: LuckStatus) -> Self {
        Self { data: ptr::null_mut(), length: 0, status }
    }

    fn from_string(value: String, status: LuckStatus) -> Self {
        match CString::new(value) {
            Ok(value) => {
                let length = value.as_bytes().len();
                Self { data: value.into_raw(), length, status }
            }
            Err(_) => Self::empty(LuckStatus::SerializationError),
        }
    }
}

#[no_mangle]
pub extern "C" fn luck_version() -> *const c_char {
    static VERSION: &[u8] = b"5.0.0\0";
    VERSION.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn luck_parse_json(input: *const c_char, fallback_domain: *const c_char) -> LuckBuffer {
    ffi_guard(|| {
        let input = read_string(input)?;
        let fallback_domain = read_optional_string(fallback_domain)?;
        let report = parse_cookies(
            &input,
            &ParseOptions { fallback_domain, ..ParseOptions::default() },
        )
        .map_err(|error| (LuckStatus::ParseError, error.to_string()))?;
        serde_json::to_string(&report)
            .map(|json| LuckBuffer::from_string(json, LuckStatus::Ok))
            .map_err(|error| (LuckStatus::SerializationError, error.to_string()))
    })
}

#[no_mangle]
pub extern "C" fn luck_convert_redacted_json(input: *const c_char, fallback_domain: *const c_char) -> LuckBuffer {
    ffi_guard(|| {
        let input = read_string(input)?;
        let fallback_domain = read_optional_string(fallback_domain)?;
        let report = parse_cookies(
            &input,
            &ParseOptions { fallback_domain: fallback_domain.clone(), ..ParseOptions::default() },
        )
        .map_err(|error| (LuckStatus::ParseError, error.to_string()))?;
        let output = serialize_cookies(
            &report.cookies,
            &SerializeOptions {
                format: OutputFormat::RedactedJson,
                hostname: fallback_domain,
                include_http_only: true,
                ..SerializeOptions::default()
            },
        )
        .map_err(|error| (LuckStatus::SerializationError, error.to_string()))?;
        Ok(LuckBuffer::from_string(output, LuckStatus::Ok))
    })
}

#[no_mangle]
pub extern "C" fn luck_buffer_free(buffer: LuckBuffer) {
    if buffer.data.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(buffer.data));
    }
}

fn ffi_guard<F>(operation: F) -> LuckBuffer
where
    F: FnOnce() -> Result<LuckBuffer, (LuckStatus, String)>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(buffer)) => buffer,
        Ok(Err((status, message))) => LuckBuffer::from_string(message, status),
        Err(_) => LuckBuffer::from_string("unexpected Rust panic".into(), LuckStatus::Panic),
    }
}

fn read_string(pointer: *const c_char) -> Result<String, (LuckStatus, String)> {
    if pointer.is_null() {
        return Err((LuckStatus::NullPointer, "input pointer is null".into()));
    }
    let value = unsafe { CStr::from_ptr(pointer) };
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|_| (LuckStatus::InvalidUtf8, "input is not valid UTF-8".into()))
}

fn read_optional_string(pointer: *const c_char) -> Result<String, (LuckStatus, String)> {
    if pointer.is_null() {
        Ok(String::new())
    } else {
        read_string(pointer)
    }
}
