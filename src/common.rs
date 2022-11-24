//! Common library features

use std::{
    collections::HashMap,
    error::Error as StdError,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    process,
};

#[cfg(target_os = "linux")]
use {
    crate::str_util::str_to_int_metric,
    std::{
        fs::File,
        io::{BufRead, BufReader},
    },
};

#[cfg(target_os = "windows")]
use {
    std::mem::size_of,
    winapi::um::{
        handleapi::CloseHandle,
        processthreadsapi::OpenProcess,
        psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        shared::minwindef::DWORD,
        winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

// Copyright 2020 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
// except in compliance with the License.  You may obtain a copy of the License at
//     https://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.  See the License for the specific language governing permissions
// and limitations under the License.

/// The buffer size for a numeric string expression.
pub const NUM_BUFFER_SIZE: i32 = 32;

/// The maximum memory size.
pub const MAX_MEMORY_SIZE: i64 = 1 << 40;

// The size of a memory page on the OS.
pub const PAGE_SIZE: i32 = 4096;

/// The string expression of the package version.
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The string expression of the library version.
pub const LIBRARY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// True if the OS is conforming to POSIX.
#[cfg(target_os = "windows")]
pub const IS_POSIX: bool = false;

/// True if the OS is conforming to POSIX.
#[cfg(not(target_os = "windows"))]
pub const IS_POSIX: bool = true;

/** True if the byte order is big endian. */
#[cfg(target_endian = "big")]
pub const IS_BIG_ENDIAN: bool = true;

#[cfg(not(target_endian = "big"))]
pub const IS_BIG_ENDIAN: bool = false;

fn default_timeval() -> libc::timeval {
    libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    }
}

fn timeval_to_str(tv: &libc::timeval) -> String {
    format!("{:.6}", tv.tv_sec as f64 + tv.tv_usec as f64 / 1_000_000.0)
}

fn default_rusage() -> libc::rusage {
    libc::rusage {
        ru_utime: default_timeval(),
        ru_stime: default_timeval(),
        ru_maxrss: 0,
        ru_ixrss: 0,
        ru_idrss: 0,
        ru_isrss: 0,
        ru_minflt: 0,
        ru_majflt: 0,
        ru_nswap: 0,
        ru_inblock: 0,
        ru_oublock: 0,
        ru_msgsnd: 0,
        ru_msgrcv: 0,
        ru_nsignals: 0,
        ru_nvcsw: 0,
        ru_nivcsw: 0,
    }
}

/// Gets system information of the environment.
///
/// # Returns
/// A map of labels and their values.
pub fn get_system_info() -> HashMap<String, String> {
    let mut info = HashMap::new();
    let pid = process::id();
    info.insert("proc_id".into(), pid.to_string());

    #[cfg(not(target_os = "windows"))]
    {
        let mut usage = default_rusage();
        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };

        if result == 0 {
            info.insert("ru_utime".into(), timeval_to_str(&usage.ru_utime));
            info.insert("ru_stime".into(), timeval_to_str(&usage.ru_stime));

            if usage.ru_maxrss > 0 {
                let max_rss = usage.ru_maxrss * 1024;
                info.insert("mem_peak".into(), max_rss.to_string());
                info.insert("mem_size".into(), max_rss.to_string());
                info.insert("mem_rss".into(), max_rss.to_string());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(fd) = File::open("/proc/self/status") {
            let mut reader = BufReader::new(fd);
            let lines = reader.lines();

            while let Some(Ok(line)) = lines.next() {
                let parts: Vec<&str> = line.splitn(':', 2).collect();
                if parts.len() == 2 {
                    let size = str_to_int_metric(parts[1].trim());
                    let key = parts[0].trim();

                    match key {
                        "VmPeak" => info.insert("mem_peak".into(), size.to_string()),
                        "VmSize" => info.insert("mem_size".into(), size.to_string()),
                        "VmRSS" => info.insert("mem_rss".into(), size.to_string()),
                        _ => (),
                    };
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    unsafe {
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if !proc_handle.is_null() {
            let mut pmc = PROCESS_MEMORY_COUNTERS {
                cb: size_of::<PROCESS_MEMORY_COUNTERS>() as DWORD,
                PageFaultCount: 0,
                PeakWorkingSetSize: 0,
                WorkingSetSize: 0,
                QuotaPeakPagedPoolUsage: 0,
                QuotaPagedPoolUsage: 0,
                QuotaPeakNonPagedPoolUsage: 0,
                QuotaNonPagedPoolUsage: 0,
                PagefileUsage: 0,
                PeakPagefileUsage: 0,
            };

            if GetProcessMemoryInfo(proc_handle, &mut pmc, size_of::<PROCESS_MEMORY_COUNTERS>() as DWORD) == 0 {
                info["mem_peak".into()] = pmc.PeakWorkingSetSize.to_string();
                info["mem_size".into()] = pmc.QuotaPagedPoolUsage.to_string();
                info["mem_rss".into()] = pmc.WorkingSetSize.to_string();
            }

            CloseHandle(proc_handle);
        }
    }

    info
}

/// Gets the memory capacity of the platform.
///
/// # Returns
/// The memory capacity of the platform in bytes, or None on failure.
pub fn get_memory_capacity() -> Option<u64> {
    let records = get_system_info();
    if let Some(mem_size) = records.get("mem_total") {
        match mem_size.parse() {
            Ok(size) => Some(size),
            Err(_) => None,
        }
    } else {
        None
    }
}

/// Gets the current memory usage of the process.
///
/// # Returns
/// The current memory usage of the process in bytes, or None on failure.
pub fn get_memory_usage() -> Option<u64> {
    let records = get_system_info();
    if let Some(mem_size) = records.get("mem_rss") {
        match mem_size.parse() {
            Ok(size) => Some(size),
            Err(_) => None,
        }
    } else {
        None
    }
}

/// Status of operations.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /** Generic error whose cause is unknown. */
    UnknownError = 1,

    /** Generic error from underlying systems. */
    SystemError = 2,

    /** Error that the feature is not implemented. */
    NotImplementedError = 3,

    /** Error that a precondition is not met. */
    PreconditionError = 4,

    /** Error that a given argument is invalid. */
    InvalidArgumentError = 5,

    /** Error that the operation is canceled. */
    CanceledError = 6,

    /** Error that a specific resource is not found. */
    NotFoundError = 7,

    /** Error that the operation is not permitted. */
    PermissionError = 8,

    /** Error that the operation is infeasible. */
    InfeasibleError = 9,

    /** Error that a specific resource is duplicated. */
    DuplicationError = 10,

    /** Error that internal data are broken. */
    BrokenDataError = 11,

    /** Error caused by networking failure. */
    NetworkError = 12,

    /** Generic error caused by the application logic. */
    ApplicationError = 13,
}

impl Debug for ErrorCode {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::UnknownError => f.write_str("UNKNOWN_ERROR"),
            Self::SystemError => f.write_str("SYSTEM_ERROR"),
            Self::NotImplementedError => f.write_str("NOT_IMPLEMENTED_ERROR"),
            Self::PreconditionError => f.write_str("PRECONDITION_ERROR"),
            Self::InvalidArgumentError => f.write_str("INVALID_ARGUMENT_ERROR"),
            Self::CanceledError => f.write_str("CANCELED_ERROR"),
            Self::NotFoundError => f.write_str("NOT_FOUND_ERROR"),
            Self::PermissionError => f.write_str("PERMISSION_ERROR"),
            Self::InfeasibleError => f.write_str("INFEASIBLE_ERROR"),
            Self::DuplicationError => f.write_str("DUPLICATION_ERROR"),
            Self::BrokenDataError => f.write_str("BROKEN_DATA_ERROR"),
            Self::NetworkError => f.write_str("NETWORK_ERROR"),
            Self::ApplicationError => f.write_str("APPLICATION_ERROR"),
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug)]
pub struct Error {
    code: ErrorCode,
    message: Option<String>,
}

impl Error {
    /// Constructor representing a specific error.
    ///
    /// # Arguments
    /// * `code`: The error code.
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: None,
        }
    }

    /// Constructor representing a specific error with a message.
    ///
    /// # Arguments
    /// `code`: The error code.
    /// `message`: An arbitrary status message.
    pub fn new_with_message<T: Into<String>>(code: ErrorCode, message: T) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }

    /// Gets a status according to a system error number of a system call.
    ///
    /// # Arguments
    /// `call_name`: The name of the system call.
    /// `sys_err_num`: The value of "errno".
    ///
    /// # Returns
    /// The status object.
    pub fn from_system_call(call_name: &str, sys_err_num: i32) -> Self {
        match sys_err_num {
            libc::EAGAIN => Self::new_with_message(ErrorCode::SystemError, format!("{}: temporarily unavailable", call_name)),
            libc::EINTR => Self::new_with_message(ErrorCode::SystemError, format!("{}: interrupted by a signal", call_name)),
            libc::EACCES => Self::new_with_message(ErrorCode::PermissionError, format!("{}: permission denied", call_name)),
            libc::ENOENT => Self::new_with_message(ErrorCode::NotFoundError, format!("{}: no such file", call_name)),
            libc::ENOTDIR => Self::new_with_message(ErrorCode::NotFoundError, format!("{}: not a directory", call_name)),
            libc::EISDIR => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: duplicated directory", call_name)),
            libc::ELOOP => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: looped path", call_name)),
            libc::EFBIG => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: too big file", call_name)),
            libc::ENOSPC => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: no enough space", call_name)),
            libc::ENOMEM => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: no enough memory", call_name)),
            libc::EEXIST => Self::new_with_message(ErrorCode::DuplicationError, format!("{}: already exist", call_name)),
            libc::ENOTEMPTY => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: not empty", call_name)),
            libc::EXDEV => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: cross device move", call_name)),
            libc::EBADF => Self::new_with_message(ErrorCode::SystemError, format!("{}: bad file descriptor", call_name)),
            libc::EINVAL => Self::new_with_message(ErrorCode::SystemError, format!("{}: invalid file descriptor", call_name)),
            libc::EIO => Self::new_with_message(ErrorCode::SystemError, format!("{}: low-level I/O error", call_name)),
            libc::EFAULT => Self::new_with_message(ErrorCode::SystemError, format!("{}: fault buffer address", call_name)),
            libc::EDQUOT => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: exhausted quota", call_name)),
            libc::EMFILE => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: exceeding process limit", call_name)),
            libc::ENFILE => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: exceeding system-wide limit", call_name)),
            libc::ENAMETOOLONG => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: too long name", call_name)),
            libc::ETXTBSY => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: busy file", call_name)),
            libc::EOVERFLOW => Self::new_with_message(ErrorCode::InfeasibleError, format!("{}: size overflow", call_name)),
            _ => Self::new_with_message(ErrorCode::SystemError, format!("{}: unknown error: {}", call_name, sys_err_num)),
        }
    }

    /// Gets the error code.
    ///
    /// # Returns
    /// The error code.
    #[inline]
    pub fn get_code(&self) -> ErrorCode {
        self.code
    }

    /// Gets the message, if any.
    ///
    /// # Returns
    /// The message, if any.
    #[inline]
    pub fn get_message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Checks whether the error has a non-empty message.
    ///
    /// # Returns
    /// True if the error has a non-empty message.
    #[inline]
    pub fn has_message(&self) -> bool {
        self.message.is_some()
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl Eq for Error {}

impl Display for Error {
    /// Gets a string expression of the status.
    ///
    /// # Returns
    /// The string expression
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self.message {
            Some(ref message) => write!(f, "{}: {}", self.code, message),
            None => write!(f, "{}", self.code),
        }
    }
}

impl StdError for Error {}
