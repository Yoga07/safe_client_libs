// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Logging utilities
//! This module is exact to safe_app::ffi::logging, therefore changes to either one of them should
//! also be reflected to the other to stay in sync.

use super::AuthError;
use config_file_handler::FileHandler;
use ffi_utils::{catch_unwind_cb, from_c_str, FfiResult, FFI_RESULT_OK};
use safe_core::utils::logging;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

/// This function should be called to enable logging to a file.
/// If `output_file_name_override` is provided, then this path will be used for
/// the log output file.
#[no_mangle]
pub unsafe extern "C" fn auth_init_logging(
    output_file_name_override: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AuthError> {
        if output_file_name_override.is_null() {
            logging::init(false)?;
        } else {
            let output_file_name_override = from_c_str(output_file_name_override)?;
            logging::init_with_output_file(false, output_file_name_override)?;
        }
        o_cb(user_data, FFI_RESULT_OK);
        Ok(())
    });
}

/// This function should be called to find where log file will be created. It
/// will additionally create an empty log file in the path in the deduced
/// location and will return the file name along with complete path to it.
#[no_mangle]
pub unsafe extern "C" fn auth_output_log_path(
    output_file_name: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, log_path: *const c_char),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AuthError> {
        let op_file = from_c_str(output_file_name)?;
        let fh = FileHandler::<()>::new(&op_file, true)
            .map_err(|e| AuthError::Unexpected(format!("{}", e)))?;
        let op_file_path = CString::new(
            fh.path()
                .to_path_buf()
                .into_os_string()
                .into_string()
                .map_err(|_| AuthError::Unexpected("Couldn't convert OsString".to_string()))?
                .into_bytes(),
        )?;
        o_cb(user_data, FFI_RESULT_OK, op_file_path.as_ptr());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::{call_0, call_1};
    use safe_core::config_dir;
    use std::env;
    use std::fs::{self, File};
    use std::io::Read;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;

    // Test path where log file is created.
    #[test]
    fn output_log_path() {
        let name = "_test path";
        let path_str = unwrap!(CString::new(name));

        let path: String = unsafe {
            unwrap!(call_1(|ud, cb| auth_output_log_path(
                path_str.as_ptr(),
                ud,
                cb
            ),))
        };

        assert!(path.contains(name));
    }

    // Test logging errors to file.
    #[test]
    fn file_logging() {
        setup_log_config();

        let log_file_name = unwrap!(PathBuf::from_str("AuthClient.log"));

        let file_name = unwrap!(CString::new(unwrap!(log_file_name
            .clone()
            .into_os_string()
            .into_string())));
        unsafe {
            unwrap!(call_0(|ud, cb| auth_init_logging(
                file_name.as_ptr(),
                ud,
                cb
            ),));
        }

        let debug_msg = "This is a sample debug message".to_owned();
        let junk_msg = "This message should not exist in the log file".to_owned();

        error!("{}", debug_msg);
        debug!("{}", junk_msg);

        // Give some time to the async logging to flush in the background thread
        thread::sleep(Duration::from_secs(1));

        let log_path = unwrap!(config_dir()).join(log_file_name);
        let mut log_file = unwrap!(File::open(log_path));
        let mut file_content = String::new();

        let written = unwrap!(log_file.read_to_string(&mut file_content));
        assert!(written > 0);

        assert!(file_content.contains(&debug_msg[..]));
        assert!(!file_content.contains(&junk_msg[..]));
    }

    fn setup_log_config() {
        let mut current_dir = unwrap!(env::current_dir());
        let mut config_dir = unwrap!(config_dir());
        unwrap!(fs::create_dir_all(config_dir.clone()));

        if current_dir.as_path() != config_dir.as_path() {
            // Try to copy log.toml from the current dir to config dir
            // so that the config_handler can find it
            current_dir.push("sample_log_file/log.toml");
            config_dir.push("log.toml");

            let _ = unwrap!(fs::copy(current_dir, config_dir));
        }
    }
}
