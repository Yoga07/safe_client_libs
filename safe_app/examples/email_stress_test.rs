// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0. This, along with the Licenses can be found in the
// root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

//! Email Stress Test

// For explanation of lint checks, run `rustc -W help`.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

use rand::{Rng, SeedableRng};
use safe_app::logging::app_init_logging;
use std::ptr;
use std::sync::Mutex;
use std::sync::mpsc::{self, Sender};
use std::time::Instant;
use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec};
use ffi_utils::FfiResult;
use ffi_utils::ReprC;
use safe_app::entry_actions::{mdata_entry_actions_insert, mdata_entry_actions_new};
use safe_app::ffi::app_registered;
use safe_app::ffi::ipc::encode_auth_req;
use safe_app::mutable_data::permissions::{
    mdata_permissions_insert, mdata_permissions_len, mdata_permissions_new,
};
use safe_app::mutable_data::{
    mdata_list_user_permissions, mdata_mutate_entries, mdata_put, seq_mdata_list_values,
    ENTRIES_EMPTY,
};
use safe_app::{decode_ipc_msg, run, App, MDataPermissionsHandle};
use safe_authenticator::ffi::ipc::encode_auth_resp;
use safe_authenticator::{create_acc, ffi::login, Authenticator};
use safe_core::client::Client;
use safe_core::core_structs::MDataValue;
use safe_core::ffi::ipc::req::PermissionSet as FfiPermissionSet;
use safe_core::ffi::ipc::resp::AuthGranted as FfiAuthGranted;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use safe_core::ipc::{AppExchangeInfo, AuthGranted, AuthReq};
use safe_core::MDataInfo as NativeMDataInfo;
use safe_nd::{AppPermissions, MDataAction, MDataAddress, MDataPermissionSet, XorName};
use std::ffi::CString;
use std::os::raw::c_void;
use tiny_keccak::sha3_256;
use unwrap::unwrap;

static USAGE: &'static str = "
Usage:
  email_stress_test [options]
Options:
  --seed <seed>  Seed for a pseudo-random number generator.
  --get-only     Only Get the data, don't Put it.
  -h, --help     Display this help message and exit.
";
#[derive(Debug, RustcDecodable)]
struct Args {
    flag_seed: Option<u32>,
    flag_get_only: bool,
    flag_help: bool,
}
const BOTS: usize = 5;
const MSGS_SENT_BY_EACH_BOT: usize = 10;


struct Bot {
    auth: Authenticator,
    email: String,
    tx_msgs: Vec<Vec<u8>>,
}

impl Bot {
    fn new(n: usize, account_exists: bool) -> Self {
        let mut sec_0: String = rng.gen_iter::<char>().take(10).collect();
        let mut sec_1: String = rng.gen_iter::<char>().take(10).collect();
        sec_0.push_str(&n.to_string());
        sec_1.push_str(&n.to_string());
        let c_sec_0 = unwrap!(CString::new(secret_0));
        let c_sec_1 = unwrap!(CString::new(secret_1));
        let auth = account_creation(c_sec_0, c_sec_1);
        let auth = unsafe { &*auth };

        let prefix: String = rng.gen_iter::<char>().take(10).collect();
        let email = format!("{}-Bot-{}-mail", prefix, n);
        let tx_msgs = (0..MSGS_SENT_BY_EACH_BOT)
            .map(|x| {
                let mut msg: Vec<_> = rng.gen_iter::<u8>().take(10).collect();
                msg.extend(format!("Bot-{}-msg-{}", n, x).into_bytes());
                msg
            })
            .collect();
        Self {
            auth: auth.clone(),
            email,
            tx_msgs,
        }
    }

    fn create_email(&self) -> Result<(), i32> {
        let Digest(digest) = sha3_256(self.email.as_bytes());

//        unsafe {
//            ad_h = try!(c1(|user_data, cb| {
//                appendable_data_new_priv(self.session, self.app_h, &digest, user_data, cb)
//            }));
//            try!(c0(|user_data, cb| appendable_data_put(self.session, ad_h, user_data, cb)));
//            try!(c0(|user_data, cb| appendable_data_free(self.session, ad_h, user_data, cb)));
//            Ok(())
//        }
    }

    fn get_peer_email_handles(&self,
                              peer_email: &str)
                              -> Result<(AppendableDataHandle, CipherOptHandle), i32> {
//        let Digest(digest) = sha256::hash(peer_email.as_bytes());
//        let data_id_h = unsafe {
//            try!(c1(|user_data, cb| {
//                data_id_new_appendable_data(self.session, &digest, true, user_data, cb)
//            }))
//        };
//        let ad_h;
//        unsafe {
//            ad_h = try!(c1(|u, cb| appendable_data_get(self.session, data_id_h, u, cb)));
//            try!(c0(|u, cb| data_id_free(self.session, data_id_h, u, cb)));
//        }
//        let cipher_opt_h;
//        let encrypt_key_h;
//        unsafe {
//            encrypt_key_h = try!(c1(|user_data, cb| {
//                appendable_data_encrypt_key(self.session, ad_h, user_data, cb)
//            }));
//            cipher_opt_h = try!(c1(|user_data, cb| {
//                cipher_opt_new_asymmetric(self.session, encrypt_key_h, user_data, cb)
//            }));
//            try!(c0(|user_data, cb| {
//                misc_encrypt_key_free(self.session, encrypt_key_h, user_data, cb)
//            }));
//        }
//        Ok((ad_h, cipher_opt_h))
    }

    fn send_email(&self, peer_ad_h: u64, cipher_opt_h: u64, msg: &[u8]) -> Result<(), i32> {
//        let se_h;
//        unsafe {
//            se_h = try!(c1(|u, cb| immut_data_new_self_encryptor(self.session, u, cb)));
//            try!(c0(|u, cb| {
//                immut_data_write_to_self_encryptor(self.session,
//                                                   se_h,
//                                                   msg.as_ptr(),
//                                                   msg.len(),
//                                                   u,
//                                                   cb)
//            }));
//        }
//        let data_id_h;
//        unsafe {
//            data_id_h = try!(c1(|u, cb| {
//                immut_data_close_self_encryptor(self.session, self.app_h, se_h, cipher_opt_h, u, cb)
//            }));
//            try!(c0(|u, cb| appendable_data_append(self.session, peer_ad_h, data_id_h, u, cb)));
//            try!(c0(|u, cb| data_id_free(self.session, data_id_h, u, cb)));
//        }
//        Ok(())
    }
    fn get_all_emails(&self) -> Result<Vec<Vec<u8>>, i32> {
//        let Digest(digest) = sha256::hash(self.email.as_bytes());
//        let data_id_h = try!(unsafe {
//            c1(|u, cb| data_id_new_appendable_data(self.session, &digest, true, u, cb))
//        });
//        let ad_h;
//        unsafe {
//            ad_h = try!(c1(|u, cb| appendable_data_get(self.session, data_id_h, u, cb)));
//            try!(c0(|u, cb| data_id_free(self.session, data_id_h, u, cb)));
//        };
//        let num_of_emails =
//            unsafe { try!(c1(|u, cb| appendable_data_num_of_data(self.session, ad_h, u, cb))) };
//        let mut rx_msgs = Vec::with_capacity(num_of_emails);
//        for n in 0..num_of_emails {
//            let data_id_h = unsafe {
//                try!(c1(|u, cb| {
//                    appendable_data_nth_data_id(self.session, self.app_h, ad_h, n, u, cb)
//                }))
//            };
//            let se_h = unsafe {
//                try!(c1(|u, cb| {
//                    immut_data_fetch_self_encryptor(self.session, self.app_h, data_id_h, u, cb)
//                }))
//            };
//            let total_size =
//                unsafe { try!(c1(|u, cb| immut_data_size(self.session, se_h, u, cb))) };
//            let rx_msg = unsafe {
//                try!(call_vec_u8(|u, cb| {
//                    immut_data_read_from_self_encryptor(self.session, se_h, 0, total_size, u, cb)
//                }))
//            };
//            rx_msgs.push(rx_msg);
//            unsafe {
//                try!(c0(|user_data, cb| data_id_free(self.session, data_id_h, user_data, cb)));
//                try!(c0(|user_data, cb| {
//                    immut_data_self_encryptor_reader_free(self.session, se_h, user_data, cb)
//                }));
//            }
//        }
//        unsafe {
//            try!(c0(|user_data, cb| appendable_data_free(self.session, ad_h, user_data, cb)));
//        }
//        Ok(rx_msgs)
    }
}
impl Drop for Bot {
    fn drop(&mut self) {
        unsafe {
            session_free(self.session);
        }
    }
}
unsafe impl Send for Bot {}
unsafe impl Sync for Bot {}

fn account_creation(sec_0: CString, sec_1: CString) -> *mut Authenticator {
    println!("\nCreate an account ...");
    unsafe {
            unwrap!(call_1(|ud, cb| create_acc(sec_0.as_ptr(), sec_1.as_ptr(), ud, disconnect_cb, cb)))
    }
}

//fn account_login(sec_0: CString, sec_1: CString) -> *mut Authenticator {
//    println!("\nTrying to log in ...");
//    unsafe {
//        unwrap!((call_1(|ud, cb| login(sec_0.as_ptr(), sec_1.as_ptr(), ud, print_disconnect_cb, cb)))
//    }
//}

//fn network_login() -> *mut Authenticator {
//    println!("\nDo you already have an account created (enter Y for yes) ?");
//    let mut user_option = String::new();
//    let _ = std::io::stdin().read_line(&mut user_option);
//    user_option = user_option.trim().to_string();
//    if user_option != "Y" && user_option != "y" {
//        println!("\n\tAccount Creation");
//        println!("\t================");
//    } else {
//        println!("\n\n\tAccount Login");
//        println!("\t====================");
//    }
//
//    let mut secret_0 = String::new();
//    let mut secret_1 = String::new();
//    println!("\n------------ Enter account-locator ---------------");
//    let _ = std::io::stdin().read_line(&mut secret_0);
//    secret_0 = secret_0.trim().to_string();
//    println!("\n------------ Enter password ---------------");
//    let _ = std::io::stdin().read_line(&mut secret_1);
//    secret_1 = secret_1.trim().to_string();
//    let c_sec_0 = unwrap!(CString::new(secret_0));
//    let c_sec_1 = unwrap!(CString::new(secret_1));
//
//    if user_option != "Y" && user_option != "y" {
//        account_creation(c_sec_0, c_sec_1)
//    } else {
//        account_login(c_sec_0, c_sec_1)
//    }
//}


/*
fn main() {
    // Sample timings in release run with mock-routing and cleared
    // VaultStorageSimulation:
    // ------------------------------------------------------------------------------------
    // Create accounts for 5 bots: 3 secs, 0 millis
    // Create emails for 5 bots: 0 secs, 218 millis
    // Send total of 200 emails by 5 bots: 23 secs, 71 millis
    // Read total of 200 emails by 5 bots: 0 secs, 30 millis
    //
    // Sample timmings in release run with actual-routing:
    // ------------------------------------------------------------------------------------
    // Create accounts for 5 bots: 27 secs, 0 millis
    // Create emails for 5 bots: 0 secs, 411 millis
    // Send total of 200 emails by 5 bots: 26 secs, 415 millis
    // Read total of 200 emails by 5 bots: 6 secs, 273 millis
    // ------------------------------------------------------------------------------------
    assert_eq!(init_logging(), 0);
//    let args: Args =
//        Docopt::new(USAGE).and_then(|docopt| docopt.decode()).unwrap_or_else(|error| error.exit());
//    let mut rng = XorShiftRng::from_seed(match args.flag_seed {
//        Some(seed) => [0, 0, 0, seed],
//        None => [rand::random(), rand::random(), rand::random(), rand::random()],
//    });
//    // ------------------------------------------------------------------------
//    // Create bots
    let mut now = Instant::now();
    let bots: Vec<_> = (0..BOTS)
        .map(|n| {
            unwrap!(Bot::new(n, &mut rng, args.flag_get_only),
                    "Can't create bot")
        })
        .collect();
//    let mut duration = now.elapsed();
//    info!("Create accounts for {} bots: {} secs, {} millis\n",
//          BOTS,
//          duration.as_secs(),
//          duration.subsec_nanos() / 1000000);
//    if !args.flag_get_only {
//        // ------------------------------------------------------------------------
//        // Create email in parallel
//        now = Instant::now();
//        crossbeam::scope(|scope| {
//            for bot in &bots {
//                let _ = scope.spawn(move || bot.create_email());
//            }
//        });
//        duration = now.elapsed();
//        info!("Create emails for {} bots: {} secs, {} millis\n",
//              BOTS,
//              duration.as_secs(),
//              duration.subsec_nanos() / 1000000);
//        // ------------------------------------------------------------------------
//        // Send emails
//        now = Instant::now();
//        for (i, bot) in bots.iter().enumerate() {
//            let peer_handles = Mutex::new(Vec::with_capacity(BOTS - 1));
//            let peer_handles_ref = &peer_handles;
//            // Get peer emails in parallel
//            crossbeam::scope(|scope| {
//                for (j, peer_bot) in bots.iter().enumerate() {
//                    if i == j {
//                        continue;
//                    }
//                    let _ = scope.spawn(move || {
//                        unwrap!(peer_handles_ref.lock())
//                            .push(unwrap!(bot.get_peer_email_handles(&peer_bot.email)))
//                    });
//                }
//            });
//            // Send each email-msg from a bot in parallel to all others
//            for msg in &bot.tx_msgs {
//                let guard = unwrap!(peer_handles.lock());
//                crossbeam::scope(|scope| {
//                    for &(ad_h, cipher_opt_h) in &*guard {
//                        let _ = scope.spawn(move || {
//                            assert!(bot.send_email(ad_h, cipher_opt_h, msg).is_ok())
//                        });
//                    }
//                })
//            }
//            let guard = unwrap!(peer_handles.lock());
//            for &(ad_h, cipher_opt_h) in &*guard {
//                unsafe {
//                    assert!(c0(|user_data, cb| {
//                                    appendable_data_free(bot.session, ad_h, user_data, cb)
//                                })
//                                .is_ok(),
//                            "can't free AppendableData");
//                    assert!(c0(|user_data, cb| {
//                                    cipher_opt_free(bot.session, cipher_opt_h, user_data, cb)
//                                })
//                                .is_ok(),
//                            "can't free CipherOpt");
//                }
//            }
//        }
//        duration = now.elapsed();
//        info!("Sent total of {} emails by {} bots: {} secs, {} millis\n",
//              MSGS_SENT_BY_EACH_BOT * (BOTS - 1) * BOTS,
//              BOTS,
//              duration.as_secs(),
//              duration.subsec_nanos() / 1000000);
//    }
//    // ------------------------------------------------------------------------
//    // Read and verify all emails by all bots in parallel
//    now = Instant::now();
//    crossbeam::scope(|scope| {
//        let bots_ref = &bots;
//        for (i, bot) in bots_ref.iter().enumerate() {
//            let _ = scope.spawn(move || {
//                let mut rx_emails = unwrap!(bot.get_all_emails(), "can't get emails");
//                assert_eq!(rx_emails.len(), MSGS_SENT_BY_EACH_BOT * (BOTS - 1));
//                for (j, peer_bot) in bots_ref.iter().enumerate() {
//                    if i == j {
//                        continue;
//                    }
//                    for tx_msg in &peer_bot.tx_msgs {
//                        let pos = unwrap!(rx_emails.iter()
//                            .position(|rx_email| *rx_email == *tx_msg));
//                        let _ = rx_emails.remove(pos);
//                    }
//                }
//            });
//        }
//    });
//    duration = now.elapsed();
//    info!("Read total of {} emails by {} bots: {} secs, {} millis\n",
//          MSGS_SENT_BY_EACH_BOT * (BOTS - 1) * BOTS,
//          BOTS,
//          duration.as_secs(),
//          duration.subsec_nanos() / 1000000);
}
// Convert a `mpsc::Sender<T>` to a void ptr which can be passed as user data to
// ffi functions
fn sender_as_user_data<T>(tx: &Sender<T>) -> *mut c_void {
//    let ptr: *const _ = tx;
//    ptr as *mut c_void
}
// Send through a `mpsc::Sender` pointed to by the user data pointer.
unsafe fn send_via_user_data<T>(u: *mut c_void, value: T)
    where T: Send
{
//    let tx = u as *mut Sender<T>;
//    unwrap!((*tx).send(value));
}
// Call a FFI function and block until its callback gets called.
// Use this if the callback accepts no arguments in addition to u
// and error_code.
fn c0<F>(f: F) -> Result<(), i32>
    where F: FnOnce(*mut c_void, unsafe extern "C" fn(*mut c_void, i32))
{
//    let (tx, rx) = mpsc::channel::<i32>();
//    f(sender_as_user_data(&tx), callback_0);
//    let error = unwrap!(rx.recv());
//    if error == 0 { Ok(()) } else { Err(error) }
}
// Call a FFI function and block until its callback gets called, then return
// the argument which were passed to that callback.
// Use this if the callback accepts one argument in addition to u
// and error_code.
unsafe fn c1<F, T>(f: F) -> Result<T, i32>
    where F: FnOnce(*mut c_void, unsafe extern "C" fn(*mut c_void, i32, T))
{
//    let (tx, rx) = mpsc::channel::<(i32, SendWrapper<T>)>();
//    f(sender_as_user_data(&tx), callback_1::<T>);
//    let (error, args) = unwrap!(rx.recv());
//    if error == 0 { Ok(args.0) } else { Err(error) }
}
// Call a FFI function and block until its callback gets called, then return
// the arguments which were passed to that callback in a tuple.
// Use this if the callback accepts three arguments in addition to u and
// error_code.
unsafe fn c3<F, T0, T1, T2>(f: F) -> Result<(T0, T1, T2), i32>
    where F: FnOnce(*mut c_void,
                    unsafe extern "C" fn(*mut c_void, i32, T0, T1, T2))
{
//    let (tx, rx) = mpsc::channel::<(i32, SendWrapper<(T0, T1, T2)>)>();
//    f(sender_as_user_data(&tx), callback_3::<T0, T1, T2>);
//    let (error, args) = unwrap!(rx.recv());
//    if error == 0 { Ok(args.0) } else { Err(error) }
}
// Call a FFI function and block until its callback gets called, then return
// the arguments which were passed to that callback converted to Vec<u8>.
// The callbacks must accept three arguments (in addition to u and
// error_code): pointer to the begining of the data (`*mut u8`), lengths
// (`usize`)
// and capacity (`usize`).
//unsafe fn call_vec_u8<F>(f: F) -> Result<Vec<u8>, i32>
//    where F: FnOnce(*mut c_void,
//                    unsafe extern "C" fn(*mut c_void, i32, *mut u8, usize, usize))
//{
//    c3(f).map(|(ptr, len, cap)| Vec::from_raw_parts(ptr, len, cap))
//}
//unsafe extern "C" fn callback_0(user_data: *mut c_void, error: i32) {
//    send_via_user_data(user_data, error)
//}
//unsafe extern "C" fn callback_1<T>(user_data: *mut c_void, error: i32, arg: T) {
//    send_via_user_data(user_data, (error, SendWrapper(arg)))
//}
//unsafe extern "C" fn callback_3<T0, T1, T2>(user_data: *mut c_void,
//                                            error: i32,
//                                            arg0: T0,
//                                            arg1: T1,
//                                            arg2: T2) {
//    send_via_user_data(user_data, (error, SendWrapper((arg0, arg1, arg2))))
//}
// Unsafe wrapper for passing non-Send types through mpsc channels.
// Use with caution!
//struct SendWrapper<T>(T);
//unsafe impl<T> Send for SendWrapper<T> {}
//unsafe extern "C" fn network_event_callback(_user_data: *mut c_void, err_code: i32, event: i32) {
//    println!("Network event with code {}, err_code: {}", event, err_code);
//}
*/

fn main() {}

fn ffi_authorise_app(auth_h: *mut Authenticator, app_info: &AppExchangeInfo) -> AuthGranted {
    let auth_req = AuthReq {
        app: app_info.clone(),
        app_container: true,
        app_permissions: AppPermissions {
            transfer_coins: true,
            perform_mutations: true,
            get_balance: true,
        },
        containers: Default::default(),
    };
    let ffi_auth_req = unwrap!(auth_req.clone().into_repr_c());

    let (req_id, _encoded): (u32, String) =
        unsafe { unwrap!(call_2(|ud, cb| encode_auth_req(&ffi_auth_req, ud, cb))) };

    let encoded_auth_resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            let auth_req = unwrap!(auth_req.into_repr_c());
            encode_auth_resp(
                auth_h, &auth_req, req_id, true, // is_granted
                ud, cb,
            )
        }))
    };
    let encoded_auth_resp = unwrap!(CString::new(encoded_auth_resp));

    let mut context = Context {
        unexpected_cb: false,
        req_id: 0,
        auth_granted: None,
    };

    let context_ptr: *mut Context = &mut context;
    unsafe {
        decode_ipc_msg(
            encoded_auth_resp.as_ptr(),
            context_ptr as *mut c_void,
            auth_cb,
            unregistered_cb,
            containers_cb,
            share_mdata_cb,
            revoked_cb,
            err_cb,
        );
    }

    assert!(!context.unexpected_cb);
    assert_eq!(context.req_id, req_id);

    unwrap!(context.auth_granted)
}

struct Context {
    unexpected_cb: bool,
    req_id: u32,
    auth_granted: Option<AuthGranted>,
}

extern "C" fn auth_cb(ctx: *mut c_void, req_id: u32, auth_granted: *const FfiAuthGranted) {
    unsafe {
        let auth_granted = unwrap!(AuthGranted::clone_from_repr_c(auth_granted));

        let ctx = ctx as *mut Context;
        (*ctx).req_id = req_id;
        (*ctx).auth_granted = Some(auth_granted);
    }
}

extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn share_mdata_cb(ctx: *mut c_void, _req_id: u32) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn revoked_cb(ctx: *mut c_void) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn unregistered_cb(
    ctx: *mut c_void,
    _req_id: u32,
    _bootstrap_cfg: *const u8,
    _bootstrap_cfg_len: usize,
) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn err_cb(ctx: *mut c_void, _res: *const FfiResult, _req_id: u32) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn disconnect_cb(_user_data: *mut c_void) {
    panic!("Disconnect callback");
}

extern "C" fn print_disconnect_cb(_user_data: *mut c_void) {
    println!("Fetched LoginPacket successfully. Disconnecting the throw-client and logging in ...");
}
