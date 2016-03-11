extern crate libc;

use std::ptr::null;
use std::ptr::null_mut;
use std::ffi::CString;

mod ffi {
    use libc::c_void;
    use libc::c_char;

    pub enum DNSService {}
    pub type DNSServiceRef = *mut DNSService;

    #[repr(i32)]
    #[allow(dead_code)]
    #[derive(Copy,Clone,Debug,PartialEq,Eq)]
    pub enum DNSServiceErrorType {
        NoError = 0,
        Unknown = -65537,
        NoSuchName = -65538,
        NoMemory = -65539,
        BadParam = -65540,
        BadReference = -65541,
        BadState = -65542,
        BadFlags = -65543,
        Unsupported = -65544,
        NotInitialized = -65545,
        AlreadyRegistered = -65547,
        NameConflict = -65548,
        Invalid = -65549,
        Firewall = -65550,
        Incompatible = -65551,
        BadInterfaceIndex = -65552,
        Refused = -65553,
        NoSuchRecord = -65554,
        NoAuth = -65555,
        NoSuchKey = -65556,
        NATTraversal = -65557,
        DoubleNAT = -65558,
        BadTime = -65559,
        BadSig = -65560,
        BadKey = -65561,
        Transient = -65562,
        ServiceNotRunning = -65563,
        NATPortMappingUnsupported = -65564,
        NATPortMappingDisabled = -65565,
        NoRouter = -65566,
        PollingMode = -65567,
        Timeout = -65568,
    }

    pub type DNSServiceFlags = u32;
    pub type DNSServiceRegisterReply = Option<extern "C" fn(DNSServiceRef,
                                                            DNSServiceFlags,
                                                            DNSServiceErrorType,
                                                            *const c_char,
                                                            *const c_char,
                                                            *const c_char,
                                                            *mut c_void)
                                                           >;

    extern "C" {
        pub fn DNSServiceRegister(sdRef: *mut DNSServiceRef,
                                  flags: DNSServiceFlags,
                                  interfaceIndex: u32,
                                  name: *const c_char,
                                  regtype: *const c_char,
                                  domain: *const c_char,
                                  host: *const c_char,
                                  port: u16,
                                  txtLen: u16,
                                  txtRecord: *const u8,
                                  callBack: DNSServiceRegisterReply,
                                  context: *mut c_void)
                                  -> DNSServiceErrorType;

        pub fn DNSServiceRefDeallocate(sdRef: DNSServiceRef);
    }
}

#[derive(Debug)]
pub struct DNSService {
    sd_ref: ffi::DNSServiceRef,
}

#[derive(Debug)]
pub struct DNSError(ffi::DNSServiceErrorType);

impl std::fmt::Display for DNSError {
    fn fmt(&self, format: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(format, "DNS-SD Error: {:?}", self.0)
    }
}

impl std::error::Error for DNSError {
    fn description(&self) -> &str {
        "DNS-SD Error"
    }
}

impl DNSService {
    pub fn register(name: Option<&str>,
                    regtype: &str,
                    domain: Option<&str>,
                    host: Option<&str>,
                    port: u16,
                    txt: &[&str])
                    -> std::result::Result<DNSService, DNSError> {
        let mut sd_ref: ffi::DNSServiceRef = null_mut();

        let txt_data: Vec<u8> = txt.into_iter()
                                   .flat_map(|value| {
                                       std::iter::once(value.len() as u8).chain(value.bytes())
                                   })
                                   .collect();

        let name = name.map(|s| CString::new(s).unwrap());
        let regtype = CString::new(regtype).unwrap();
        let domain = domain.map(|s| CString::new(s).unwrap());
        let host = host.map(|s| CString::new(s).unwrap());

        let err = unsafe {
            ffi::DNSServiceRegister(&mut sd_ref as *mut _,
                                    0,
                                    0,
                                    name.as_ref().map_or(null(), |s| s.as_ptr()),
                                    regtype.as_ptr(),
                                    domain.as_ref().map_or(null(), |s| s.as_ptr()),
                                    host.as_ref().map_or(null(), |s| s.as_ptr()),
                                    port.to_be(),
                                    txt_data.len() as u16,
                                    if txt_data.is_empty() {
                                        null()
                                    } else {
                                        txt_data.as_ptr()
                                    },
                                    None,
                                    null_mut())
        };

        // We must be sure these stay are still alive during the DNSServiceRegister call
        // Because we pass them as raw pointers, rust's borrow checker is useless there
        // If they are still valid at this point, then we're good
        drop(name);
        drop(regtype);
        drop(domain);
        drop(host);
        drop(txt_data);

        if err == ffi::DNSServiceErrorType::NoError {
            Ok(DNSService { sd_ref: sd_ref })
        } else {
            Err(DNSError(err))
        }
    }
}

impl Drop for DNSService {
    fn drop(&mut self) {
        unsafe {
            ffi::DNSServiceRefDeallocate(self.sd_ref);
        }
    }
}
