//! # Certificate Generation and Handling Library
//!
//! This Rust library provides functionality for generating self-signed certificates, creating server certificates signed by a Certificate Authority (CA), and handling certificate loading and saving operations. It leverages the `rustls_pki_types`, `rcgen`, and `pem` crates to achieve these tasks.
//!
//! ## Features
//!
//! - **Self-Signed Certificate Generation**: Create self-signed certificates with specified parameters.
//! - **CA-Signed Certificate Generation**: Generate server certificates signed by a CA certificate.
//! - **Certificate Loading**: Load certificates and private keys from PEM files or PEM-formatted strings.
//! - **Certificate Saving**: Convert certificates and private keys to PEM format for storage or transmission.
//!
//! ## Error Handling
//!
//! The library defines a `CertGenError` enumeration to represent various errors that might occur during certificate handling, including I/O errors, generation failures, parse errors, and other miscellaneous errors.
//!
//! ## Usage
//!
//! ### Generating a Self-Signed CA Certificate
//!
//! ```rust
//! use certgenutil::generate_self_signed_cert;
//! 
//! let (cert, private_key) = generate_self_signed_cert(
//!     "example.com",
//!     true,
//!     365,
//!     vec!["www.example.com".to_string(), "mail.example.com".to_string()],
//! ).unwrap();
//! ```
//!
//! ### Generating a Server Certificate Signed by a CA
//!
//! #### Using a CA Certificate File
//!
//! ```rust
//! use certgenutil::generate_server_cert_by_ca_file;
//! use std::path::PathBuf;
//!
//! let ca_file_path = PathBuf::from("ca.pem");
//! let (cert, private_key) = generate_server_cert_by_ca_file(
//!     ca_file_path,
//!     "example.com",
//!     365,
//!     vec!["www.example.com".to_string(), "mail.example.com".to_string()],
//! ).unwrap();
//! ```
//!
//! #### Using a CA Certificate PEM String
//!
//! ```rust
//! use certgenutil::generate_server_cert_by_ca_pem;
//!
//! let ca_pem = String::from(r#"-----BEGIN CERTIFICATE-----
//! MIIBejCCASCgAwIBAgIUNcB9KoFex2HVOvNXIZzfN/7QyMUwCgYIKoZIzj0EAwIw
//! ETEPMA0GA1UEAwwGcm9vdGNhMB4XDTI0MDgxODA0NDEwOFoXDTI1MDgxODA0NDEw
//! OFowETEPMA0GA1UEAwwGcm9vdGNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
//! 0kzg73SoZ82snyWboqjKbrlgvavvzduYSWmn2x6NBejWlPLLxdtMxiY0NVfSXq+I
//! 9eBqzr88yV7QC79yH+GxyKNWMFQwEgYDVR0RBAswCYIHYWJjLmNvbTAOBgNVHQ8B
//! Af8EBAMCAQYwHQYDVR0OBBYEFP/KV01ye89Wwfde0wic7i+StpidMA8GA1UdEwEB
//! /wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgfQlSU05caJtz8XxJvA/AmHSQkroy
//! YUloxc/s1mQKR9ICIQD9twx295ClByM7bjsHsGNnORok3szuCuJiQaX9o5DR1w==
//! -----END CERTIFICATE-----
//! -----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSnXLALeEZnbLdbRT
//! T4IumE9TztYMJTF97pMQFpF0zByhRANCAATSTODvdKhnzayfJZuiqMpuuWC9q+/N
//! 25hJaafbHo0F6NaU8svF20zGJjQ1V9Jer4j14GrOvzzJXtALv3If4bHI
//! -----END PRIVATE KEY-----"#);
//! let (cert, private_key) = generate_server_cert_by_ca_pem(
//!     ca_pem,
//!     "example.com",
//!     365,
//!     vec!["www.example.com".to_string(), "mail.example.com".to_string()],
//! ).unwrap();
//! ```
//!
//! ### Loading Certificates and Private Keys
//!
//! #### From PEM Files
//!
//! ```rust
//! use certgenutil::{load_cert_from_pem_file, load_key_from_pem_file};
//! use std::path::PathBuf;
//!
//! let cert_path = PathBuf::from("ca.pem");
//! let key_path = PathBuf::from("ca.pem");
//!
//! let cert = load_cert_from_pem_file(cert_path).unwrap();
//! let key = load_key_from_pem_file(key_path).unwrap();
//! ```
//!
//! #### From PEM Strings
//!
//! ```rust
//! use certgenutil::{load_cert_from_pem_str, load_key_from_pem_str};
//!
//! let cert_pem = r#"-----BEGIN CERTIFICATE-----
//! MIIBejCCASCgAwIBAgIUBH8zfLAlg0h8FQUc8wZjJlrPWrgwCgYIKoZIzj0EAwIw
//! ETEPMA0GA1UEAwwGcm9vdGNhMB4XDTI0MDgxODA0MzMxMFoXDTI1MDgxODA0MzMx
//! MFowETEPMA0GA1UEAwwGcm9vdGNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
//! 8GuAphYzDWDsTbuXaQcZt28NAgVJJC2RRj+h76CtfpIH/VonRCEBsRtS6UOWXvi9
//! QX7bO+evfMFvpyJq7IE9KaNWMFQwEgYDVR0RBAswCYIHYWJjLmNvbTAOBgNVHQ8B
//! Af8EBAMCAQYwHQYDVR0OBBYEFPK0E8CY4Hv2FQurWHogzHeXWIYWMA8GA1UdEwEB
//! /wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKvhoh2oz+WZ3Ry0du8saLwqAFBz
//! Kdpn9dwKE0NF3Ju9AiAs2ZO7fDaMxEkeFIqZi1XktTNWOzSMrjuZDknC2tZugQ==
//! -----END CERTIFICATE-----"#;
//! let key_pem = r#"-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPY2goeIEayj3JLGR
//! /eRUTD7CAevRscPGxSWAbcWOpYChRANCAATwa4CmFjMNYOxNu5dpBxm3bw0CBUkk
//! LZFGP6HvoK1+kgf9WidEIQGxG1LpQ5Ze+L1Bfts75698wW+nImrsgT0p
//! -----END PRIVATE KEY-----"#;
//!
//! let cert = load_cert_from_pem_str(cert_pem).unwrap();
//! let key = load_key_from_pem_str(key_pem).unwrap();
//! ```
//!
//! ### Converting to PEM Format
//!
//! ```rust
//! use certgenutil::{get_cert_pem, get_key_pem,load_cert_from_pem_file,load_key_from_pem_file};
//! let cert = load_cert_from_pem_file("ca.pem").unwrap();
//! let key = load_key_from_pem_file("ca.pem").unwrap();
//! let cert_pem = get_cert_pem(&cert);
//! let key_pem = get_key_pem(&key).unwrap();
//! ```
//!
//! ## Dependencies
//!
//! - `rustls_pki_types`
//! - `rcgen`
//! - `pem`
//! - `thiserror`
//!
//! ## License
//!
//! This library is licensed under the MIT license. See the [LICENSE](LICENSE) file for more details.
//!
//! ## Contributing
//!
//! Contributions are welcome! Please open an issue or submit a pull request on the [GitHub repository](https://github.com/your_username/your_repo).
//!
//! ## Contact
//!
//! For questions or support, please contact [your_email@example.com](mailto:your_email@example.com).

use thiserror::Error;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

// Defines a CertGenError enumeration, used to represent various errors that might occur during certificate handling.
#[derive(Error, Debug)]
pub enum CertGenError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to generate {0}")]
    Generation(#[from] rcgen::Error),

    #[error("Parse error: {message} (context: {context})")]
    ParseError {
        message: String,
        context: String,
    },

    #[error("Other error: {0}")]
    OtherError(String),
}

impl From<&str> for CertGenError {
    fn from(s: &str) -> Self {
        CertGenError::OtherError(s.to_string())
    }
}

impl From<std::convert::Infallible> for CertGenError {
    fn from(_s: std::convert::Infallible) -> Self {
        CertGenError::OtherError("Infallible".into())
    }
}

/// Loads a certificate from a PEM formatted string.
/// 
/// # Parameters
/// - `s`: A type parameter that implements `AsRef<str>`, can be a string or a string slice.
/// 
/// # Returns
/// Returns a `Result` containing a `CertificateDer` object with a `'static` lifetime on success, or an error that implements `std::error::Error` on failure.
/// 
/// # Errors
/// Returns a `CertGenError::ParseError` if the PEM parsing fails.
pub fn load_cert_from_pem_str<T: AsRef<str>>(s: T) -> Result<CertificateDer<'static>, CertGenError> {
    let cursor = std::io::Cursor::new(s.as_ref());
    let mut reader = std::io::BufReader::new(cursor);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| CertGenError::ParseError {
            message: "Get Certificate Failed".to_string(),
            context: s.as_ref().to_string(),
        })??;
    Ok(cert)
}

/// Loads a private key from a PEM formatted string.
///
/// # Parameters
/// - `s`: A parameter that implements the `AsRef<str>` trait, which can be a string or a string slice.
///
/// # Returns
/// - Returns a `Result` type, containing a `PrivateKeyDer` private key on success, and an error object on failure.
///
/// # Errors
/// - If the private key cannot be parsed, it returns a `CertGenError::ParseError`.
pub fn load_key_from_pem_str<T: AsRef<str>>(s: T) -> Result<PrivateKeyDer<'static>, CertGenError>
{
    let cursor = std::io::Cursor::new(s.as_ref());
    let mut reader = std::io::BufReader::new(cursor);
    let key = rustls_pemfile::private_key(&mut reader)?
    .ok_or_else(|| CertGenError::ParseError{message:"Get Key Failed".to_string(),context:s.as_ref().to_string()})?;
    Ok(key)
}

/// Loads a certificate from a PEM file.
///
/// This function attempts to load a certificate in PEM format from the specified path and converts it into a `CertificateDer`.
/// It uses the provided file path to open the file and parse the certificate using `rustls_pemfile`.
/// If the file does not exist or the certificate cannot be parsed, an appropriate error is returned.
///
/// # Arguments
/// * `f` - A path that implements `AsRef<Path>`, pointing to a file containing a PEM-formatted certificate.
///
/// # Returns
/// * `Result<CertificateDer<'static>, CertGenError>` - An `Ok` result containing the certificate or an error during certificate generation.
///
/// # Errors
/// * If the file cannot be opened or the certificate cannot be parsed from the file, a `CertGenError` is returned.
///
/// # Examples
/// ```
/// use certgenutil::load_cert_from_pem_file;
/// use std::path::Path;
///
/// let cert = load_cert_from_pem_file(Path::new("ca.pem")).unwrap();
/// assert!(cert.len() > 0);
/// ```
pub fn load_cert_from_pem_file<P: AsRef<std::path::Path>>(f: P) -> Result<CertificateDer<'static>,CertGenError>
{
    let fd = std::fs::File::open(f.as_ref())?;
    let mut reader = std::io::BufReader::new(fd);
    let cert = rustls_pemfile::certs(&mut reader)
    .next()
    .ok_or_else(|| CertGenError::ParseError{message:"Get Certificate Failed".to_string(),context:f.as_ref().to_string_lossy().into_owned()})??;
    Ok(cert)
}

/// Loads a private key from a PEM file.
/// 
/// # Parameters
/// - `f`: A path to the PEM file, implementing `AsRef<Path>`.
/// 
/// # Returns
/// A `Result` where `Ok` contains a static reference to a `PrivateKeyDer`,
/// representing the private key loaded from the PEM file; `Err` contains an error object,
/// which could be a file opening error or other errors.
/// 
/// # Error Handling
/// If the file cannot be opened or if no private key is found in the PEM file,
/// an appropriate error message is returned.
/// 
/// # Examples
/// ```rust
/// use certgenutil::load_key_from_pem_file;
/// let key = load_key_from_pem_file("ca.pem").unwrap();
/// ```
pub fn load_key_from_pem_file<P: AsRef<std::path::Path>>(f: P) -> Result<PrivateKeyDer<'static>,CertGenError>
{
    let fd = std::fs::File::open(f.as_ref())?;
    let mut reader = std::io::BufReader::new(fd);
    let k = rustls_pemfile::private_key(&mut reader)?
    .ok_or_else(|| CertGenError::ParseError{message:"Get Key Failed".to_string(),context:f.as_ref().to_string_lossy().into_owned()})?;
    Ok(k)
}

/// Converts a private key to a PEM formatted string.
///
/// # Arguments
/// * `key` - A DER encoded private key with a static lifetime.
///
/// # Returns
/// A `Result` where `Ok` contains the PEM formatted private key string and `Err` contains a certificate error.
///
/// # Errors
/// Returns a `CertGenError` if the private key type is not supported.
///
/// # Examples
/// ```
/// // this example demonstrates how to call `get_key_pem`.
/// use certgenutil::load_key_from_pem_file;
/// use certgenutil::get_key_pem;
/// let private_key_der = load_key_from_pem_file("ca.pem").unwrap();
/// let pem_string = get_key_pem(&private_key_der).unwrap();
/// assert!(!pem_string.is_empty());
/// println!("{}", pem_string);
/// ```
pub fn get_key_pem(key: &PrivateKeyDer<'static>) -> Result<String, CertGenError> {
    // Set the line ending for the PEM file based on the target operating system family
    let line_ending = if cfg!(target_family = "windows") {
        pem::LineEnding::CRLF
    } else {
        pem::LineEnding::LF
    };

    // Encode the private key based on its type
    let pem_result = match key {
        PrivateKeyDer::Pkcs1(key) => {
            let key_data = key.secret_pkcs1_der();
            let p = pem::Pem::new("RSA PRIVATE KEY", key_data);
            Ok(pem::encode_config(&p, pem::EncodeConfig::new().set_line_ending(line_ending)))
        },
        PrivateKeyDer::Sec1(key) => {
            let key_data = key.secret_sec1_der();
            let p = pem::Pem::new("EC PRIVATE KEY", key_data);
            Ok(pem::encode_config(&p, pem::EncodeConfig::new().set_line_ending(line_ending)))
        },
        PrivateKeyDer::Pkcs8(key) => {
            let key_data = key.secret_pkcs8_der();
            let p = pem::Pem::new("PRIVATE KEY", key_data);
            Ok(pem::encode_config(&p, pem::EncodeConfig::new().set_line_ending(line_ending)))
        },
        _ => return Err(CertGenError::OtherError("Unsupported private key type".to_owned())),
    };

    pem_result
}

/// Converts the given certificate into a PEM formatted string.
///
/// This function takes a CertificateDer object with a static lifetime as input
/// and returns a string containing the PEM formatted certificate.
///
/// # Parameters
/// - `cert`: A reference to a CertificateDer object with a static lifetime, containing the certificate data.
///
/// # Returns
/// Returns a string containing the PEM formatted certificate content.
/// 
/// # Examples
/// ```
/// use certgenutil::get_cert_pem;
/// use certgenutil::load_cert_from_pem_file;
/// let cert_der = load_cert_from_pem_file("ca.pem").unwrap();
/// let pem_string = get_cert_pem(&cert_der);
/// assert!(!pem_string.is_empty());
/// println!("{}", pem_string);
/// ```
pub fn get_cert_pem(cert: &CertificateDer<'static>) -> String
{
	let line_ending = match cfg!(target_family = "windows") {
		true => pem::LineEnding::CRLF,
		false => pem::LineEnding::LF,
	};
	pem::EncodeConfig::new().set_line_ending(line_ending);
    pem::encode_config(&pem::Pem::new("CERTIFICATE", cert.as_ref()), pem::EncodeConfig::new().set_line_ending(line_ending))
}

/// Generates a self-signed certificate.
///
/// # Arguments
/// - `common_name`: The common name of the certificate.
/// - `is_ca`: Whether the certificate is for a Certificate Authority (CA).
/// - `days`: The number of days the certificate is valid.
/// - `subject_alt_names`: Alternative names in the certificate's subject.
///
/// # Returns
/// A result containing the generated certificate and private key, or an error.
///
/// # Examples
/// 
/// ```
/// use certgenutil::generate_self_signed_cert;
/// let (certificates, private_key) = generate_self_signed_cert("example.com", true, 365, vec!["www.example.com".into()]).unwrap();
/// assert!(certificates.len() == 1);
/// assert!(!private_key.secret_der().is_empty());
/// ```
pub fn generate_self_signed_cert(
    common_name: &str,
    is_ca: bool,
    days: usize,
    subject_alt_names: impl Into<Vec<String>>,
) -> Result<(Vec<CertificateDer<'static>>,PrivateKeyDer<'static>), CertGenError>
{
    // Create a distinguished name with the common name.
    let mut distinguished_name = rcgen::DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::CommonName, common_name);

    // Set up the certificate parameters.
    let mut certificate_params = rcgen::CertificateParams::new(subject_alt_names.into())?;

    if is_ca {
        // Configure the certificate as a CA.
        certificate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        certificate_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
    }

    // Generate the key pair.
    let key_pair = rcgen::KeyPair::generate()?;

    // Set the distinguished name and validity period.
    certificate_params.distinguished_name = distinguished_name;
    certificate_params.not_before = time::OffsetDateTime::now_utc();
    certificate_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days as i64);

    // Generate the self-signed certificate.
    let certificate = certificate_params.self_signed(&key_pair)?;

    // Serialize the key pair and the certificate.
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())?;
    Ok((vec![CertificateDer::try_from(certificate)?],key_der))
}

/// Generates a server certificate using a CA certificate file.
///
/// # Arguments
/// * `cafile` - A path to the CA certificate file.
/// * `common_name` - The common name for the certificate.
/// * `days` - The validity period of the certificate in days.
/// * `subject_alt_names` - Subject alternative names for the certificate's alternate name list.
///
/// # Returns
/// Returns a `Result` containing the generated server certificate and private key on success, or a `CertGenError` on failure.
///
/// # Error Handling
/// If loading the CA key or certificate fails, or if there is an error generating the certificate, a `CertGenError` is returned.
///
/// # Examples
/// 
/// ```
/// use std::path::PathBuf;
/// use certgenutil::{generate_server_cert_by_ca_file, CertGenError};
///
/// // Example usage:
/// let ca_file_path = PathBuf::from("ca.pem");
/// let (cert, private_key) = generate_server_cert_by_ca_file(
///     ca_file_path,
///     "example.com",
///     365,
///     vec!["www.example.com".to_string(), "mail.example.com".to_string()],
/// ).unwrap();
/// assert!(cert.len() > 0);
/// assert!(private_key.secret_der().len() > 0);
/// ```
pub fn generate_server_cert_by_ca_file<P: AsRef<std::path::Path>>(cafile: P,
    common_name: &str,
    days: usize,
    subject_alt_names: impl Into<Vec<String>>) -> Result<(Vec<CertificateDer<'static>>,PrivateKeyDer<'static>),CertGenError>
{
    // Load the CA certificate and private key from the provided file.
    let ca_key = load_key_from_pem_file(cafile.as_ref())?;
    let ca_crt = load_cert_from_pem_file(cafile.as_ref())?;

    // prepare CA certificate for signing the server certificate.
    let ca_key_pair = rcgen::KeyPair::try_from(ca_key.secret_der())?;
    let ca_cert_params = rcgen::CertificateParams::from_ca_cert_der(&ca_crt.into())?;
    let ca_cert_for_sign = ca_cert_params.self_signed(&ca_key_pair)?;

    // Create the parameters for the server certificate
    let mut server_cert_params = rcgen::CertificateParams::new(subject_alt_names.into())?;
    let server_cert_key = rcgen::KeyPair::generate()?;

    // Create a distinguished name with the common name.
    let mut distinguished_name = rcgen::DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::CommonName, common_name);

    // Set the distinguished name and the validity period for the server certificate.
    server_cert_params.distinguished_name = distinguished_name;
    server_cert_params.not_before = time::OffsetDateTime::now_utc();
    server_cert_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days as i64);

    // Generate the server certificate signed by the CA.
    let server_signed_cert = server_cert_params.signed_by(&server_cert_key, &ca_cert_for_sign, &ca_key_pair)?;

    // Serialize the server key pair into DER format.
    let server_key_der = PrivateKeyDer::try_from(server_cert_key.serialize_der())?;
    
    Ok((vec![CertificateDer::try_from(server_signed_cert)?],server_key_der))
}

/// Generates a server certificate signed by a CA based on the provided CA certificate PEM.
///
/// # Parameters
/// - `s`: The PEM content of the CA certificate.
/// - `common_name`: The common name of the server certificate.
/// - `days`: The number of days the server certificate is valid for.
/// - `subject_alt_names`: Alternative names for the server.
///
/// # Returns
/// A result containing the generated server certificate and private key, or an error.
///
/// # Examples
/// 
/// ```
/// use certgenutil::generate_server_cert_by_ca_pem;
/// let ca_pem = String::from(r#"-----BEGIN CERTIFICATE-----
/// MIIBejCCASCgAwIBAgIUNcB9KoFex2HVOvNXIZzfN/7QyMUwCgYIKoZIzj0EAwIw
/// ETEPMA0GA1UEAwwGcm9vdGNhMB4XDTI0MDgxODA0NDEwOFoXDTI1MDgxODA0NDEw
/// OFowETEPMA0GA1UEAwwGcm9vdGNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
/// 0kzg73SoZ82snyWboqjKbrlgvavvzduYSWmn2x6NBejWlPLLxdtMxiY0NVfSXq+I
/// 9eBqzr88yV7QC79yH+GxyKNWMFQwEgYDVR0RBAswCYIHYWJjLmNvbTAOBgNVHQ8B
/// Af8EBAMCAQYwHQYDVR0OBBYEFP/KV01ye89Wwfde0wic7i+StpidMA8GA1UdEwEB
/// /wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgfQlSU05caJtz8XxJvA/AmHSQkroy
/// YUloxc/s1mQKR9ICIQD9twx295ClByM7bjsHsGNnORok3szuCuJiQaX9o5DR1w==
/// -----END CERTIFICATE-----
/// -----BEGIN PRIVATE KEY-----
/// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSnXLALeEZnbLdbRT
/// T4IumE9TztYMJTF97pMQFpF0zByhRANCAATSTODvdKhnzayfJZuiqMpuuWC9q+/N
/// 25hJaafbHo0F6NaU8svF20zGJjQ1V9Jer4j14GrOvzzJXtALv3If4bHI
/// -----END PRIVATE KEY-----"#);
/// 
/// let (certs, private_key) = generate_server_cert_by_ca_pem(
///     ca_pem,
///     "example.com",
///     365,
///     vec!["www.example.com".to_string(), "mail.example.com".to_string()],
/// ).unwrap();
/// ```
pub fn generate_server_cert_by_ca_pem<T: AsRef<str>>(s: T,
    common_name: &str,
    days: usize,
    subject_alt_names: impl Into<Vec<String>>) -> Result<(Vec<CertificateDer<'static>>,PrivateKeyDer<'static>),CertGenError>
{
    // Load the CA certificate and private key from the provided file.
    let ca_key = load_key_from_pem_str(s.as_ref())?;
    let ca_crt = load_cert_from_pem_str(s.as_ref())?;

    // Prepare CA certificate for signing the server certificate.
    let ca_key_pair = rcgen::KeyPair::try_from(ca_key.secret_der())?;
    let ca_cert_params = rcgen::CertificateParams::from_ca_cert_der(&ca_crt.into())?;
    let ca_cert_for_sign = ca_cert_params.self_signed(&ca_key_pair)?;

    // Create the parameters for the server certificate
    let mut server_cert_params = rcgen::CertificateParams::new(subject_alt_names.into())?;
    let server_cert_key = rcgen::KeyPair::generate()?;

    // Create a distinguished name with the common name.
    let mut distinguished_name = rcgen::DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::CommonName, common_name);

    // Set the distinguished name and the validity period for the server certificate.
    server_cert_params.distinguished_name = distinguished_name;
    server_cert_params.not_before = time::OffsetDateTime::now_utc();
    server_cert_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days as i64);

    // Generate the server certificate signed by the CA.
    let server_signed_cert = server_cert_params.signed_by(&server_cert_key, &ca_cert_for_sign, &ca_key_pair)?;

    // Serialize the server key pair into DER format.
    let server_der = PrivateKeyDer::try_from(server_cert_key.serialize_der())?;
    
    Ok((vec![CertificateDer::try_from(server_signed_cert)?],server_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    static INVALID_PEM_STR:&str = r#"-----BEGIN CERTIFICATE-----
MIIDMTCCAhkCFBsvm7O2J59B4p722qsQSA4WTFgiMA0GCSqGSIb3DQEBCwUAMFUx
-----END CERTIFICATE-----"#;

    static PEM_STR:&str = r#"-----BEGIN CERTIFICATE-----
MIIDWTCCAkECFAjp6kYnQymepABi3auFdKobkMzVMA0GCSqGSIb3DQEBCwUAMGkx
CzAJBgNVBAYTAkNOMQswCQYDVQQIDAJCSjELMAkGA1UEBwwCQkoxFDASBgNVBAoM
C0NlcnRHZW5VdGlsMRQwEgYDVQQLDAtDZXJ0R2VuVXRpbDEUMBIGA1UEAwwLQ2Vy
dEdlblV0aWwwHhcNMjQwODE4MDMxOTQ2WhcNMjUwODE4MDMxOTQ2WjBpMQswCQYD
VQQGEwJDTjELMAkGA1UECAwCQkoxCzAJBgNVBAcMAkJKMRQwEgYDVQQKDAtDZXJ0
R2VuVXRpbDEUMBIGA1UECwwLQ2VydEdlblV0aWwxFDASBgNVBAMMC0NlcnRHZW5V
dGlsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzLV9R17sMeisx6a6
90D6J1iw2wLBRfohBFFd+i0QrLjN1Lfm+L+ErV5OPZDXFvFS7MGnzYfiO4s3jxBW
4Io7qmJFZfvSDOiruA+vg7OuvcXh18JQeSpBv7YNLQYj4CS4KJtP7/NCFAwqS2sv
/7M04llCH8yk3RZdYCxekET0PV6puJw5855M53HteVdd4k4Ww1KkZRfZXkstBOzj
TDQ3jhT5KHEwWt6uCxKtCqObeGc7/Ve7TfMP7Pne2jNY0GhjQZt7bPaQYN23Tjj6
KCi4BTLT++rYMFkU1ra6Cj7pnhAmLC4pqpyBfJm9rdbq4wIHjemgg5m/stKtEw8j
7zcyYwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQC6X/v/jY880wQ93Yfkb2xSecze
Wqf62XyIgYXS+6z6BoL9zY81FNALXNEvFfQ7A0j97sj1peCboLJ26qXFKgm5Fkr3
dAwIcXXwY5IxkcxvOuYgwhe5PCaSXhTnLkj8DVZEgoBag9bkhbW6LdGVMHbznCcm
4Kh+Wcx52FXkNlrCj0w9yAydgvFR0r0k/4gLPFuUAXEq5NB4eDxJoPb4rbPVcmWw
pqMWe9KG1rmC4lz81Mb946KWf/VyFt+STJjjy6a5EgV7fj1wWDqGP3/c1GRj/xrx
G6B55bGMKvuYYWvRyfKafbk9ao3Uyqyjxl+Fiqt+H5BEPKdrlShRKGUBdXbT
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzLV9R17sMeisx6a690D6J1iw2wLBRfohBFFd+i0QrLjN1Lfm
+L+ErV5OPZDXFvFS7MGnzYfiO4s3jxBW4Io7qmJFZfvSDOiruA+vg7OuvcXh18JQ
eSpBv7YNLQYj4CS4KJtP7/NCFAwqS2sv/7M04llCH8yk3RZdYCxekET0PV6puJw5
855M53HteVdd4k4Ww1KkZRfZXkstBOzjTDQ3jhT5KHEwWt6uCxKtCqObeGc7/Ve7
TfMP7Pne2jNY0GhjQZt7bPaQYN23Tjj6KCi4BTLT++rYMFkU1ra6Cj7pnhAmLC4p
qpyBfJm9rdbq4wIHjemgg5m/stKtEw8j7zcyYwIDAQABAoIBAHel6Ghrub/eEAbN
k9/qcYvH0e7gaFjfPqcIa9ZKusFJbrzTFEP1pLW0NiTT4HO/b0mEUvDVaEyHLV0I
Hs803HTU5V0bV4VGBQAa4uomfo7a9wqlv2ViZnWIEaFsQlHDBIRvasSDuO6AwcO9
DZv1gYZ+xyBQ+1dhuAf7RvYp51tqSdyRiHF9XTAGe92qx85LFRrBEb6C7AyxxsDq
GW7GaYhYregpbVeMMC4qQAXKohAgnadp2KwWAdb4M6cjvKDgG6GF95PVO6HW07RV
L0wD4NmF7K8c+h44csP/0d61m13y+qdAJOi1N6bN9bYkKRHMb+2Bk8vPuGry09ja
Gq0YFqECgYEA8lx1RdmBM7iqMiZeW6tkYHRmRbCBnbYUozHOZTnbDYldckf9mtIY
G7qsBT+nxNOv49vFEnASa08nnefS8jyDWH6Ttq3HwIXFh5IDZXOh/h+8DtKDHuwP
oMu6Pqcg8/5ihknVd6C25Y5E7pCILrOPg63UvXHC03vWy/fgotexp9ECgYEA2DqZ
kEuA+Wo1nGgYDj5n0kxzCi+PWi6L6cwpsqfrW2pjE4TjsQJTgIOr8F2RlU2pt/s9
y7hVW+PasnVrDG/ykMF7hw/sgvA6+b9Kfr4rQQxLe0/nFXrwOCNt80KdCj6P9CvQ
9WZN/5BhppSHsBvsHHJMyjnC86fIBOB2oDbXN/MCgYBoT9ENujq4tx9RrF/qVo9C
UHcAQaLX7Vlej/5EZS1Z2yiEGmYVr50+ug51x9r+hRnsGVftwpy64PutI+0P42mo
ufn7ozoZK7pDyl152dX8GU6IlqRmt7VWQLktZCNzwKZJJBgjf+GYVa5ne3+RkikP
xM6OpxryiRd+/HYLwIgvMQKBgQCF5NOOnJKC35fPAE5VE6Oqf5iE6Cp2h3gwEDKJ
5J1DAD/VqGZuB6i5Xc+sieRKdcrwmG0Np1mECzYzZ64gB3pG1OivG9cyxZtfZ2qz
zQJvxzM+ap4HmRcDTD0bc1ZXL6JoanF8ZBtMc5VkV3kmPkQY4VZXqyjjRDQBgRUz
5IGkrQKBgQCtVQwyh+cvGZ1Fo8qTLhcaQllH3GRuRNLExLDBh8WurrkE6uf8RnhO
yO5ZxuYVXNE9U7zKmgJTg4SkieFrreJYBeSET1o6NQTTDp4tMCZwJo8jOf4w1bmx
OEa6ZFEk4oIiYRARa+/BBkIBsETm+QuJkKSW1pYOKVmsJ9Sq7R7Hig==
-----END RSA PRIVATE KEY-----"#;

    #[test]
    fn read_from_pem_str()
    {
        use std::io::BufRead;
        let cursor = std::io::Cursor::new(PEM_STR);
        let reader = std::io::BufReader::new(cursor);
        for line in reader.lines() {
            println!("{:?}", line);
        }
    }

    #[test]
    fn load_cert_from_pem_str_valid_pem() {
        let valid_pem = PEM_STR;
    
        let cert = load_cert_from_pem_str(valid_pem).unwrap();
    
        assert!(!cert.is_empty(), "Expected a non-empty certificate.");
    }

    #[test]
    #[should_panic]
    fn load_cert_from_pem_str_invalid_pem() {
        let invalid_pem = INVALID_PEM_STR;

        assert!(load_cert_from_pem_str(invalid_pem).is_err(), "Expected an error when loading an invalid PEM string.");
    }

    #[test]
    fn load_cert_from_pem_file_valid_file()  {

        let valid_pem_path = std::path::Path::new("valid_certificate.pem");

        std::fs::write(valid_pem_path, PEM_STR).unwrap();
    
        assert!(valid_pem_path.exists(), "save PEM file does not exist");
    
        let cert = load_cert_from_pem_file(valid_pem_path).unwrap();
    
        assert!(!cert.is_empty(), "Expected a non-empty certificate.");
    }

    #[test]
    fn load_cert_from_pem_file_nonexistent_file() {
        let nonexistent_pem_path = std::path::Path::new("nonexistent_certificate.pem");
    
        assert!(load_cert_from_pem_file(nonexistent_pem_path).is_err(), "Expected an error when loading a nonexistent PEM file.");
    }

    #[test]
    fn load_key_from_valid_pem_str() {
        let valid_pem = PEM_STR;
    
        let key = load_key_from_pem_str(valid_pem).unwrap();

        assert!(!key.secret_der().is_empty(), "Expected a non-empty private key.");
    }

    #[test]
    fn load_key_from_pem_str_invalid_pem() {

        let invalid_pem =  INVALID_PEM_STR;
    
        assert!(load_key_from_pem_str(invalid_pem).is_err(), "Expected an error when loading an invalid PEM string.");
    }

    #[test]
    fn load_key_from_pem_file_valid_file() -> Result<(), Box<dyn std::error::Error>> {

        let valid_pem_path = std::path::Path::new("valid_private_key.pem");

        std::fs::write(valid_pem_path, PEM_STR).unwrap();
    
        assert!(valid_pem_path.exists(), "save PEM file does not exist");

        let key = load_key_from_pem_file(valid_pem_path)?;
    
        assert!(!key.secret_der().is_empty(), "Expected a non-empty private key.");
    
        Ok(())
    }
    
    #[test]
    fn load_key_from_pem_file_nonexistent_file() {

        let nonexistent_pem_path = std::path::Path::new("nonexistent_private_key.pem");
    
        assert!(load_key_from_pem_file(nonexistent_pem_path).is_err(), "Expected an error when loading a nonexistent PEM file.");
    }

    #[test]
    fn test_generate_server_cert_by_ca_file() {

        // Create a temporary CA file
        let (ca_cert, ca_key) = generate_self_signed_cert("rootca",true,365,vec!["abc.com".into()]).unwrap();
        let cert_str = get_cert_pem(&ca_cert[0]);
        let key_str = get_key_pem(&ca_key).unwrap();
        let cafile_path = std::path::Path::new("ca.pem");
        std::fs::write(cafile_path, cert_str+&key_str).unwrap();

        // Define common name and subject alternative names for the server certificate
        let common_name = "server.example.com";
        let subject_alt_names = vec!["server.example.com".to_string(), "localhost".to_string()];

        // Generate the server certificate and private key
        let result = generate_server_cert_by_ca_file(cafile_path, common_name, 365, subject_alt_names);
        assert!(result.is_ok());

        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

//     #[test]
//     fn test()
//     {use certgenutil::
//         use certgenutil::generate_self_signed_cert;
//         let (cert, private_key) = generate_self_signed_cert(
//         "example.com",
//         true,
//         365,
//         vec!["www.example.com".to_string(), "mail.example.com".to_string()],
//         ).unwrap();
//    }
}    

