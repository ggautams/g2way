//! Library portion of the g2way gateway binary.
//!
//! The binary (`main.rs`) only parses CLI flags and wires configuration;
//! everything runnable lives here so integration tests can start a real
//! gateway in-process on an ephemeral port.

pub mod reload;
pub mod server;
