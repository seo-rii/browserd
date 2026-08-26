//! Shared launch-approval protocol for the fail-closed Chromium exec gate.

use std::io::{self, Read};

/// The complete one-shot frame required before the launch gate may execute Chromium.
pub const APPROVAL_FRAME: &[u8] = b"browserd-launch-gate/v1 approve\n";

/// Accepts exactly one complete approval frame followed immediately by EOF.
///
/// EOF before the complete frame, a mismatched byte, and any trailing byte all fail closed.
pub fn validate_approval(reader: &mut impl Read) -> io::Result<()> {
    let mut received = [0_u8; APPROVAL_FRAME.len()];
    reader.read_exact(&mut received)?;
    if received != APPROVAL_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid launch approval frame",
        ));
    }

    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing launch approval data",
        ));
    }
    Ok(())
}
