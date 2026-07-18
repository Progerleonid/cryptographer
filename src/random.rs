use crate::error::VaultError;

pub trait RandomSource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), VaultError>;
}

pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), VaultError> {
        getrandom::fill(destination).map_err(|_| VaultError::RandomFailure)
    }
}

pub fn random_array<const N: usize>(source: &mut impl RandomSource) -> Result<[u8; N], VaultError> {
    let mut value = [0_u8; N];
    source.fill(&mut value)?;
    Ok(value)
}
