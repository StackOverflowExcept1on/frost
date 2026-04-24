use core::fmt::{self, Debug};

use alloc::{string::ToString, vec::Vec};

#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use crate::{serialization::SerializableElement, Challenge, Ciphersuite, Error, Group, Signature};

/// A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct VerifyingKey<C>
where
    C: Ciphersuite,
{
    pub(crate) element: SerializableElement<C>,
}

impl<C> VerifyingKey<C>
where
    C: Ciphersuite,
{
    /// Create a new VerifyingKey from the given element.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn new(element: <C::Group as Group>::Element) -> Self {
        Self {
            element: SerializableElement(element),
        }
    }

    /// Return the underlying element.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn to_element(self) -> <C::Group as Group>::Element {
        self.element.0
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<VerifyingKey<C>, Error<C>> {
        Ok(Self::new(SerializableElement::deserialize(bytes)?.0))
    }

    /// Serialize `VerifyingKey` to bytes
    pub fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        self.element.serialize()
    }

    /// Verify a purported `signature` with a pre-hashed [`Challenge`] made by this verification
    /// key.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn verify_prehashed(
        &self,
        challenge: Challenge<C>,
        signature: &Signature<C>,
    ) -> Result<(), Error<C>> {
        // Verify check is h * ( - z * B + R  + c * A) == 0
        //                 h * ( z * B - c * A - R) == 0
        //
        // where h is the cofactor
        let zB = C::Group::generator() * signature.z;
        let cA = self.element.0 * challenge.0;
        let check = (zB - cA - signature.R) * C::Group::cofactor();

        if check == C::Group::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify a purported `signature` over `msg` made by this verification key.
    pub fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<(), Error<C>> {
        C::verify_signature(msg, signature, self)
    }

    /// Computes the group public key given the group commitment.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    pub(crate) fn from_commitment(
        commitment: &crate::keys::VerifiableSecretSharingCommitment<C>,
    ) -> Result<VerifyingKey<C>, Error<C>> {
        Ok(VerifyingKey::new(
            commitment
                .coefficients()
                .first()
                .ok_or(Error::IncorrectCommitment)?
                .value(),
        ))
    }
}

#[cfg(feature = "codec")]
impl<C> parity_scale_codec::Encode for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn encode(&self) -> Vec<u8> {
        let tmp = self
            .serialize()
            .expect("Could not serialize `VerifyingKey<C>`");
        let compact_len = parity_scale_codec::Compact(tmp.len() as u32);

        let mut output = Vec::with_capacity(compact_len.size_hint() + tmp.len());

        compact_len.encode_to(&mut output);
        output.extend(tmp);

        output
    }
}

#[cfg(feature = "codec")]
impl<C> parity_scale_codec::Decode for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let input: Vec<u8> = parity_scale_codec::Decode::decode(input)?;
        Self::deserialize(&input).map_err(|_| "Could not decode `VerifyingKey<C>`".into())
    }
}

#[cfg(feature = "codec")]
impl<C> scale_info::TypeInfo for VerifyingKey<C>
where
    C: Ciphersuite,
{
    type Identity = Self;

    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new_with_replace(
                "VerifyingKey",
                module_path!(),
                &[],
            ))
            .type_params(scale_info::prelude::vec![])
            .docs(&[
                "A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].",
            ])
            .composite(
                scale_info::build::Fields::unnamed()
                    .field(|f| f.ty::<Vec<u8>>().type_name("Vec<u8>")),
            )
    }
}

impl<C> Debug for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(
                &self
                    .serialize()
                    .map(hex::encode)
                    .unwrap_or("<invalid>".to_string()),
            )
            .finish()
    }
}

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for VerifyingKey<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        Self::deserialize(&v).map_err(|_| "malformed verifying key encoding")
    }
}
