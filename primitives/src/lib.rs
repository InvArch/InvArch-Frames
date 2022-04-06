#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

#[derive(Encode, Decode, Clone, Eq, PartialEq, MaxEncodedLen, Debug, TypeInfo)]
pub enum Parentage<AccountId, IpsId> {
    /// Parent IP (Account Id of itself)
    Parent(AccountId),
    /// Child IP (Id of the immediate parent, Account Id of the topmost parent)
    Child(IpsId, AccountId),
}

#[derive(Encode, Decode, Clone, Eq, PartialEq, MaxEncodedLen, Debug, TypeInfo)]
pub enum IpsType<IpsId> {
    /// Normal IPS
    Normal,
    /// IP Replica (Id of the original IP)
    Replica(IpsId),
}

/// IPS info
#[derive(Encode, Decode, Clone, Eq, PartialEq, MaxEncodedLen, Debug, TypeInfo)]
pub struct IpsInfo<AccountId, Data, IpsMetadataOf, IpsId> {
    /// IPS parentage
    pub parentage: Parentage<AccountId, IpsId>,
    /// IPS metadata
    pub metadata: IpsMetadataOf,
    /// IPS Properties
    pub data: Data,
    /// IPS Type
    pub ips_type: IpsType<IpsId>,
    /// If this IPS allows replicas
    pub allow_replica: bool,
}

/// IPF Info
#[derive(Encode, Decode, Clone, Eq, PartialEq, MaxEncodedLen, Debug, TypeInfo)]
pub struct IpfInfo<AccountId, Data, IpfMetadataOf> {
    /// IPF owner
    pub owner: AccountId,
    /// Original IPF author
    pub author: AccountId,
    /// IPF metadata
    pub metadata: IpfMetadataOf,
    /// IPF data
    pub data: Data,
}

#[derive(Encode, Decode, Clone, Eq, PartialEq, MaxEncodedLen, Debug, TypeInfo)]
pub enum AnyId<IpsId, IpfId> {
    IpsId(IpsId),
    IpfId(IpfId),
}

#[cfg(feature = "utils")]
pub mod utils {
    use codec::{Decode, Encode};
    use sp_io::hashing::blake2_256;
    // use sp_runtime::traits::TrailingZeroInput;

    struct TrailingZeroInput<'a>(&'a [u8]);

    impl<'a> TrailingZeroInput<'a> {
        /// Create a new instance from the given byte array.
        fn new(data: &'a [u8]) -> Self {
            Self(data)
        }
    }

    impl<'a> codec::Input for TrailingZeroInput<'a> {
        fn remaining_len(&mut self) -> Result<Option<usize>, codec::Error> {
            Ok(None)
        }

        fn read(&mut self, into: &mut [u8]) -> Result<(), codec::Error> {
            let len_from_inner = into.len().min(self.0.len());
            into[..len_from_inner].copy_from_slice(&self.0[..len_from_inner]);
            for i in &mut into[len_from_inner..] {
                *i = 0;
            }
            self.0 = &self.0[len_from_inner..];

            Ok(())
        }
    }

    pub fn multi_account_id<T: frame_system::Config, IpsId: Encode>(
        ips_id: IpsId,
        original_caller: Option<T::AccountId>,
    ) -> <T as frame_system::Config>::AccountId
    where
        <T as frame_system::Config>::AccountId: Encode + Decode,
    {
        let entropy = if let Some(original_caller) = original_caller {
            (b"modlpy/utilisuba", ips_id, original_caller).using_encoded(blake2_256)
        } else {
            (b"modlpy/utilisuba", ips_id).using_encoded(blake2_256)
        };

        Decode::decode(&mut TrailingZeroInput::new(entropy.as_ref()))
            .expect("infinite length input; no invalid inputs for type; qed")
    }
}
