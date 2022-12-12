#![cfg_attr(not(feature = "std"), no_std)]
#![feature(specialization)]

use codec::{self, Decode, Encode};
use frame_support::BoundedVec;
use frame_system::ensure_signed;
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{Bounded, DispatchInfoOf, SaturatedConversion, Saturating, SignedExtension},
    transaction_validity::{
        InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
    },
};
use sp_std::{marker::PhantomData, prelude::*};

pub use pallet::*;

mod traits;
pub use traits::*;

extern crate alloc;

use alloc::string::String;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{dispatch::Dispatchable, pallet_prelude::*};
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        type Call: Parameter + Dispatchable + Encode + Rule;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(1_000_000_000)]
        pub fn new_rule(
            origin: OriginFor<T>,
            rule: <<T as Config>::Call as Rule>::CallRule,
        ) -> DispatchResultWithPostInfo {
            let origin = ensure_signed(origin)?;

            Self::deposit_event(Event::EvalResult { result: false });

            Ok(().into())
        }

        #[pallet::weight(1_000_000_000)]
        pub fn check_rule(
            origin: OriginFor<T>,
            call: Box<<T as Config>::Call>,
            rule: Box<<<T as Config>::Call as Rule>::CallRule>,
        ) -> DispatchResultWithPostInfo {
            let origin = ensure_signed(origin)?;

            Self::deposit_event(Event::EvalResult {
                result: call.check_rule(*rule),
            });

            Ok(().into())
        }
    }

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        EvalResult { result: bool },
    }
}

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub enum V {
    String(Vec<u8>),
    Boolean(bool),
    Int(i64),
    Empty,

    Vec(Vec<Box<V>>),
}

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Eq(Box<Instruction>, Box<Instruction>),
    Not(Box<Instruction>, Box<Instruction>),
    Gt(Box<Instruction>, Box<Instruction>),
    Lt(Box<Instruction>, Box<Instruction>),
    And(Box<Instruction>, Box<Instruction>),
    Or(Box<Instruction>, Box<Instruction>),
    Data(V),
    Variable(Vec<u8>),
}
