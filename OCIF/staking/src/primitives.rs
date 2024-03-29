//! Provides supporting types and traits for the staking pallet.
//!
//! ## Overview
//!
//! Primitives provides the foundational types and traits for a staking pallet.  
//!
//! ## Types overview:
//!
//! - `BalanceOf` - A type alias for the balance of a currency in the system.
//! - `CoreMetadata` - A struct that holds metadata for a core entity in the system.
//! - `CoreInfo` - A struct that holds information about a core entity, including its account ID and metadata.
//! - `RewardInfo` - A struct that holds information about rewards, including the balance for stakers and the core.
//! - `EraInfo` - A struct that holds information about a specific era, including rewards, staked balance, active stake, and locked balance.
//! - `CoreStakeInfo` - A struct that holds information about a core's stake, including the total balance,
//! number of stakers, and whether a reward has been claimed.
//! - `EraStake` - A struct that holds information about the stake for a specific era.
//! - `StakerInfo` - A struct that holds information about a staker's stakes across different eras.
//! - `UnlockingChunk` - A struct that holds information about an unlocking chunk of balance.
//! - `UnbondingInfo` - A struct that holds information about unbonding chunks of balance.
//! - `AccountLedger` - A struct that holds information about an account's locked balance and unbonding information.

use codec::{Decode, Encode, HasCompact, MaxEncodedLen};
use frame_support::traits::Currency;
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{AtLeast32BitUnsigned, Zero},
    RuntimeDebug,
};
use sp_std::{ops::Add, prelude::*};

pub use crate::pallet::*;

/// The balance type of this pallet.
pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

const MAX_ASSUMED_VEC_LEN: u32 = 10;

/// Metadata for a core entity in the system.
#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct CoreMetadata<Name, Description, Image> {
    pub name: Name,
    pub description: Description,
    pub image: Image,
}

/// Information about a core entity, including its account ID and metadata.
#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct CoreInfo<AccountId, Metadata> {
    pub account: AccountId,
    pub metadata: Metadata,
}

/// Information about rewards, including the balance for stakers and the core.
#[derive(PartialEq, Eq, Clone, Default, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct RewardInfo<Balance: HasCompact + MaxEncodedLen> {
    #[codec(compact)]
    pub(crate) stakers: Balance,
    #[codec(compact)]
    pub(crate) core: Balance,
}

/// Information about a specific era, including rewards, staked balance, active stake, and locked balance.
#[derive(PartialEq, Eq, Clone, Default, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct EraInfo<Balance: HasCompact + MaxEncodedLen> {
    pub(crate) rewards: RewardInfo<Balance>,
    #[codec(compact)]
    pub(crate) staked: Balance,
    #[codec(compact)]
    pub(crate) active_stake: Balance,
    #[codec(compact)]
    pub(crate) locked: Balance,
}

/// Information about a core's stake, including the total balance, number of stakers, and whether a reward has been claimed.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Default, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct CoreStakeInfo<Balance: HasCompact + MaxEncodedLen> {
    #[codec(compact)]
    pub(crate) total: Balance,
    #[codec(compact)]
    pub(crate) number_of_stakers: u32,
    pub(crate) reward_claimed: bool,
    pub(crate) active: bool,
}

/// Information about the stake for a specific era.
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub(crate) struct EraStake<Balance: AtLeast32BitUnsigned + Copy + MaxEncodedLen> {
    #[codec(compact)]
    pub(crate) staked: Balance,
    #[codec(compact)]
    pub(crate) era: Era,
}

/// Information about a staker's stakes across different eras.
#[derive(Encode, Decode, Clone, Default, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct StakerInfo<Balance: AtLeast32BitUnsigned + Copy + MaxEncodedLen> {
    pub(crate) stakes: Vec<EraStake<Balance>>,
}

impl<Balance: AtLeast32BitUnsigned + Copy + MaxEncodedLen> MaxEncodedLen for StakerInfo<Balance> {
    fn max_encoded_len() -> usize {
        codec::Compact(MAX_ASSUMED_VEC_LEN)
            .encoded_size()
            .saturating_add(
                (MAX_ASSUMED_VEC_LEN as usize)
                    .saturating_mul(EraStake::<Balance>::max_encoded_len()),
            )
    }
}

impl<Balance: AtLeast32BitUnsigned + Copy + MaxEncodedLen> StakerInfo<Balance> {
    pub(crate) fn is_empty(&self) -> bool {
        self.stakes.is_empty()
    }

    pub(crate) fn len(&self) -> u32 {
        self.stakes.len() as u32
    }

    /// Stakes the given value in the current era, mutates StakerInfo in-place.
    pub(crate) fn stake(&mut self, current_era: Era, value: Balance) -> Result<(), &str> {
        if let Some(era_stake) = self.stakes.last_mut() {
            if era_stake.era > current_era {
                return Err("Unexpected era");
            }

            let new_stake_value = era_stake.staked.saturating_add(value);

            if current_era == era_stake.era {
                *era_stake = EraStake {
                    staked: new_stake_value,
                    era: current_era,
                }
            } else {
                self.stakes.push(EraStake {
                    staked: new_stake_value,
                    era: current_era,
                })
            }
        } else {
            self.stakes.push(EraStake {
                staked: value,
                era: current_era,
            });
        }

        Ok(())
    }

    /// Unstakes the given value in the current era, mutates StakerInfo in-place.
    pub(crate) fn unstake(&mut self, current_era: Era, value: Balance) -> Result<(), &str> {
        if let Some(era_stake) = self.stakes.last_mut() {
            if era_stake.era > current_era {
                return Err("Unexpected era");
            }

            let new_stake_value = era_stake.staked.saturating_sub(value);
            if current_era == era_stake.era {
                *era_stake = EraStake {
                    staked: new_stake_value,
                    era: current_era,
                }
            } else {
                self.stakes.push(EraStake {
                    staked: new_stake_value,
                    era: current_era,
                })
            }

            if !self.stakes.is_empty() && self.stakes[0].staked.is_zero() {
                self.stakes.remove(0);
            }
        }

        Ok(())
    }

    /// Claims the stake for the current era, mutates StakerInfo in-place.  
    /// Returns the era and the staked balance.
    pub(crate) fn claim(&mut self) -> (Era, Balance) {
        if let Some(era_stake) = self.stakes.first() {
            let era_stake = *era_stake;

            if self.stakes.len() == 1 || self.stakes[1].era > era_stake.era + 1 {
                self.stakes[0] = EraStake {
                    staked: era_stake.staked,
                    era: era_stake.era.saturating_add(1),
                }
            } else {
                self.stakes.remove(0);
            }

            if !self.stakes.is_empty() && self.stakes[0].staked.is_zero() {
                self.stakes.remove(0);
            }

            (era_stake.era, era_stake.staked)
        } else {
            (0, Zero::zero())
        }
    }

    /// Returns the latest staked balance.
    pub(crate) fn latest_staked_value(&self) -> Balance {
        self.stakes.last().map_or(Zero::zero(), |x| x.staked)
    }
}

/// A chunk of balance that is unlocking until a specific era.
#[derive(
    Clone, PartialEq, Eq, Copy, Encode, Decode, Default, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
pub(crate) struct UnlockingChunk<Balance: MaxEncodedLen> {
    #[codec(compact)]
    pub(crate) amount: Balance,
    #[codec(compact)]
    pub(crate) unlock_era: Era,
}

impl<Balance> UnlockingChunk<Balance>
where
    Balance: Add<Output = Balance> + Copy + MaxEncodedLen,
{
    /// Adds the given amount to the chunk's amount.
    pub(crate) fn add_amount(&mut self, amount: Balance) {
        self.amount = self.amount + amount
    }
}

/// Information about unbonding chunks of balance.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Default, RuntimeDebug, TypeInfo)]
pub(crate) struct UnbondingInfo<Balance: AtLeast32BitUnsigned + Default + Copy + MaxEncodedLen> {
    pub(crate) unlocking_chunks: Vec<UnlockingChunk<Balance>>,
}

impl<Balance: AtLeast32BitUnsigned + Default + Copy + MaxEncodedLen> MaxEncodedLen
    for UnbondingInfo<Balance>
{
    fn max_encoded_len() -> usize {
        codec::Compact(MAX_ASSUMED_VEC_LEN)
            .encoded_size()
            .saturating_add(
                (MAX_ASSUMED_VEC_LEN as usize)
                    .saturating_mul(UnlockingChunk::<Balance>::max_encoded_len()),
            )
    }
}

impl<Balance> UnbondingInfo<Balance>
where
    Balance: AtLeast32BitUnsigned + Default + Copy + MaxEncodedLen,
{
    pub(crate) fn len(&self) -> u32 {
        self.unlocking_chunks.len() as u32
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.unlocking_chunks.is_empty()
    }

    /// Returns the total amount of the unlocking chunks.
    pub(crate) fn sum(&self) -> Balance {
        self.unlocking_chunks
            .iter()
            .map(|chunk| chunk.amount)
            .reduce(|c1, c2| c1 + c2)
            .unwrap_or_default()
    }

    /// Adds the given chunk to the unbonding info.
    pub(crate) fn add(&mut self, chunk: UnlockingChunk<Balance>) {
        match self
            .unlocking_chunks
            .binary_search_by(|x| x.unlock_era.cmp(&chunk.unlock_era))
        {
            Ok(pos) => self.unlocking_chunks[pos].add_amount(chunk.amount),
            Err(pos) => self.unlocking_chunks.insert(pos, chunk),
        }
    }

    /// returns the chucks before and after a given era.
    pub(crate) fn partition(self, era: Era) -> (Self, Self) {
        let (matching_chunks, other_chunks): (
            Vec<UnlockingChunk<Balance>>,
            Vec<UnlockingChunk<Balance>>,
        ) = self
            .unlocking_chunks
            .iter()
            .partition(|chunk| chunk.unlock_era <= era);

        (
            Self {
                unlocking_chunks: matching_chunks,
            },
            Self {
                unlocking_chunks: other_chunks,
            },
        )
    }
}

/// Information about an account's locked balance and unbonding information.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Default, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct AccountLedger<Balance: AtLeast32BitUnsigned + Default + Copy + MaxEncodedLen> {
    #[codec(compact)]
    pub(crate) locked: Balance,
    pub(crate) unbonding_info: UnbondingInfo<Balance>,
}

impl<Balance: AtLeast32BitUnsigned + Default + Copy + MaxEncodedLen> AccountLedger<Balance> {
    pub(crate) fn is_empty(&self) -> bool {
        self.locked.is_zero() && self.unbonding_info.is_empty()
    }
}
