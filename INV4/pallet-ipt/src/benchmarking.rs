//! Benchmarks for IPT Pallet
#![cfg(feature = "runtime-benchmarks")]

pub use super::*;
use frame_benchmarking::{
    account, benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller, Box,
};
use frame_system::RawOrigin;
use primitives::SubIptInfo;
use sp_io::hashing::blake2_256;

const SEED: u32 = 0;

benchmarks! {
    where_clause {
        where T: pallet::Config<Call = Call<T>>
    }

   mint {
        let s in 0 .. 100;
        let caller: T::AccountId = whitelisted_caller();
        let amount: <T as pallet::Config>::Balance = 300u32.into();
        let target: T::AccountId = account("target", 0, SEED);
    }: _(RawOrigin::Signed(caller), (T::IptId::from(s), None), amount, target)

    burn {
        let s in 0 .. 100;
        let caller: T::AccountId = whitelisted_caller();
        let amount: <T as pallet::Config>::Balance = 300u32.into();
        let target: T::AccountId = account("target", 0, SEED);
    }: _(RawOrigin::Signed(caller), (T::IptId::from(s), None), amount, target)

    operate_multisig {
        let s in 0 .. 100;
        let caller: T::AccountId = whitelisted_caller();
        let target: T::AccountId = account("target", 0, SEED);
        let call = Call::mint::<T> {
            ipt_id: (T::IptId::from(s), None),
            amount: 1000u32.into(),
            target,
        };
    }: _(RawOrigin::Signed(caller), false, (T::IptId::from(s), None), Box::new(call))

    vote_multisig {
        let s in 0 .. 100;
        let caller: T::AccountId = whitelisted_caller();
        let target: T::AccountId = account("target", 0, SEED);
        let call = Call::mint::<T> {
            ipt_id: (T::IptId::from(s), None),
            amount: 1000u32.into(),
            target,
        };
    }: _(RawOrigin::Signed(caller), (T::IptId::from(s), None), blake2_256(&call.encode()))

    withdraw_vote_multisig {
        let s in 0 .. 100;
        let caller: T::AccountId = whitelisted_caller();
        let target: T::AccountId = account("target", 0, SEED);
        let call = Call::mint::<T> {
            ipt_id: (T::IptId::from(s), None),
            amount: 1000u32.into(),
            target,
        };
    }: _(RawOrigin::Signed(caller), (T::IptId::from(s), None), blake2_256(&call.encode()))

    create_sub_asset {
        let s in 0 .. 100;
        let caller: T::AccountId = whitelisted_caller();
        let sub_assets: SubAssetsWithEndowment<T> = vec![(
            SubIptInfo {id: T::IptId::from(s), metadata: Default::default()}, (account("target", 0, SEED), 500u32.into())
        )];
    }: _(RawOrigin::Signed(caller), T::IptId::from(s), sub_assets)
}

impl_benchmark_test_suite!(Ipt, crate::mock::new_test_ext(), crate::mock::Test,);