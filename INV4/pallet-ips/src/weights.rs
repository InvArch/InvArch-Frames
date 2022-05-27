
//! Autogenerated weights for `pallet_ips`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-05-27, STEPS: `20`, REPEAT: 10, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("solo-dev"), DB CACHE: 1024

// Executed Command:
// ./target/release/invarch-collator
// benchmark
// --chain
// solo-dev
// --execution
// wasm
// --wasm-execution
// compiled
// --pallet
// pallet-ips
// --extrinsic
// append
// --steps
// 20
// --repeat
// 10
// --json-file=./weights/ips/ips.json
// --output
// ../InvArch-Frames/INV4/pallet-ips/src/weights.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `pallet_ips`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_ips::WeightInfo for WeightInfo<T> {
	// Storage: Ips IpsStorage (r:1 w:1)
	fn append(_s: u32, ) -> Weight {
		(18_019_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(1 as Weight))
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
	}
}
