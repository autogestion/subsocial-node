// This file is part of Substrate.

// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use sp_io::hashing::twox_128;
use sp_std::str;

use frame_support::{
	storage::StoragePrefixedMap,
	traits::{
		Get, GetStorageVersion, PalletInfoAccess, StorageVersion,
		STORAGE_VERSION_STORAGE_KEY_POSTFIX,
	},
	weights::Weight,
};

use crate as pallet_profile_follows;


pub fn migrate<T: pallet_profile_follows::Config, P: GetStorageVersion + PalletInfoAccess, N: AsRef<str>>(
	old_pallet_name: N,
) -> Weight {
	let old_pallet_name = old_pallet_name.as_ref();
	let new_pallet_name = <P as PalletInfoAccess>::name();

	if new_pallet_name == old_pallet_name {
		log::info!(
			target: "runtime::pallet-follows",
			"New pallet name is equal to the old prefix. No migration needs to be done.",
		);
		return 0
	}

	let on_chain_storage_version = <P as GetStorageVersion>::on_chain_storage_version();
	log::info!(
		target: "runtime::pallet-follows",
		"Running migration to v2 for tips with storage version {:?}",
		on_chain_storage_version,
	);

	if on_chain_storage_version < 2 {
		let storage_prefix = pallet_profile_follows::AccountFollowers::<T>::storage_prefix();
		frame_support::storage::migration::move_storage_from_pallet(
			storage_prefix,
			old_pallet_name.as_bytes(),
			new_pallet_name.as_bytes(),
		);
		log_migration("migration", storage_prefix, old_pallet_name, new_pallet_name);

		let storage_prefix = pallet_profile_follows::AccountFollowedByAccount::<T>::storage_prefix();
		frame_support::storage::migration::move_storage_from_pallet(
			storage_prefix,
			old_pallet_name.as_bytes(),
			new_pallet_name.as_bytes(),
		);
		log_migration("migration", storage_prefix, old_pallet_name, new_pallet_name);

		let storage_prefix = pallet_profile_follows::AccountsFollowedByAccount::<T>::storage_prefix();
		frame_support::storage::migration::move_storage_from_pallet(
			storage_prefix,
			old_pallet_name.as_bytes(),
			new_pallet_name.as_bytes(),
		);
		log_migration("migration", storage_prefix, old_pallet_name, new_pallet_name);

		StorageVersion::new(2).put::<P>();
		<T as frame_system::Config>::BlockWeights::get().max_block
	} else {
		log::warn!(
			target: "runtime::profile-follows",
			"Attempted to apply migration to v2 but failed because storage version is {:?}",
			on_chain_storage_version,
		);
		0
	}
}

/// Some checks prior to migration. This can be linked to
/// [`frame_support::traits::OnRuntimeUpgrade::pre_upgrade`] for further testing.
///
/// Panics if anything goes wrong.
pub fn pre_migrate<
	T: pallet_profile_follows::Config,
	P: GetStorageVersion + PalletInfoAccess,
	N: AsRef<str>,
>(
	old_pallet_name: N,
) {
	let old_pallet_name = old_pallet_name.as_ref();
	let new_pallet_name = <P as PalletInfoAccess>::name();

	let storage_prefix_followers = pallet_profile_follows::AccountFollowers::<T>::storage_prefix();
	let storage_prefix_followed = pallet_profile_follows::AccountFollowedByAccount::<T>::storage_prefix();
	let storage_prefix_sfollowed = pallet_profile_follows::AccountsFollowedByAccount::<T>::storage_prefix();

	log_migration("pre-migration", storage_prefix_followers, old_pallet_name, new_pallet_name);
	log_migration("pre-migration", storage_prefix_followed, old_pallet_name, new_pallet_name);
	log_migration("pre-migration", storage_prefix_sfollowed, old_pallet_name, new_pallet_name);

	if new_pallet_name == old_pallet_name {
		return
	}

	let new_pallet_prefix = twox_128(new_pallet_name.as_bytes());
	let storage_version_key = twox_128(STORAGE_VERSION_STORAGE_KEY_POSTFIX);

	let mut new_pallet_prefix_iter = frame_support::storage::KeyPrefixIterator::new(
		new_pallet_prefix.to_vec(),
		new_pallet_prefix.to_vec(),
		|key| Ok(key.to_vec()),
	);

	// Ensure nothing except the storage_version_key is stored in the new prefix.
	assert!(new_pallet_prefix_iter.all(|key| key == storage_version_key));

	assert!(<P as GetStorageVersion>::on_chain_storage_version() < 2);
}

/// Some checks for after migration. This can be linked to
/// [`frame_support::traits::OnRuntimeUpgrade::post_upgrade`] for further testing.
///
/// Panics if anything goes wrong.
pub fn post_migrate<
	T: pallet_profile_follows::Config,
	P: GetStorageVersion + PalletInfoAccess,
	N: AsRef<str>,
>(
	old_pallet_name: N,
) {
	let old_pallet_name = old_pallet_name.as_ref();
	let new_pallet_name = <P as PalletInfoAccess>::name();

	let storage_prefix_followers = pallet_profile_follows::AccountFollowers::<T>::storage_prefix();
	let storage_prefix_followed = pallet_profile_follows::AccountFollowedByAccount::<T>::storage_prefix();
	let storage_prefix_sfollowed = pallet_profile_follows::AccountsFollowedByAccount::<T>::storage_prefix();

	log_migration("post-migration", storage_prefix_followers, old_pallet_name, new_pallet_name);
	log_migration("post-migration", storage_prefix_followed, old_pallet_name, new_pallet_name);
	log_migration("post-migration", storage_prefix_sfollowed, old_pallet_name, new_pallet_name);

	if new_pallet_name == old_pallet_name {
		return
	}

	// Assert that no `Tips` and `Reasons` storages remains at the old prefix.
	let old_pallet_prefix = twox_128(old_pallet_name.as_bytes());
	let old_followers_key = [&old_pallet_prefix, &twox_128(storage_prefix_followers)[..]].concat();
	let old_followers_key_iter = frame_support::storage::KeyPrefixIterator::new(
		old_followers_key.to_vec(),
		old_followers_key.to_vec(),
		|_| Ok(()),
	);
	assert_eq!(old_followers_key_iter.count(), 0);

	let old_followed_key = [&old_pallet_prefix, &twox_128(storage_prefix_followed)[..]].concat();
	let old_followed_key_iter = frame_support::storage::KeyPrefixIterator::new(
		old_followed_key.to_vec(),
		old_followed_key.to_vec(),
		|_| Ok(()),
	);
	assert_eq!(old_followed_key_iter.count(), 0);

	let old_sfollowed_key = [&old_pallet_prefix, &twox_128(storage_prefix_sfollowed)[..]].concat();
	let old_sfollowed_key_iter = frame_support::storage::KeyPrefixIterator::new(
		old_sfollowed_key.to_vec(),
		old_sfollowed_key.to_vec(),
		|_| Ok(()),
	);
	assert_eq!(old_sfollowed_key_iter.count(), 0);

	// Assert that the storages (if they exist) have been moved to the new
	// prefix.
	// NOTE: storage_version_key is already in the new prefix.
	let new_pallet_prefix = twox_128(new_pallet_name.as_bytes());
	let new_pallet_prefix_iter = frame_support::storage::KeyPrefixIterator::new(
		new_pallet_prefix.to_vec(),
		new_pallet_prefix.to_vec(),
		|_| Ok(()),
	);
	assert!(new_pallet_prefix_iter.count() >= 1);

	assert_eq!(<P as GetStorageVersion>::on_chain_storage_version(), 2);
}

fn log_migration(stage: &str, storage_prefix: &[u8], old_pallet_name: &str, new_pallet_name: &str) {
	log::info!(
		target: "runtime::tips",
		"{} prefix of storage '{}': '{}' ==> '{}'",
		stage,
		str::from_utf8(storage_prefix).unwrap_or("<Invalid UTF8>"),
		old_pallet_name,
		new_pallet_name,
	);
}