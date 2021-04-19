use crate::{SpaceId};

use pallet_utils::Content;

pub trait IsAccountBlocked {
    type AccountId;

    fn is_blocked_account(account: Self::AccountId, scope: SpaceId) -> bool;
}

impl IsAccountBlocked for () {
    type AccountId = sp_runtime::AccountId32;

    fn is_blocked_account(_account: Self::AccountId, _scope: u64) -> bool {
        false
    }
}

pub trait IsSpaceBlocked {
    fn is_blocked_space(space_id: SpaceId, scope: SpaceId) -> bool;
}

pub trait IsPostBlocked {
    type PostId;

    fn is_blocked_post(post_id: Self::PostId, scope: SpaceId) -> bool;
}

impl IsPostBlocked for () {
    type PostId = u64;

    fn is_blocked_post(_post_id: Self::PostId, _scope: SpaceId) -> bool {
        false
    }
}

pub trait IsContentBlocked {
    fn is_blocked_content(content: Content, scope: SpaceId) -> bool;
}

impl IsContentBlocked for () {
    fn is_blocked_content(_content: Content, _scope: u64) -> bool {
        false
    }
}
