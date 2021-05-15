use std::sync::Arc;
use codec::Codec;
use sp_blockchain::HeaderBackend;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use pallet_utils::{SpaceId, rpc::map_rpc_error};
use pallet_permissions::SpacePermission;

pub use roles_runtime_api::RolesApi as RolesRuntimeApi;

#[rpc]
pub trait RolesApi<BlockHash, AccountId> {
    #[rpc(name = "roles_getSpacePermissionsByAccount")]
    fn get_space_permissions_by_account(
        &self,
        at: Option<BlockHash>,
        account: AccountId,
        space_id: SpaceId
    ) -> Result<Vec<SpacePermission>>;

    #[rpc(name = "roles_getSpaceEditors")]
    fn get_space_editors(
        &self,
        at: Option<BlockHash>,
        space_id: SpaceId
    ) -> Result<Vec<AccountId>>;

    #[rpc(name = "roles_getSpaceIdsWhereAccountHasAnyRole")]
    fn get_space_ids_where_account_has_any_role(
        &self,
        at: Option<BlockHash>,
        account_id: AccountId
    ) -> Result<Vec<SpaceId>>;
}

pub struct Roles<C, M> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<M>,
}

impl<C, M> Roles<C, M> {
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _marker: Default::default(),
        }
    }
}

impl<C, Block, AccountId> RolesApi<<Block as BlockT>::Hash, AccountId>
    for Roles<C, Block>
where
    Block: BlockT,
    AccountId: Codec,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: RolesRuntimeApi<Block, AccountId>,
{
    fn get_space_permissions_by_account(
        &self, at:
        Option<<Block as BlockT>::Hash>,
        account: AccountId,
        space_id: SpaceId
    ) -> Result<Vec<SpacePermission>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(|| self.client.info().best_hash));

        let runtime_api_result = api.get_space_permissions_by_account(&at, account, space_id);
        runtime_api_result.map_err(map_rpc_error)
    }

    fn get_space_editors(
        &self, at:
        Option<<Block as BlockT>::Hash>,
        space_id: SpaceId
    ) -> Result<Vec<AccountId>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(|| self.client.info().best_hash));

        let runtime_api_result = api.get_space_editors(&at, space_id);
        runtime_api_result.map_err(map_rpc_error)
    }

    fn get_space_ids_where_account_has_any_role(
        &self, at:
        Option<<Block as BlockT>::Hash>,
        account_id: AccountId
    ) -> Result<Vec<SpaceId>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(|| self.client.info().best_hash));

        let runtime_api_result = api.get_space_ids_where_account_has_any_role(&at, account_id);
        runtime_api_result.map_err(map_rpc_error)
    }
}