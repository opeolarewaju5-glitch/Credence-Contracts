//! Deterministic failure-boundary coverage for the `get_role` read entrypoint.
//!
//! [`AdminContract::get_role`] resolves an `Address` to its stored
//! [`AdminRole`] and is the shared role primitive behind `add_admin`,
//! `remove_admin`, `update_admin_role`, `deactivate_admin`,
//! `reactivate_admin`, and the `pausable` pause-authority check. Its contract
//! is deterministic for every input class:
//!
//! * **valid**     — a registered address resolves to exactly its stored role;
//! * **invalid**   — an unknown, removed, sentinel, or pre-initialisation
//!                   address fails with the wire-stable `NotAdmin` (100)
//!                   error and leaves no state, event, or epoch change;
//! * **duplicate** — repeated reads are idempotent and observably identical,
//!                   and a rejected duplicate *mutation* never moves the
//!                   epoch or the event stream;
//! * **boundary**  — suspension, the suspension-expiry instant, deactivation,
//!                   a committed role change, a dangling `AdminList` entry,
//!                   and the paused state all resolve deterministically
//!                   without ever serving stale data.
//!
//! The entrypoint is read-only: it must never advance
//! [`AdminContract::get_config_epoch`] and never publish an event. A stored
//! role is deliberately *not* an effective-authority check — callers that need
//! "may this address act right now?" use `is_admin` / `has_role_at_least`.

#![cfg(test)]

use crate::*;
use credence_errors::Role;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

// Wire-stable error discriminants (`credence_errors::ContractError`).
const ERR_NOT_ADMIN: u32 = 100;
const ERR_ALREADY_ACTIVE: u32 = 405;
const ERR_CONTRACT_PAUSED: u32 = 106;

/// The all-zero Ed25519 public key in strkey format.
const ZERO_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

fn setup() -> (Env, Address, AdminContractClient<'static>, Address) {
    let e = Env::default();
    let contract_id = e.register_contract(None, AdminContract);
    let client = AdminContractClient::new(&e, &contract_id);
    let super_admin = Address::generate(&e);
    e.mock_all_auths();
    client.initialize(&super_admin, &1u32, &100u32);
    (e, contract_id, client, super_admin)
}

fn new_admin_with_role(
    e: &Env,
    client: &AdminContractClient,
    caller: &Address,
    role: AdminRole,
) -> Address {
    let new_admin = Address::generate(e);
    client.add_admin(caller, &new_admin, &role);
    new_admin
}

fn assert_not_admin(err: soroban_sdk::Error) {
    assert_eq!(err, soroban_sdk::Error::from_contract_error(ERR_NOT_ADMIN));
}

// ---------------------------------------------------------------------------
// Success
// ---------------------------------------------------------------------------

/// Every role in the hierarchy resolves to exactly the value that was stored
/// for it — no clamping, no coercion, no defaulting.
#[test]
fn get_role_returns_exact_role_for_each_hierarchy_level() {
    let (e, _contract_id, client, super_admin) = setup();
    let operator = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);
    let admin = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);

    assert_eq!(client.get_role(&super_admin), AdminRole::SuperAdmin);
    assert_eq!(client.get_role(&admin), AdminRole::Admin);
    assert_eq!(client.get_role(&operator), AdminRole::Operator);
}

/// Reads are pure: repeating them yields identical answers and never advances
/// the config epoch or appends to the event stream.
#[test]
fn get_role_is_repeatable_and_leaves_epoch_and_events_untouched() {
    let (e, _contract_id, client, super_admin) = setup();
    let operator = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);

    let epoch_before = client.get_config_epoch();
    let events_before = e.events().all().len();

    let first = client.get_role(&operator);
    for _ in 0..8 {
        assert_eq!(client.get_role(&operator), first);
    }

    assert_eq!(first, AdminRole::Operator);
    assert_eq!(client.get_config_epoch(), epoch_before);
    assert_eq!(e.events().all().len(), events_before);
}

// ---------------------------------------------------------------------------
// Invalid input
// ---------------------------------------------------------------------------

/// An address that was never registered fails with the typed `NotAdmin`
/// discriminant rather than a bare panic, and mutates nothing.
#[test]
fn get_role_rejects_unknown_address_with_not_admin() {
    let (e, _contract_id, client, _super_admin) = setup();
    let stranger = Address::generate(&e);

    let epoch_before = client.get_config_epoch();
    let events_before = e.events().all().len();

    assert_not_admin(client.try_get_role(&stranger).unwrap_err().unwrap());

    assert_eq!(client.get_config_epoch(), epoch_before);
    assert_eq!(e.events().all().len(), events_before);
}

/// The zero/sentinel strkey has no `AdminInfo` record, so it fails the same
/// way as any unknown address instead of resolving to a default role.
#[test]
fn get_role_rejects_zero_address_sentinel_with_not_admin() {
    let (e, _contract_id, client, _super_admin) = setup();
    let zero = Address::from_string(&String::from_str(&e, ZERO_ADDRESS));

    let epoch_before = client.get_config_epoch();
    let events_before = e.events().all().len();

    assert_not_admin(client.try_get_role(&zero).unwrap_err().unwrap());

    assert_eq!(client.get_config_epoch(), epoch_before);
    assert_eq!(e.events().all().len(), events_before);
}

/// Before `initialize` there is no `AdminInfo` namespace to read from. The
/// per-address read fails with `NotAdmin` (not a bare panic and not a
/// partial read), so the pre-initialisation state is pinned here.
#[test]
fn get_role_before_initialize_rejects_with_not_admin() {
    let e = Env::default();
    let contract_id = e.register_contract(None, AdminContract);
    let client = AdminContractClient::new(&e, &contract_id);
    let stranger = Address::generate(&e);

    assert_not_admin(client.try_get_role(&stranger).unwrap_err().unwrap());
}

/// Once an admin is removed its record is gone, so the read can no longer
/// resolve a role for it — no stale value survives removal.
#[test]
fn get_role_rejects_removed_admin() {
    let (e, _contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);
    assert_eq!(client.get_role(&target), AdminRole::Admin);

    client.remove_admin(&super_admin, &target);

    assert_not_admin(client.try_get_role(&target).unwrap_err().unwrap());
}

// ---------------------------------------------------------------------------
// Boundary cases
// ---------------------------------------------------------------------------

/// Suspension removes *effective authority*, not the stored role. `get_role`
/// keeps reporting the stored role while the effective-authority read flips
/// to false — the separation is intentional and is what callers rely on.
#[test]
fn get_role_returns_stored_role_while_suspended() {
    let (e, _contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);
    let until = e.ledger().timestamp() + 1_000;
    client.suspend_admin(&super_admin, &target, &until);

    assert_eq!(client.get_role(&target), AdminRole::Admin);
    assert!(!client.has_role_at_least(&target, &AdminRole::Admin));
    assert_eq!(client.is_admin(&target), Role::User);
}

/// Timing boundary: the stored role is a pure function of storage, so it is
/// byte-identical one second before expiry, at the exact expiry instant, and
/// after it — while `has_role_at_least` flips at `until` (inclusive expiry).
#[test]
fn get_role_is_timestamp_independent_across_suspension_expiry_boundary() {
    let (e, _contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);
    let until = e.ledger().timestamp() + 100;
    client.suspend_admin(&super_admin, &target, &until);

    e.ledger().with_mut(|ledger| ledger.timestamp = until - 1);
    assert_eq!(client.get_role(&target), AdminRole::Admin);
    assert!(!client.has_role_at_least(&target, &AdminRole::Admin));

    e.ledger().with_mut(|ledger| ledger.timestamp = until);
    assert_eq!(client.get_role(&target), AdminRole::Admin);
    assert!(client.has_role_at_least(&target, &AdminRole::Admin));

    e.ledger().with_mut(|ledger| ledger.timestamp = until + 1);
    assert_eq!(client.get_role(&target), AdminRole::Admin);
    assert!(client.has_role_at_least(&target, &AdminRole::Admin));
}

/// Deactivation is the permanent counterpart of suspension: it clears
/// authority but leaves the stored role readable.
#[test]
fn get_role_returns_stored_role_for_deactivated_admin() {
    let (e, _contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);

    client.deactivate_admin(&super_admin, &target);

    assert_eq!(client.get_role(&target), AdminRole::Admin);
    assert_eq!(client.is_admin(&target), Role::User);
    assert!(!client.has_role_at_least(&target, &AdminRole::Admin));
}

/// A read taken at epoch *N* is detectably stale once a privileged mutation
/// commits at *N+1*, and the next read observes the committed value. Each
/// committed role change advances the epoch exactly once; a no-op does not.
#[test]
fn get_role_reflects_committed_role_change_and_detects_stale_read() {
    let (e, _contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);

    let epoch_at_read = client.get_config_epoch();
    assert_eq!(client.get_role(&target), AdminRole::Operator);

    client.update_admin_role(&super_admin, &target, &AdminRole::Admin);
    assert_eq!(client.get_config_epoch(), epoch_at_read + 1);
    assert_eq!(client.get_role(&target), AdminRole::Admin);

    client.update_admin_role(&super_admin, &target, &AdminRole::Operator);
    assert_eq!(client.get_config_epoch(), epoch_at_read + 2);
    assert_eq!(client.get_role(&target), AdminRole::Operator);

    // Re-writing the role the address already holds is a no-op: no epoch
    // advance, so a retrying client never observes a phantom conflict.
    client.update_admin_role(&super_admin, &target, &AdminRole::Operator);
    assert_eq!(client.get_config_epoch(), epoch_at_read + 2);
    assert_eq!(client.get_role(&target), AdminRole::Operator);
}

/// A dangling `AdminList` entry (the list still names the address, but the
/// `AdminInfo` record is gone) must never resolve to a role: the read fails
/// with `NotAdmin` rather than serving the stale list data.
#[test]
fn get_role_rejects_dangling_admin_list_entry() {
    let (e, contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);
    assert_eq!(client.get_role(&target), AdminRole::Admin);

    e.as_contract(&contract_id, || {
        e.storage()
            .instance()
            .remove(&DataKey::AdminInfo(target.clone()));
    });

    assert_not_admin(client.try_get_role(&target).unwrap_err().unwrap());

    let admin_list: Vec<Address> = e
        .as_contract(&contract_id, || e.storage().instance().get(&DataKey::AdminList))
        .expect("AdminList must still be present");
    assert_eq!(admin_list.len(), 2);
}

// ---------------------------------------------------------------------------
// Duplicate / retry / failure recovery
// ---------------------------------------------------------------------------

/// Re-adding an address already on the roster is rejected with the typed
/// `AlreadyActive` error *before* any epoch or event change, and the
/// original role assignment is untouched.
#[test]
fn rejected_duplicate_add_admin_leaves_get_role_epoch_and_events_unchanged() {
    let (e, _contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);

    let epoch_before = client.get_config_epoch();
    let events_before = e.events().all().len();

    let err = client
        .try_add_admin(&super_admin, &target, &AdminRole::Admin)
        .unwrap_err()
        .unwrap();
    assert_eq!(
        err,
        soroban_sdk::Error::from_contract_error(ERR_ALREADY_ACTIVE)
    );

    assert_eq!(client.get_config_epoch(), epoch_before);
    assert_eq!(e.events().all().len(), events_before);
    assert_eq!(client.get_role(&target), AdminRole::Operator);
}

/// A rejected mutation leaves the world exactly as it was, so a subsequent
/// retry with a valid authoriser commits exactly once instead of double-
/// applying or wedging.
#[test]
fn rejected_unauthorized_mutation_then_successful_retry_is_consistent() {
    let (e, _contract_id, client, super_admin) = setup();
    let operator = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);
    let candidate = Address::generate(&e);

    let epoch_before = client.get_config_epoch();
    let events_before = e.events().all().len();

    // An Operator is below the role required to assign an Admin.
    let err = client
        .try_add_admin(&operator, &candidate, &AdminRole::Admin)
        .unwrap_err()
        .unwrap();
    assert_not_admin(err);

    assert_eq!(client.get_config_epoch(), epoch_before);
    assert_eq!(e.events().all().len(), events_before);
    assert_not_admin(client.try_get_role(&candidate).unwrap_err().unwrap());

    // The retry with a valid authoriser commits exactly once.
    client.add_admin(&super_admin, &candidate, &AdminRole::Admin);
    assert_eq!(client.get_config_epoch(), epoch_before + 1);
    assert_eq!(client.get_role(&candidate), AdminRole::Admin);
}

/// Reads stay available while the contract is paused, and the write path is
/// blocked with a typed `ContractPaused` error — so pausing can never make a
/// role lookup unreadable or let a rejected write masquerade as a read
/// failure.
#[test]
fn get_role_remains_available_while_paused() {
    let (e, _contract_id, client, super_admin) = setup();
    let operator = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);
    let stranger = Address::generate(&e);
    let candidate = Address::generate(&e);

    client.pause(&super_admin);
    assert!(client.is_paused());

    assert_eq!(client.get_role(&super_admin), AdminRole::SuperAdmin);
    assert_eq!(client.get_role(&operator), AdminRole::Operator);
    assert_not_admin(client.try_get_role(&stranger).unwrap_err().unwrap());

    let epoch_before = client.get_config_epoch();
    let err = client
        .try_add_admin(&super_admin, &candidate, &AdminRole::Admin)
        .unwrap_err()
        .unwrap();
    assert_eq!(
        err,
        soroban_sdk::Error::from_contract_error(ERR_CONTRACT_PAUSED)
    );
    assert_eq!(client.get_config_epoch(), epoch_before);

    client.unpause(&super_admin);
    assert!(!client.is_paused());
    client.add_admin(&super_admin, &candidate, &AdminRole::Admin);
    assert_eq!(client.get_role(&candidate), AdminRole::Admin);
}

/// `get_role` is the guard every privileged mutation consults first. An
/// unregistered caller is rejected before the target record, the epoch, or
/// the event stream are touched.
#[test]
fn unregistered_caller_is_rejected_before_any_state_change() {
    let (e, _contract_id, client, super_admin) = setup();
    let target = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);
    let stranger = Address::generate(&e);

    let epoch_before = client.get_config_epoch();
    let events_before = e.events().all().len();

    let err = client
        .try_remove_admin(&stranger, &target)
        .unwrap_err()
        .unwrap();
    assert_not_admin(err);

    assert_eq!(client.get_config_epoch(), epoch_before);
    assert_eq!(e.events().all().len(), events_before);
    assert_eq!(client.get_role(&target), AdminRole::Admin);
    assert_eq!(client.get_admin_info(&target).role, AdminRole::Admin);
}

// ---------------------------------------------------------------------------
// Regression: the two role reads must not drift apart
// ---------------------------------------------------------------------------

/// `get_role` and its sibling `get_admin_role` are independent entrypoints
/// over the same record. They must agree for every state — active, suspended,
/// deactivated — and fail with the identical error for removed and unknown
/// addresses, so no caller can get two different answers.
#[test]
fn get_role_agrees_with_get_admin_role_across_all_states() {
    let (e, _contract_id, client, super_admin) = setup();

    let operator = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);
    let suspended = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);
    let until = e.ledger().timestamp() + 500;
    client.suspend_admin(&super_admin, &suspended, &until);

    let deactivated = new_admin_with_role(&e, &client, &super_admin, AdminRole::Admin);
    client.deactivate_admin(&super_admin, &deactivated);

    let removed = new_admin_with_role(&e, &client, &super_admin, AdminRole::Operator);
    client.remove_admin(&super_admin, &removed);
    let unknown = Address::generate(&e);

    let resolvable = [
        super_admin.clone(),
        operator.clone(),
        suspended.clone(),
        deactivated.clone(),
    ];
    for address in resolvable.iter() {
        assert_eq!(client.get_role(address), client.get_admin_role(address));
    }

    for address in [removed, unknown].iter() {
        let from_get_role = client.try_get_role(address).unwrap_err().unwrap();
        let from_get_admin_role = client.try_get_admin_role(address).unwrap_err().unwrap();
        assert_eq!(from_get_role, from_get_admin_role);
        assert_not_admin(from_get_role);
    }
}
