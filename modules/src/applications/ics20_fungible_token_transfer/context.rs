use core::str::FromStr;

use sha2::{Digest, Sha256};
use subtle_encoding::hex;

use super::error::Error as Ics20Error;
use crate::applications::ics20_fungible_token_transfer::acknowledgement::Acknowledgement;
use crate::applications::ics20_fungible_token_transfer::packet::PacketData;
use crate::applications::ics20_fungible_token_transfer::relay_application_logic::on_ack_packet::process_ack_packet;
use crate::applications::ics20_fungible_token_transfer::relay_application_logic::on_recv_packet::process_recv_packet;
use crate::applications::ics20_fungible_token_transfer::{
    DenomTrace, HashedDenom, IbcCoin, VERSION,
};
use crate::applications::ics20_fungible_token_transfer::relay_application_logic::on_timeout_packet::process_timeout_packet;
use crate::core::ics04_channel::channel::{Counterparty, Order};
use crate::core::ics04_channel::context::{ChannelKeeper, ChannelReader};
use crate::core::ics04_channel::msgs::acknowledgement::Acknowledgement as GenericAcknowledgement;
use crate::core::ics04_channel::packet::Packet;
use crate::core::ics04_channel::Version;
use crate::core::ics05_port::capabilities::ChannelCapability;
use crate::core::ics05_port::context::{PortKeeper, PortReader};
use crate::core::ics24_host::identifier::{ChannelId, ConnectionId, PortId};
use crate::core::ics26_routing::context::OnRecvPacketAck;
use crate::prelude::*;
use crate::signer::Signer;

pub trait Ics20Keeper:
    ChannelKeeper + PortKeeper + BankKeeper<AccountId = <Self as Ics20Keeper>::AccountId>
{
    type AccountId: Into<String>;

    /// Sets a new {trace hash -> denom trace} pair to the store.
    fn set_denom_trace(&mut self, denom_trace: &DenomTrace) -> Result<(), Ics20Error>;
}

pub trait Ics20Reader:
    BankReader<AccountId = <Self as Ics20Reader>::AccountId>
    + AccountReader<AccountId = <Self as Ics20Reader>::AccountId>
    + ChannelReader
    + PortReader
{
    type AccountId: Into<String> + FromStr<Err = Ics20Error>;

    /// get_port returns the portID for the transfer module.
    fn get_port(&self) -> Result<PortId, Ics20Error>;

    /// Returns the escrow account id for a port and channel combination
    fn get_channel_escrow_address(
        &self,
        port_id: &PortId,
        channel_id: ChannelId,
    ) -> Result<<Self as Ics20Reader>::AccountId, Ics20Error> {
        // https://github.com/cosmos/cosmos-sdk/blob/master/docs/architecture/adr-028-public-key-addresses.md
        let contents = format!("{}/{}", port_id, channel_id);
        let mut hasher = Sha256::new();
        hasher.update(VERSION.as_bytes());
        hasher.update(b"0");
        hasher.update(contents.as_bytes());
        let hash: Vec<u8> = hasher.finalize().to_vec().drain(20..).collect();
        String::from_utf8(hex::encode_upper(hash))
            .expect("hex encoded bytes are not valid UTF8")
            .parse()
    }

    /// Returns true iff send is enabled.
    fn is_send_enabled(&self) -> bool;

    /// Returns true iff receive is enabled.
    fn is_receive_enabled(&self) -> bool;

    /// Returns true iff the store contains a `DenomTrace` entry for the specified `HashedDenom`.
    fn has_denom_trace(&self, hashed_denom: &HashedDenom) -> bool {
        self.get_denom_trace(hashed_denom).is_some()
    }

    /// Get the denom trace associated with the specified hash in the store.
    fn get_denom_trace(&self, denom_hash: &HashedDenom) -> Option<DenomTrace>;
}

pub trait BankKeeper {
    type AccountId: Into<String>;

    /// This function should enable sending ibc fungible tokens from one account to another
    fn send_coins(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        amt: &IbcCoin,
    ) -> Result<(), Ics20Error>;

    /// This function to enable minting ibc tokens in a module
    fn mint_coins(&mut self, module: &Self::AccountId, amt: &IbcCoin) -> Result<(), Ics20Error>;

    /// This function should enable burning of minted tokens
    fn burn_coins(&mut self, module: &Self::AccountId, amt: &IbcCoin) -> Result<(), Ics20Error>;

    /// This function should enable transfer of tokens from the ibc module to an account
    fn send_coins_from_module_to_account(
        &mut self,
        module: &Self::AccountId,
        to: &Self::AccountId,
        amt: &IbcCoin,
    ) -> Result<(), Ics20Error>;

    /// This function should enable transfer of tokens from an account to the ibc module
    fn send_coins_from_account_to_module(
        &mut self,
        from: &Self::AccountId,
        module: &Self::AccountId,
        amt: &IbcCoin,
    ) -> Result<(), Ics20Error>;
}

pub trait BankReader {
    type AccountId: Into<String> + FromStr;

    /// Returns true if the specified account is not allowed to receive funds and false otherwise.
    fn is_blocked_account(&self, account: &Self::AccountId) -> bool;

    /// get_transfer_account returns the ICS20 - transfers AccountId.
    fn get_transfer_account(&self) -> Self::AccountId;
}

pub trait AccountReader {
    type AccountId: Into<String>;
    type Address;

    fn get_account(&self, address: &Self::Address) -> Option<Self::AccountId>;
}

/// Captures all the dependencies which the ICS20 module requires to be able to dispatch and
/// process IBC messages.
pub trait Ics20Context:
    Ics20Keeper<AccountId = <Self as Ics20Context>::AccountId>
    + Ics20Reader<AccountId = <Self as Ics20Context>::AccountId>
{
    type AccountId: Into<String> + FromStr<Err = Ics20Error>;
}

fn validate_transfer_channel_params(
    ctx: &mut impl Ics20Context,
    order: Order,
    port_id: &PortId,
    channel_id: &ChannelId,
    version: &Version,
) -> Result<(), Ics20Error> {
    if channel_id.sequence() > (u32::MAX as u64) {
        return Err(Ics20Error::chan_seq_exceeds_limit(channel_id.sequence()));
    }

    if order != Order::Unordered {
        return Err(Ics20Error::channel_not_unordered(order));
    }

    let bound_port = ctx.get_port()?;
    if port_id != &bound_port {
        return Err(Ics20Error::invalid_port(port_id.clone(), bound_port));
    }

    if version != &Version::ics20() {
        return Err(Ics20Error::invalid_version(
            version.clone(),
            Version::ics20(),
        ));
    }

    Ok(())
}

fn validate_counterparty_version(counterparty_version: &Version) -> Result<(), Ics20Error> {
    if counterparty_version == &Version::ics20() {
        Ok(())
    } else {
        Err(Ics20Error::invalid_counterparty_version(
            counterparty_version.clone(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn on_chan_open_init(
    ctx: &mut impl Ics20Context,
    order: Order,
    _connection_hops: &[ConnectionId],
    port_id: &PortId,
    channel_id: &ChannelId,
    _channel_cap: &ChannelCapability,
    _counterparty: &Counterparty,
    version: &Version,
) -> Result<(), Ics20Error> {
    validate_transfer_channel_params(ctx, order, port_id, channel_id, version)?;

    // TODO(hu55a1n1): claim channel capability

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn on_chan_open_try(
    ctx: &mut impl Ics20Context,
    order: Order,
    _connection_hops: &[ConnectionId],
    port_id: &PortId,
    channel_id: &ChannelId,
    _channel_cap: &ChannelCapability,
    _counterparty: &Counterparty,
    version: &Version,
    counterparty_version: &Version,
) -> Result<Version, Ics20Error> {
    validate_transfer_channel_params(ctx, order, port_id, channel_id, version)?;
    validate_counterparty_version(counterparty_version)?;

    // TODO(hu55a1n1): claim channel capability (iff we don't already own it)

    Ok(Version::ics20())
}

pub fn on_chan_open_ack(
    _ctx: &mut impl Ics20Context,
    _port_id: &PortId,
    _channel_id: &ChannelId,
    counterparty_version: &Version,
) -> Result<(), Ics20Error> {
    validate_counterparty_version(counterparty_version)?;
    Ok(())
}

pub fn on_chan_open_confirm(
    _ctx: &mut impl Ics20Context,
    _port_id: &PortId,
    _channel_id: &ChannelId,
) -> Result<(), Ics20Error> {
    Ok(())
}

pub fn on_chan_close_init(
    _ctx: &mut impl Ics20Context,
    _port_id: &PortId,
    _channel_id: &ChannelId,
) -> Result<(), Ics20Error> {
    Err(Ics20Error::cant_close_channel())
}

pub fn on_chan_close_confirm(
    _ctx: &mut impl Ics20Context,
    _port_id: &PortId,
    _channel_id: &ChannelId,
) -> Result<(), Ics20Error> {
    Ok(())
}

pub fn on_recv_packet<Ctx: 'static + Ics20Context>(
    ctx: &Ctx,
    packet: &Packet,
    _relayer: &Signer,
) -> OnRecvPacketAck {
    let data = match serde_json::from_slice::<PacketData>(&packet.data) {
        Ok(data) => data,
        Err(_) => {
            return OnRecvPacketAck::Failed(Box::new(Acknowledgement::Error(
                Ics20Error::packet_data_deserialization().to_string(),
            )))
        }
    };

    // TODO(hu55a1n1): emit event

    match process_recv_packet(ctx, packet, data) {
        Ok(write_fn) => OnRecvPacketAck::Successful(Box::new(Acknowledgement::success()), write_fn),
        Err(e) => OnRecvPacketAck::Failed(Box::new(Acknowledgement::from_error(e))),
    }
}

pub fn on_acknowledgement_packet(
    ctx: &mut impl Ics20Context,
    packet: &Packet,
    acknowledgement: &GenericAcknowledgement,
    _relayer: &Signer,
) -> Result<(), Ics20Error> {
    let data = serde_json::from_slice::<PacketData>(&packet.data)
        .map_err(|_| Ics20Error::packet_data_deserialization())?;

    let ack = serde_json::from_slice::<Acknowledgement>(acknowledgement.as_ref())
        .map_err(|_| Ics20Error::ack_deserialization())?;

    process_ack_packet(ctx, packet, &data, &ack)?;

    // TODO(hu55a1n1): emit event

    Ok(())
}

pub fn on_timeout_packet(
    ctx: &mut impl Ics20Context,
    packet: &Packet,
    _relayer: &Signer,
) -> Result<(), Ics20Error> {
    let data = serde_json::from_slice::<PacketData>(&packet.data)
        .map_err(|_| Ics20Error::packet_data_deserialization())?;

    process_timeout_packet(ctx, packet, &data)?;

    // TODO(hu55a1n1): emit event

    Ok(())
}
