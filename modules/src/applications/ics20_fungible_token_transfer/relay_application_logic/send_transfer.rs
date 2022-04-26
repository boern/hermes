use crate::applications::ics20_fungible_token_transfer::context::Ics20Context;
use crate::applications::ics20_fungible_token_transfer::error::Error;
use crate::applications::ics20_fungible_token_transfer::msgs::transfer::MsgTransfer;
use crate::applications::ics20_fungible_token_transfer::packet::PacketData;
use crate::applications::ics20_fungible_token_transfer::{Coin, IbcCoin, Source, TracePrefix};
use crate::core::ics04_channel::handler::send_packet::send_packet;
use crate::core::ics04_channel::packet::Packet;
use crate::core::ics04_channel::packet::PacketResult;
use crate::handler::HandlerOutput;
use crate::prelude::*;
use crate::signer::Signer;

#[allow(unused)]
pub(crate) fn send_transfer<Ctx>(
    ctx: &mut Ctx,
    msg: MsgTransfer,
) -> Result<HandlerOutput<PacketResult>, Error>
where
    Ctx: Ics20Context,
{
    if !ctx.is_send_enabled() {
        return Err(Error::send_disabled());
    }

    let source_channel_end = ctx
        .channel_end(&(msg.source_port.clone(), msg.source_channel))
        .map_err(Error::ics04_channel)?;

    let destination_port = source_channel_end.counterparty().port_id().clone();
    let destination_channel = *source_channel_end
        .counterparty()
        .channel_id()
        .ok_or_else(|| {
            Error::destination_channel_not_found(msg.source_port.clone(), msg.source_channel)
        })?;

    // get the next sequence
    let sequence = ctx
        .get_next_sequence_send(&(msg.source_port.clone(), msg.source_channel))
        .map_err(Error::ics04_channel)?;

    // TODO(hu55a1n1): get channel capability

    let denom = match msg.token.clone() {
        IbcCoin::Hashed(coin) => ctx
            .get_denom_trace(&coin.denom)
            .ok_or_else(Error::trace_not_found)?,
        IbcCoin::Base(coin) => coin.denom.into(),
    };

    let sender = msg.sender.to_string().parse()?;

    let prefix = TracePrefix::new(msg.source_port.clone(), msg.source_channel);
    match denom.source_chain(&prefix) {
        Source::Sender => {
            let escrow_address =
                ctx.get_channel_escrow_address(&msg.source_port, msg.source_channel)?;
            ctx.send_coins(&sender, &escrow_address, &msg.token)?;
        }
        Source::Receiver => {
            ctx.send_coins_from_account_to_module(
                &sender,
                &ctx.get_transfer_account(),
                &msg.token,
            )?;
            ctx.burn_coins(&ctx.get_transfer_account(), &msg.token)
                .expect("cannot burn coins after a successful send to a module account");
        }
    }

    let data = {
        let data = PacketData {
            token: Coin {
                denom,
                amount: msg.token.amount(),
            },
            sender: msg.sender.to_string().parse()?,
            receiver: msg.receiver.to_string().parse()?,
        };
        serde_json::to_vec(&data).expect("PacketData's infallible Serialize impl failed")
    };

    // endocde packet data
    let encode_data = serde_json::to_vec(&data).map_err(|_| Error::invalid_serde_data())?;

    let packet = Packet {
        sequence,
        source_port: msg.source_port,
        source_channel: msg.source_channel,
        destination_port,
        destination_channel,
        data,
        timeout_height: msg.timeout_height,
        timeout_timestamp: msg.timeout_timestamp,
    };

    let handler_output = send_packet(ctx, packet).map_err(Error::ics04_channel)?;

    //TODO:  add event/atributes and writes to the store issued by the application logic for packet sending.
    Ok(handler_output)
}
