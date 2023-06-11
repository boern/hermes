#!/bin/bash -e

# echo "------- create client for rococo-0 ---------"
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml create client --host-chain earth-0 --reference-chain rococo-0

# echo "------- create client for earth-0 ---------"
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml create client --host-chain rococo-0 --reference-chain earth-0

# echo "------- hermes start ---------"
# nohup hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml start >| ./hermes.log 2>&1 &

# echo "------- create connction ---------"
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx conn-init --dst-chain earth-0 --src-chain rococo-0 --dst-client 10-grandpa-0 --src-client 07-tendermint-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx conn-try --dst-chain rococo-0 --src-chain earth-0 --dst-client 07-tendermint-0 --src-client 10-grandpa-0 --src-connection connection-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx conn-ack --dst-chain earth-0 --src-chain rococo-0 --dst-client 10-grandpa-0 --src-client 07-tendermint-0 --dst-connection connection-0 --src-connection connection-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx conn-confirm --dst-chain rococo-0 --src-chain earth-0 --dst-client 07-tendermint-0 --src-client 10-grandpa-0 --dst-connection connection-0 --src-connection connection-0

# echo "------- create channel ---------"
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx chan-open-init --dst-chain rococo-0 --src-chain earth-0 --dst-connection connection-0 --dst-port transfer --src-port transfer
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx chan-open-try --dst-chain earth-0 --src-chain rococo-0 --dst-connection connection-0 --dst-port transfer --src-port transfer --src-channel channel-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx chan-open-ack --dst-chain rococo-0 --src-chain earth-0 --dst-connection connection-0 --dst-port transfer --src-port transfer --dst-channel channel-0 --src-channel channel-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx chan-open-confirm --dst-chain earth-0 --src-chain rococo-0 --dst-connection connection-0 --dst-port transfer --src-port transfer --dst-channel channel-0 --src-channel channel-0

# transfer from earth to rococo
hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx ft-transfer --timeout-height-offset 1000 --number-msgs 1 --dst-chain rococo-0 --src-chain earth-0 --src-port transfer --src-channel channel-0 --amount 999000 --denom ERT
sleep 2
hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-recv --dst-chain rococo-0 --src-chain earth-0 --src-port transfer --src-channel channel-0
sleep 2
hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-ack --dst-chain earth-0 --src-chain rococo-0 --src-port transfer --src-channel channel-0

# transfer back to earth from rococo
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx ft-transfer --timeout-height-offset 1000 --denom ibc/972368C2A53AAD83A3718FD4A43522394D4B5A905D79296BF04EE80565B595DF  --dst-chain earth-0 --src-chain rococo-0 --src-port transfer --src-channel channel-0 --amount 999000
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-recv --dst-chain earth-0 --src-chain rococo-0 --src-port transfer --src-channel channel-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-ack --dst-chain rococo-0 --src-chain earth-0 --src-port transfer --src-channel channel-0

# # transfer from rococo to earth
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx ft-transfer --timeout-height-offset 1000  --number-msgs 1 --dst-chain earth-0 --src-chain rococo-0 --src-port transfer --src-channel channel-0 --amount 20000000000000000 --denom ROC
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-recv --dst-chain earth-0 --src-chain rococo-0 --src-port transfer --src-channel channel-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-ack --dst-chain rococo-0 --src-chain earth-0 --src-port transfer --src-channel channel-0
# transfer back to rococo from earth
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx ft-transfer --timeout-height-offset 1000 --denom ibc/B94E95895D5F53F95DDE1A02663268D7288B39172F7DBA4D4A48FF4DDA4E092A  --dst-chain rococo-0 --src-chain earth-0 --src-port transfer --src-channel channel-0 --amount 20000000000000000
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-recv --dst-chain rococo-0 --src-chain earth-0 --src-port transfer --src-channel channel-0
# sleep 2
# hermes --config crates/relayer-cli/tests/fixtures/cos_sub.toml tx packet-ack --dst-chain earth-0 --src-chain rococo-0 --src-port transfer --src-channel channel-0
