import datetime
import ipfshttpclient
import maya
from sha3 import keccak_256
from solc import compile_source
import sys
from threading import Thread
from time import sleep
from twisted.logger import globalLogPublisher
from umbral.keys import UmbralPublicKey
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

from nucypher.characters.lawful import Alice, Bob, Enrico, Ursula
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.utilities.logging import SimpleObserver
from nucypher.utilities.sandbox.constants import TEMPORARY_DOMAIN

#####################
# Utility functions #
#####################

def compile_source_file(file_path):
   with open(file_path, 'r') as f:
      source = f.read()
   return compile_source(source)


def deploy_contract(w3, contract_interface, *args):
    tx_hash = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']).constructor(*args).transact()
    address = w3.eth.waitForTransactionReceipt(tx_hash)['contractAddress']
    return address

######################
# Boring setup stuff #
######################

# Twisted Logger
try:
    LOGGER_ON = sys.argv[2].lower() == 'true'
except IndexError:
    LOGGER_ON = False
if LOGGER_ON:
    globalLogPublisher.addObserver(SimpleObserver())

# IPFS client
ipfs_client = ipfshttpclient.connect('/ip4/172.28.0.2/tcp/5001/http')

# if your ursulas are NOT running on your current host,
# run like this: python finnegans-wake-demo.py 172.28.1.3:11500
# otherwise the default will be fine.
# (will fail with bad connection though)
try:
    SEEDNODE_URI = sys.argv[1]
except IndexError:
    SEEDNODE_URI = "localhost:11500"

# Compile Solidity sources
compiled_proxy_account = compile_source_file('ProxyAccount.sol')
_, proxy_account_interface = compiled_proxy_account.popitem()

compiled_claim_holder = compile_source_file('ClaimHolder.sol')
_, claim_holder_interface = compiled_claim_holder.popitem()

# Create and connect to an EthereumTester
w3 = Web3(EthereumTesterProvider())

# use pre-funded accounts
alice_eth_address = w3.eth.accounts[0]
bob_eth_address = w3.eth.accounts[1]
enrico_eth_address = w3.eth.accounts[2]

# create proxy account data keys (as keccak256 digest of their labels, as currently defined in EIP 725)
claim_holder_key = keccak_256(b'735').digest()
nucypher_decrypting_key = keccak_256(b'nuCypherDecrypting').digest()
nucypher_signing_key = keccak_256(b'nuCypherSigning').digest()
health_label = b'X-/health'
health_label_key = keccak_256(health_label).digest()

##############################################
# Ursula, the Untrusted Re-Encryption Proxy  #
##############################################
ursula = Ursula.from_seed_and_stake_info(seed_uri=SEEDNODE_URI,
                                         federated_only=True,
                                         minimum_stake=0)

###################################################
# On-chain deployment of Decentralized Identities #
###################################################

# Alice deploys a ProxyAccount and a ClaimHolder, and refers to the latter in the former
w3.eth.defaultAccount = alice_eth_address
alice_proxy_account_address = deploy_contract(w3, proxy_account_interface)
alice_proxy_account = w3.eth.contract(address=alice_proxy_account_address,
                                      abi=proxy_account_interface['abi'])
alice_claim_holder_address = deploy_contract(w3, claim_holder_interface, alice_proxy_account_address)
alice_claim_holder = w3.eth.contract(address=alice_claim_holder_address,
                                      abi=claim_holder_interface['abi'])
tx_hash = alice_proxy_account.functions.setData(claim_holder_key, alice_claim_holder_address).transact()
w3.eth.waitForTransactionReceipt(tx_hash)

# Bob deploys a ProxyAccount
w3.eth.defaultAccount = bob_eth_address
bob_proxy_account_address = deploy_contract(w3, proxy_account_interface)
bob_proxy_account = w3.eth.contract(address=bob_proxy_account_address,
                                      abi=proxy_account_interface['abi'])

# Enrico deploys a ProxyAccount
w3.eth.defaultAccount = enrico_eth_address
enrico_proxy_account_address = deploy_contract(w3, proxy_account_interface)
enrico_proxy_account = w3.eth.contract(address=enrico_proxy_account_address,
                                      abi=proxy_account_interface['abi'])


######################################
# Alice, the Authority of the Policy #
######################################

alice = Alice(network_middleware=RestMiddleware(),
              domains={TEMPORARY_DOMAIN},
              known_nodes=[ursula],
              learn_on_same_thread=True,
              federated_only=True)
# store public keys on chain
w3.eth.defaultAccount = alice_eth_address
alice_nucypher_decrypting_pub_key = alice.public_keys(DecryptingPower).to_bytes()
tx_hash = alice_proxy_account.functions.setData(nucypher_decrypting_key, alice_nucypher_decrypting_pub_key).transact()
w3.eth.waitForTransactionReceipt(tx_hash)
alice_nucypher_signing_pub_key = alice.public_keys(SigningPower).to_bytes()
tx_hash = alice_proxy_account.functions.setData(nucypher_signing_key, alice_nucypher_signing_pub_key).transact()
w3.eth.waitForTransactionReceipt(tx_hash)

#########################
# Bob the data receiver #
#########################

bob = Bob(known_nodes=[ursula],
          domains={TEMPORARY_DOMAIN},
          network_middleware=RestMiddleware(),
          federated_only=True,
          start_learning_now=True,
          learn_on_same_thread=True)
# store public keys on chain
w3.eth.defaultAccount = bob_eth_address
bob_nucypher_decrypting_pub_key = bob.public_keys(DecryptingPower).to_bytes()
tx_hash = bob_proxy_account.functions.setData(nucypher_decrypting_key, bob_nucypher_decrypting_pub_key).transact()
w3.eth.waitForTransactionReceipt(tx_hash)
bob_nucypher_signing_pub_key = bob.public_keys(SigningPower).to_bytes()
tx_hash = bob_proxy_account.functions.setData(nucypher_signing_key, bob_nucypher_signing_pub_key).transact()
w3.eth.waitForTransactionReceipt(tx_hash)

#####################################################
# Alice creates the policy and grants access to Bob #
#####################################################

# Alice can get the public key even before creating the policy.
# From this moment on, any Data Source like Enrico that knows the public key
# can encrypt data originally intended for Alice, but that can be shared with
# any Bob that Alice grants access.
# To share this key, Alice stores it on-chain
policy_pubkey = alice.get_policy_encrypting_key_from_label(health_label)

# Alice stores the policy public key on chain
w3.eth.defaultAccount = alice_eth_address
tx_hash = alice_proxy_account.functions.setData(health_label_key, policy_pubkey.to_bytes()).transact()
w3.eth.waitForTransactionReceipt(tx_hash)

alice.start_learning_loop(now=True)

# Here are our Policy details.
policy_end_datetime = maya.now() + datetime.timedelta(days=5)
m, n = 2, 3

# Alice uses Bob's Decentralized ID on-chain to collects relevant data and create a Bob profile
bob_nucypher_decrypting_pub_key_as_seen_by_alice =  bob_proxy_account.functions.getData(nucypher_decrypting_key).call()
bob_nucypher_signing_pub_key_as_seen_by_alice =  bob_proxy_account.functions.getData(nucypher_signing_key).call()
bob_as_seen_by_alice = Bob.from_public_keys(powers_and_material={
    DecryptingPower: bob_nucypher_decrypting_pub_key_as_seen_by_alice,
    SigningPower: bob_nucypher_signing_pub_key_as_seen_by_alice})
# Alice grants access to Bob
policy = alice.grant(bob_as_seen_by_alice,
                     health_label,
                     m=m, n=n,
                     expiration=policy_end_datetime)
assert policy.public_key == policy_pubkey

# Alice can disappear from the Internet.
del alice

# Bob joins the Policy
alice_nucypher_signing_pub_key_as_seen_by_bob =  alice_proxy_account.functions.getData(nucypher_signing_key).call()
bob.join_policy(health_label, alice_nucypher_signing_pub_key_as_seen_by_bob)

# Threaded function simulating Bob's behaviour, watching for on-chain claims
def decrypt_first_message():
    ###############
    # Back to Bob #
    ###############

    # Bob watches for the first claim to be made on alice about her health
    claim_added_filter = alice_claim_holder.events.ClaimAdded.createFilter(fromBlock=0x0,
                                                                           argument_filters={'topic': health_label_key})
    while True:
        events = claim_added_filter.get_all_entries()
        if events:
            break
        sleep(0.2)

    # From details of the event, Bob knows who made the claim.
    # That way, he can refer to the right DID in order to fetch right verification/signing keys.
    event = events[0]
    assert event.args.issuer == enrico_eth_address
    enrico_nucypher_signing_pub_key_as_seen_by_bob = enrico_proxy_account.functions.getData(nucypher_signing_key).call()

    # He uses Alice's Decentralized ID to get the policy's public key
    policy_pubkey_bytes_as_seen_by_bob = alice_proxy_account.functions.getData(health_label_key).call()
    policy_pubkey_as_seen_by_bob = UmbralPublicKey.from_bytes(policy_pubkey_bytes_as_seen_by_bob)

    # Now he can create an instance of Enrico
    enrico_as_understood_by_bob = Enrico.from_public_keys(
        verifying_key=enrico_nucypher_signing_pub_key_as_seen_by_bob,
        policy_encrypting_key=policy_pubkey_as_seen_by_bob
    )

    # From details of the event, Bob can also get URI of claim data.
    # From this intermediary data, he finds URI of cipher data.
    claim_content = ipfs_client.get_json(event.args.uri)
    clear_data_hex_digest_as_seen_by_bob = claim_content['clearDataHexDigest']
    cipher_ipfs_hash_as_seen_by_bob = claim_content['encryptedDataIPFSHash']

    # Bob can recreate the encrypted message kit from data found on-chain and on IPFS
    cipher_as_seen_by_bob = ipfs_client.cat(cipher_ipfs_hash_as_seen_by_bob)
    cipher_kit_as_seen_by_bob = UmbralMessageKit.from_bytes(cipher_as_seen_by_bob)

    # Now Bob can retrieve the original message, as he was granted access by Alice
    delivered_clear_data_list = bob.retrieve(message_kit=cipher_kit_as_seen_by_bob,
                                        data_source=enrico_as_understood_by_bob,
                                        alice_verifying_key=UmbralPublicKey.from_bytes(
                                            alice_nucypher_signing_pub_key_as_seen_by_bob),
                                        label=health_label)
    delivered_clear_data = delivered_clear_data_list[0]

    # Anytime, without any additional interaction with NuCypher network, Bob can efficiently
    # verify his own possession of the clear data by comparing its digest to the one stored on IPFS
    # as part of the claim intermediary data.
    assert keccak_256(delivered_clear_data).hexdigest() == clear_data_hex_digest_as_seen_by_bob

    # Bob indeed received data he was granted access to by Alice
    print("========== DATA RETRIEVED ==========")
    print(delivered_clear_data.decode())


# Start a thread dedicated to Bob who is now watching for claims on-chain
thread = Thread(target=decrypt_first_message)
thread.start()

#######################
# some time passes.   #
# ...                 #
# ...                 #
# ...                 #
#######################

#########################
# Enrico, the Encryptor #
#########################

# Now that Bob has joined the Policy, let's show how Enrico the Encryptor
# can share data with the members of this Policy and then how Bob retrieves it.
with open('alices-health-record-from-enrico.txt', 'rb') as file:
    enricos_clear_data = file.read()

# Enrico uses Alice's Decentralized ID to get the policy's public key
policy_pubkey_bytes_as_seen_by_enrico = alice_proxy_account.functions.getData(health_label_key).call()
policy_pubkey_as_seen_by_enrico = UmbralPublicKey.from_bytes(policy_pubkey_bytes_as_seen_by_enrico)
enrico = Enrico(policy_encrypting_key=policy_pubkey_as_seen_by_enrico)

# Store public keys on chain
w3.eth.defaultAccount = enrico_eth_address
enrico_nucypher_signing_pub_key = enrico.public_keys(SigningPower).to_bytes()
tx_hash = enrico_proxy_account.functions.setData(nucypher_signing_key, enrico_nucypher_signing_pub_key).transact()
w3.eth.waitForTransactionReceipt(tx_hash)

# Encrypt the data
cipher_kit, _ = enrico.encrypt_message(enricos_clear_data)

# Push cipher to IPFS
cipher_ipfs_hash = ipfs_client.add_bytes(cipher_kit.to_bytes())

# Push digest of the clear data and ipfs hash of the cipher to IPFS
clear_data_hex_digest = keccak_256(enricos_clear_data).hexdigest()
claim_ipfs_hash = ipfs_client.add_json({
    "clearDataHexDigest": clear_data_hex_digest,
    "encryptedDataIPFSHash": cipher_ipfs_hash,
})

# Add claim on-chain
tx_hash = alice_claim_holder.functions.addClaim(health_label_key, claim_ipfs_hash).transact()
w3.eth.waitForTransactionReceipt(tx_hash)

# And leave...
del enrico

# Wait for Bob to decrypt the data before exiting
thread.join()
