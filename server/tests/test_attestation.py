import base64, hashlib, os, struct, tempfile
import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from app.attestation import AttestationVerifier
from app.store import Store

def make_assertion(private_key, app_id, client_data_hash, counter):
    auth = hashlib.sha256(app_id.encode()).digest() + b"\x01" + struct.pack(">I", counter)
    nonce = hashlib.sha256(auth + client_data_hash).digest()
    sig = private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(cbor2.dumps({"signature": sig, "authenticatorData": auth})).decode()

def setup(td, account="acct-1"):
    store=Store("sqlite:///"+os.path.join(td,"shield.db"),os.path.join(td,"storage"))
    key=ec.generate_private_key(ec.SECP256R1())
    raw=key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    key_id=base64.b64encode(hashlib.sha256(raw).digest()).decode()
    der=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    store.save_attestation_key(key_id,account,base64.b64encode(der).decode(),"development","")
    return store,key,key_id

def test_assertion_signature_counter_and_replay():
    with tempfile.TemporaryDirectory() as td:
        store,key,key_id=setup(td)
        app_id="TEAM.com.tradedeck.shield"; client_hash=hashlib.sha256(b"canonical-bind-hash").digest()
        v=AttestationVerifier("development",app_id,store=store)
        assertion=make_assertion(key,app_id,client_hash,1)
        ok=v.verify_assertion(assertion,client_hash.hex(),key_id,account_id="acct-1")
        assert ok["trusted"] is True
        replay=v.verify_assertion(assertion,client_hash.hex(),key_id,account_id="acct-1")
        assert replay["status"]=="assertion_counter_not_increasing"

def test_assertion_wrong_account_rejected():
    with tempfile.TemporaryDirectory() as td:
        store,key,key_id=setup(td)
        app_id="TEAM.com.tradedeck.shield"; client_hash=hashlib.sha256(b"bind").digest()
        v=AttestationVerifier("development",app_id,store=store)
        assertion=make_assertion(key,app_id,client_hash,1)
        result=v.verify_assertion(assertion,client_hash.hex(),key_id,account_id="acct-2")
        assert result["status"]=="attestation_key_account_mismatch"
