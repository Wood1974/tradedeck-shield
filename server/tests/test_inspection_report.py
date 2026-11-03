"""The inspection report's AI block and human approval, and the offline checker, agree and refuse what they must.

No AI is called: findings here are synthetic. The approval is signed with a throwaway P-256 key standing in for a phone's hardware key.
"""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import inspection_report as ir

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("shield_inspection_verify", ROOT / "verifier" / "shield_inspection_verify.py")
iv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iv)

b64 = lambda raw: base64.b64encode(raw).decode("ascii")
H = lambda c: c * 64
FINDINGS = [
    {"id": "f1", "category": "material", "status": "found", "text": "Pressure-treated lumber sill plate.", "confidence_permille": 870},
    {"id": "f2", "category": "defect", "status": "found", "text": "Honeycombing at the lower left of the pour.", "confidence_permille": 620},
    {"id": "f3", "category": "missing-step", "status": "abstain", "text": "Cannot tell from this angle whether anchor bolts are present.", "confidence_permille": None},
]


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


@pytest.fixture
def analysis(monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setenv("SHIELD_ANALYSIS_SIGNING_KEY_PEM", pem(key))
    return key


def signed(findings=None, run_id=None):
    return ir.sign_ai_block(photo_sha256=H("a"), record_hash=H("b"), checkpoint_context_sha256=H("c"), model_id="model-x",
                            prompt_sha256=H("d"), raw_output_sha256=H("e"), findings=copy.deepcopy(FINDINGS if findings is None else findings),
                            evaluation_run_id=run_id, now=lambda: 1_700_000_000_000)


class Phone:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.point = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def approve(self, env, decisions, shown=None):
        approval = {"version": 1, "ai_block_sha256": env["ai_block_sha256"], "decisions": decisions, "reviewed_at_ms": 1_700_000_500_000,
                    "effort": {"shown_finding_ids": shown if shown is not None else [d["finding_id"] for d in decisions], "screen_ms": 41000}}
        sig = self.key.sign(ir.approval_client_data(approval), ec.ECDSA(hashes.SHA256()))
        return {"approval": approval, "signature_der_b64": b64(sig), "public_key_uncompressed_b64": b64(self.point)}


def report(env, approval=None, phone=None):
    integrity = {"record_hash": H("b"), "photo_sha256": H("a")}
    if phone:
        integrity["public_key_uncompressed_b64"] = b64(phone.point)
    return {"report_version": 1, "integrity": integrity, "ai": env, "human_approval": approval}


def pinned(analysis_key):
    return b64(analysis_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def tags(lines):
    return {t for t, _ in lines if t}


def test_signing_is_closed_without_a_key(monkeypatch):
    monkeypatch.delenv("SHIELD_ANALYSIS_SIGNING_KEY_PEM", raising=False)
    with pytest.raises(ir.AnalysisClosed):
        signed()


def test_a_wrong_kind_of_key_is_refused(monkeypatch):
    monkeypatch.setenv("SHIELD_ANALYSIS_SIGNING_KEY_PEM", pem(ec.generate_private_key(ec.SECP384R1())))
    with pytest.raises(ir.AnalysisClosed):
        signed()


def test_a_pinned_key_passes_and_nothing_is_called_validated(analysis):
    env = signed()
    code, lines = iv.check(report(env), pinned(analysis))
    assert code == 3  # no human approval yet: not a full pass, and said so
    assert not any(t == "FAILED" for t, _ in lines)
    text = "\n".join(x for _, x in lines)
    assert "AI findings, not validated" in text and "not reviewed" in text.lower()
    assert "the signing key is the analysis key you pinned" in text


def test_without_a_pinned_key_the_source_is_not_checked(analysis):
    code, lines = iv.check(report(signed()))
    assert code == 3 and ("NOT CHECKED", "that the signing key is Shield's analysis key (pass --analysis-key with the published public key)") in lines


def test_another_key_than_the_pinned_one_fails(analysis):
    other = pinned(ec.generate_private_key(ec.SECP256R1()))
    assert iv.check(report(signed()), other)[0] == 2


def test_a_full_report_with_approval_checks_clean_and_labels_unreviewed(analysis):
    phone, env = Phone(), signed()
    approval = phone.approve(env, [{"finding_id": "f1", "decision": "accepted"}, {"finding_id": "f2", "decision": "rejected"}], shown=["f1", "f2", "f3"])
    code, lines = iv.check(report(env, approval, phone), pinned(analysis))
    assert code == 0, lines
    text = "\n".join(x for _, x in lines)
    assert "1 accepted, 1 rejected, 1 not reviewed" in text and "AI, not reviewed: f3" in text
    assert "approved with the same key that signed the photo" in text
    assert "OUT OF SCOPE" in tags(lines) | {t for t, _ in lines}


def test_a_different_approver_key_is_reported_as_a_fact_not_a_failure(analysis):
    env, photo_phone, other = signed(), Phone(), Phone()
    approval = other.approve(env, [{"finding_id": "f1", "decision": "accepted"}])
    code, lines = iv.check(report(env, approval, photo_phone), pinned(analysis))
    assert code == 0 and any("a different key than the one that signed the photo" in x for _, x in lines)


def test_a_named_evaluation_run_is_not_checked_by_this_file(analysis):
    code, lines = iv.check(report(signed(run_id="run-7")), pinned(analysis))
    assert any(t == "NOT CHECKED" and "run-7" in x for t, x in lines) and not any("not validated" in x for _, x in lines)


@pytest.mark.parametrize("edit", ["text", "confidence", "photo", "model", "add_finding", "swap_signature"])
def test_any_change_to_the_signed_ai_block_fails(analysis, edit):
    env = signed()
    other = signed(findings=[{**FINDINGS[0], "text": "A different block, validly signed."}])  # ECDSA is randomized: a second signature over the SAME block would also verify
    if edit == "text":
        env["ai_block"]["findings"][0]["text"] = "Different words."
    elif edit == "confidence":
        env["ai_block"]["findings"][0]["confidence_permille"] = 999
    elif edit == "photo":
        env["ai_block"]["photo_sha256"] = H("f")
    elif edit == "model":
        env["ai_block"]["model_id"] = "other-model"
    elif edit == "add_finding":
        env["ai_block"]["findings"].append({"id": "f9", "category": "defect", "status": "found", "text": "New.", "confidence_permille": 1})
    else:
        env["signature_der_b64"] = other["signature_der_b64"]
    env["ai_block_sha256"] = hashlib.sha256(iv.canonical(env["ai_block"])).hexdigest()  # an attacker fixes the hash too
    assert iv.check(report(env), pinned(analysis))[0] == 2


def test_findings_about_another_photo_than_the_report_names_fail(analysis):
    r = report(signed())
    r["integrity"]["photo_sha256"] = H("9")
    assert iv.check(r, pinned(analysis))[0] == 2


def test_the_server_refuses_malformed_findings(analysis):
    bad = [
        [{**FINDINGS[0], "category": "opinion"}],
        [{**FINDINGS[0], "status": "maybe"}],
        [{**FINDINGS[0], "confidence_permille": 1001}],
        [{**FINDINGS[0], "confidence_permille": 0.5}],
        [{**FINDINGS[2], "confidence_permille": 500}],  # an abstention carries no confidence
        [{**FINDINGS[0], "text": "  "}],
        [FINDINGS[0], FINDINGS[0]],  # duplicate id
        [{**FINDINGS[0], "extra": 1}],
    ]
    for findings in bad:
        with pytest.raises(ir.Invalid):
            signed(findings)


def test_a_human_cannot_edit_only_accept_or_reject(analysis):
    env, phone = signed(), Phone()
    for decision in ({"finding_id": "f1", "decision": "edited"}, {"finding_id": "f1", "decision": "accepted", "text": "my wording"},
                     {"finding_id": "f1", "decision": "accepted", "replacement": "x"}):
        approval = phone.approve(env, [decision])
        r = report(env, approval, phone)
        assert iv.check(r, pinned(analysis))[0] == 2
        with pytest.raises(ir.Invalid):
            ir.validated_approval(approval["approval"], env["ai_block"])


def test_an_approval_over_a_modified_block_or_a_missing_finding_fails(analysis):
    env, phone = signed(), Phone()
    good = phone.approve(env, [{"finding_id": "f1", "decision": "accepted"}])
    # the approval travels with a different AI block (same photo, other words)
    other = signed(findings=[{**FINDINGS[0], "text": "Something else."}])
    assert iv.check(report(other, good, phone), pinned(analysis))[0] == 2
    with pytest.raises(ir.Invalid):
        ir.validated_approval(good["approval"], other["ai_block"])
    # a finding id the block does not have
    assert iv.check(report(env, phone.approve(env, [{"finding_id": "f77", "decision": "accepted"}], shown=[]), phone), pinned(analysis))[0] == 2
    # decided twice
    assert iv.check(report(env, phone.approve(env, [{"finding_id": "f1", "decision": "accepted"}, {"finding_id": "f1", "decision": "rejected"}]), phone), pinned(analysis))[0] == 2


def test_a_finding_cannot_be_decided_without_being_shown(analysis):
    env, phone = signed(), Phone()
    approval = phone.approve(env, [{"finding_id": "f1", "decision": "accepted"}], shown=["f2"])
    assert iv.check(report(env, approval, phone), pinned(analysis))[0] == 2
    with pytest.raises(ir.Invalid):
        ir.validated_approval(approval["approval"], env["ai_block"])


def test_a_tampered_approval_signature_or_decision_fails(analysis):
    env, phone = signed(), Phone()
    approval = phone.approve(env, [{"finding_id": "f1", "decision": "accepted"}])
    flipped = copy.deepcopy(approval)
    flipped["approval"]["decisions"][0]["decision"] = "rejected"
    assert iv.check(report(env, flipped, phone), pinned(analysis))[0] == 2
    forged = copy.deepcopy(approval)
    forged["signature_der_b64"] = b64(Phone().key.sign(ir.approval_client_data(approval["approval"]), ec.ECDSA(hashes.SHA256())))
    assert iv.check(report(env, forged, phone), pinned(analysis))[0] == 2


def test_the_checker_and_the_server_agree_on_the_bytes_that_are_signed(analysis):
    env = signed()
    assert hashlib.sha256(iv.canonical(env["ai_block"])).hexdigest() == ir.ai_block_sha256(env["ai_block"]) == env["ai_block_sha256"]
    assert ir.public_info()["kid"] == env["ai_block"]["kid"]


def test_no_ai_section_says_so_and_never_passes(analysis):
    code, lines = iv.check(report(None))
    assert code == 3 and ("NOT PRESENT", "no AI findings in this report") in lines


def test_garbage_input_fails_closed(analysis):
    for junk in ({}, [], "x", {"report_version": 2}, {"report_version": 1}, {"report_version": 1, "integrity": {}}):
        assert iv.check(junk)[0] == 2


def test_the_command_line_exit_codes(analysis, tmp_path, capsys):
    phone, env = Phone(), signed()
    approval = phone.approve(env, [{"finding_id": "f1", "decision": "accepted"}], shown=["f1", "f2", "f3"])
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report(env, approval, phone)))
    assert iv.main([str(path), "--analysis-key", pinned(analysis)]) == 0
    assert "== AI FINDINGS ==" in capsys.readouterr().out
    assert iv.main([str(path)]) == 3
