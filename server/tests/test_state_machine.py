from app.state_machine import EvidenceStateMachine

def test_valid_seal_path():
    s=EvidenceStateMachine("capture_received")
    s=s.transition("verified").transition("sealed")
    assert s.state == "sealed"

def test_rewind_is_rejected():
    s=EvidenceStateMachine("sealed")
    try:
        s.transition("verified")
        assert False
    except ValueError as e:
        assert str(e) == "illegal_evidence_transition:sealed->verified"

def test_terminal_states_are_terminal():
    for state in ("voided", "rejected"):
        try:
            EvidenceStateMachine(state).transition("sealed")
            assert False
        except ValueError:
            pass
