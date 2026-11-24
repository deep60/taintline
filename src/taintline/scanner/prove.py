"""A static finding is a suspicion. Each one that can be tested gets the command that tests it.

Risk-shaped findings (a trifecta, a poisoned description, a shadowed tool, broad file access,
auto-approval) map to a `taintline session` lab with the same shape: your own client runs against
it, and a leak at the sink proves the risk is real for that client. Supply-chain findings map to
`monitor`, which catches the change when it happens. Plain facts (a pasted secret, plain http)
need no proof and get none.
"""
from __future__ import annotations

SESSION_WHY = "runs your client against a lab with the same shape; a leak at the sink proves it"

# kind -> (command, why). {file} is the config file the finding is in.
PROOF: dict[str, tuple[str, str]] = {
    "lethal_trifecta_across_servers": ("taintline session start --lab files+inbox", SESSION_WHY),
    "lethal_trifecta_across_servers/url": ("taintline session start --lab db+web", SESSION_WHY),
    "lethal_trifecta_in_server": ("taintline session start --lab inbox", SESSION_WHY),
    "broad_filesystem": ("taintline session start --lab files+inbox", SESSION_WHY),
    "auto_approved_tools": ("taintline session start --lab notes",
                            "auto-approve the taintline-* tools the same way, then see whether a leak needs a click"),
    "unpinned_package": ("taintline monitor --config {file}", "pins the tools now and alerts when a launch pulls new ones"),
    "mutable_image_tag": ("taintline monitor --config {file}", "pins the tools now and alerts when the image changes"),
    # tool-manifest scan findings
    "poisoned_description": ("taintline session start --lab poisoned+inbox --attack native_poison", SESSION_WHY),
    "duplicate_tool_name": ("taintline session start --lab shadow+inbox", SESSION_WHY),
    "lethal_trifecta": ("taintline session start --lab inbox", SESSION_WHY),
}
POISON_KINDS = {"override_instruction", "hidden_directive_tag", "concealment_from_user", "sensitive_path_reference",
                "pre_call_instruction", "exfil_destination", "cross_tool_steering", "hidden_unicode",
                "unusually_long_description"}


def proof_for(kind: str, file: str = "") -> dict | None:
    key = "poisoned_description" if kind in POISON_KINDS else kind.split(" ")[0]
    if key not in PROOF:
        return None
    cmd, why = PROOF[key]
    return {"command": cmd.format(file=file), "why": why}
