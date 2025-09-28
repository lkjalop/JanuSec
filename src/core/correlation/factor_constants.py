"""Central definitions for lane factor and correlation factor identifiers.

This reduces drift risk when renaming lane emissions or correlation outputs.
Import these constants in rules and tests instead of hardcoding strings.
"""
# Lane factor prefixes (governance: all lane emissions must start with lane_<lane_name>:)
LANE_PROCESS_LINEAGE_PREFIX = "lane_process_lineage:"
LANE_JA3_NOVELTY_PREFIX = "lane_ja3_novelty:"

# Specific lane factor suffixes
OFFICE_MACRO_SPAWN_POWERSHELL = f"{LANE_PROCESS_LINEAGE_PREFIX}office_macro_spawn_powershell"
POWERSHELL_ENCODED_COMMAND = f"{LANE_PROCESS_LINEAGE_PREFIX}powershell_encoded_command"
SIGNED_TO_UNSIGNED_TRANSITION = f"{LANE_PROCESS_LINEAGE_PREFIX}signed_to_unsigned_transition"
PROC_PARENT_CHAIN = f"{LANE_PROCESS_LINEAGE_PREFIX}proc_parent_chain"  # generic parent chain factor
JA3_RARE = f"{LANE_JA3_NOVELTY_PREFIX}ja3_rare"

# Correlation factor outputs
CORR_OFFICE_PS_RARE_JA3 = "corr_office_ps_rare_ja3"
CORR_ENCODED_PS_SIGNED_TO_UNSIGNED = "corr_encoded_ps_signed_to_unsigned"
CORR_LATERAL_PIVOT_POSSIBLE = "corr_lateral_pivot_possible"

ALL_CORR_FACTORS = {
    CORR_OFFICE_PS_RARE_JA3,
    CORR_ENCODED_PS_SIGNED_TO_UNSIGNED,
    CORR_LATERAL_PIVOT_POSSIBLE,
}
