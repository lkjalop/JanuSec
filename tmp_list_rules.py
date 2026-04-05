from src.core.correlation.rules.registry import CORRELATION_RULES
print([r.name for r in CORRELATION_RULES.list()])
