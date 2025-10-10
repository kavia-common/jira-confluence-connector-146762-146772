def mask_secret(value: str, keep: int = 4) -> str:
    """Mask secret preserving last 'keep' chars."""
    if not value:
        return value
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]
