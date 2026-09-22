MAX_DOCUMENT_SIZE = 100 * 1024 * 1024


def check_size(data: bytes, label: str = "document") -> None:
    if len(data) > MAX_DOCUMENT_SIZE:
        raise ValueError(
            f"{label} is {len(data)} bytes, exceeding MAX_DOCUMENT_SIZE "
            f"({MAX_DOCUMENT_SIZE} bytes) -- refusing to process it"
        )