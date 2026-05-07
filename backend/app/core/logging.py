import logging


def configure_logging() -> None:
    """Configure consistent application logging for local development."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
