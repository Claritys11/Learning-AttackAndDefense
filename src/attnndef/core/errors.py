class AttnndefError(Exception):
    """Base class for all package-specific errors."""


class TargetNotFoundError(AttnndefError):
    pass


class TargetTimeoutError(AttnndefError):
    pass


class ExtractionError(AttnndefError):
    pass


class PatchError(AttnndefError):
    pass


class RollbackError(AttnndefError):
    pass


class HealthCheckError(AttnndefError):
    pass
