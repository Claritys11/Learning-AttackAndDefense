"""Tiny local solver used to test the wave controller without sockets."""
def always_flag(target):
    return f"FLAG{{fixture-{target.id}}}"
