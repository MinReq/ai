"""Checks for file paths named on the command line, shared by
gptlive_call.py and webhook_server.py: keep this file next to them.

Only a file directly in the user's home directory or in the current
directory is accepted, and a symbolic link there must point inside one of
them, so a mistyped or injected argument cannot reach other files. The
returned path is rebuilt from that directory and the name as given, so the
kernel follows a link the same way it would without this check. Stdlib only.
"""
import os
import sys


def current_dir():
    try:
        return os.path.realpath(os.getcwd())
    except OSError:  # the current directory was deleted
        return None


def same_file(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def inside(path, bases):
    """True when path lies in one of bases or below it. Folders are compared
    by identity, so letter case and folder aliases do not matter."""
    folder = os.path.dirname(path)
    while not any(same_file(folder, d) for d in bases):
        parent = os.path.dirname(folder)
        if parent == folder:
            return False
        folder = parent
    return True


def user_path(path, flag, hint=""):
    """The path to open for the value of option flag, or exit with a message.
    hint is appended to the refusal and says what to do instead."""
    home, cwd = os.path.realpath(os.path.expanduser("~")), current_dir()
    raw = os.path.expanduser(path)
    if cwd is None and not os.path.isabs(raw):
        sys.exit(f"{flag} {path}: the current directory no longer exists")
    # No normpath: a ".." after a linked folder must mean what it means to the kernel.
    given = raw if os.path.isabs(raw) else os.path.join(cwd, raw)
    bases = [d for d in (home, cwd) if d]
    base = next((d for d in bases if same_file(os.path.dirname(given), d)), None)
    if base is None:
        sys.exit(f"{flag} must name a file directly in your home directory or the "
                 f"current directory, not {path}. Move it there or run from its "
                 f"folder{hint}.")
    target = os.path.realpath(given)
    if os.path.islink(given) and not inside(target, bases):
        sys.exit(f"{flag} {path} is a link to {target}, outside your home "
                 "directory and the current directory")
    # realpath() guesses when a path gets too long; the kernel does not. Refuse
    # unless the file the kernel reaches is the one checked above.
    if os.path.exists(given) and not same_file(given, target):
        sys.exit(f"{flag} {path}: cannot confirm that the file it leads to is "
                 "in your home directory or the current directory; name that file "
                 "itself")
    return os.path.join(base, os.path.basename(given))
