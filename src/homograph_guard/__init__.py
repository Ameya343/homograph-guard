"""homograph-guard: IDN homograph phishing URL checker.

The checker never opens the URL it is given. It treats the URL purely as data,
inspects the hostname for look-alike characters, and (optionally) compares how
several public DNS resolvers answer for it.
"""

import os as _os
import sys as _sys

__version__ = "1.3.0"


def _restore_user_site() -> None:
    """Let ``python -I`` workers find dependencies installed with ``pip --user``.

    The GUI worker and the Docker entry point run under ``python -I`` so that
    PYTHONPATH, PYTHONSTARTUP and the current directory cannot inject code. -I
    also drops user site-packages, which is where ``pip install --user`` and the
    Microsoft Store Python put dnspython and idna, so the worker would fail to
    start. The directory is appended as a plain path: system packages still win
    and its ``.pth`` files are not executed. Virtual environments are left alone.
    """
    if not _sys.flags.isolated or _sys.prefix != _sys.base_prefix:
        return
    try:
        import site

        user_site = site.getusersitepackages()
    except Exception:  # nosec B110
        return  # best effort: the ImportError that follows is clearer than anything raised here
    if isinstance(user_site, str) and _os.path.isdir(user_site) and user_site not in _sys.path:
        _sys.path.append(user_site)


_restore_user_site()
