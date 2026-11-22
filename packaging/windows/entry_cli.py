"""homograph-guard.exe - the command-line tool (also the GUI's isolated worker)."""

from homograph_guard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
