"""hg-native-host.exe - started by the browser for the Homograph Guard extension (native messaging)."""

from homograph_guard.native_host import main

if __name__ == "__main__":
    raise SystemExit(main())
