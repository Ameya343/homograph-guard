PY ?= python3
IMAGE ?= homograph-guard:latest

.PHONY: install test check-install lint docker run gui firewall-up firewall-down extension-data extension-test extension-e2e extension-compat extension-browser lab-linux lab-systemd lab-enterprise
BROWSER ?= edge

install:            ## editable install with dev tools
	$(PY) -m pip install -e ".[dev]"

test:               ## unit + local DNS-lab tests (GUI test runs when a display exists)
	$(PY) -m pytest -q

check-install:      ## build a wheel, install it in a fresh venv, run the installed commands
	PY=$(PY) bash scripts/check-install.sh

extension-data:     ## regenerate extension/lib/data.js and the shared analysis vectors
	$(PY) scripts/build_extension_data.py

extension-test:     ## JavaScript unit tests of the extension (Node 22+)
	node --test "extension/tests/*.test.mjs"

extension-e2e:      ## the extension in Playwright's Chromium, alone and through the app (pip install playwright; playwright install chromium)
	$(PY) extension/tests/e2e.py
	HG_NATIVE=1 $(PY) extension/tests/e2e.py

extension-compat:   ## sites keep working with the extension (add LIVE=--live for the real sign-in pages)
	$(PY) extension/tests/compat.py compat-shots $(LIVE)

extension-browser:  ## the extension in your installed browser: make extension-browser BROWSER=chrome
	cd browser-test && npm install --no-audit --no-fund && node run.mjs --browser $(BROWSER)

lint:               ## static checks
	$(PY) -m ruff check src tests scripts extension/tests packaging
	$(PY) -m bandit -q -r src -c pyproject.toml

docker:             ## build the hardened image
	docker build -t $(IMAGE) .

run:                ## make run URL=https://example.com
	sandbox/run.sh "$(URL)"

gui:                ## desktop GUI (uses the Docker image when it exists)
	$(PY) -m homograph_guard.gui

firewall-up:        ## Linux: create the egress-firewalled Docker network
	sudo sandbox/egress-firewall.sh up

firewall-down:
	sudo sandbox/egress-firewall.sh down

lab-linux:          ## Docker: test suite + extension end to end on Debian, as a normal user
	bash labs/linux/run.sh

lab-systemd:        ## Docker: the daily update timer under a real systemd (privileged container)
	bash labs/systemd/run.sh

lab-enterprise:     ## Docker: no direct internet, TLS-inspecting proxy, internal mirror, request log
	bash labs/enterprise/run.sh $(PY)
