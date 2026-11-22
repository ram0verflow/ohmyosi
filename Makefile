BIN := ohmyosi
NETWORK ?= unlabelled
REPEAT ?= 1

build:
	go build -o $(BIN) ./cmd/ohmyosi

mac-app:
	DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer ./mac/build-app.sh

# Render the canvas headlessly to a PNG. Needs the daemon running, since it
# draws whatever is actually on the wire.
# Rebuild + relaunch on every source change. Start once, leave running.
mac-watch:
	./mac/watch.sh

mac-preview: mac-app
	./dist/OhMyOSI.app/Contents/MacOS/OhMyOSI --verify --snapshot $(PWD)/dist/ui-preview.png
	@echo "wrote dist/ui-preview.png"

mac-dmg:
	DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer ./mac/build-app.sh --dmg

run: build
	sudo ./$(BIN)

# Headers only: much lower overhead, no SNI.
run-light: build
	sudo ./$(BIN) -snaplen 128 -no-icons

test:
	go test -race ./...

# Compare two recordings: make diff A=~/sessions/mon.ndjson B=~/sessions/tue.ndjson
diff: build
	./$(BIN) -diff $(A),$(B)

# ACN: controlled experiment with ground truth. No root, no network.
lab: build
	@mkdir -p dist
	go run ./cmd/acn-lab -o dist/lab.pcapng
	./$(BIN) -eval dist/lab.pcapng -truth dist/lab.truth.json -eval-block telemetry-vendor.example

# ACN: capture this machine for a while, then measure it. Needs root for pktap.
field: build
	./tools/field.sh

# ACN main experiment: fixed Tranco list x browser x DoH x cold/warm cache.
# sudo make workload NETWORK=home REPEAT=1   (then REPEAT=2, 3 on other days)
workload:
	NETWORK=$(NETWORK) REPEAT=$(REPEAT) ./tools/workload/run.sh

# ACN: launch-and-idle session per installed desktop app.
apps:
	NETWORK=$(NETWORK) REPEAT=$(REPEAT) ./tools/workload/apps.sh

# ACN: measure every capture in dist/runs; tables to stdout, one CSV row per run.
report: build
	./$(BIN) -report dist/runs -report-csv dist/runs.csv

clean:
	rm -f $(BIN)
	rm -rf dist/OhMyOSI.app dist/OhMyOSI.dmg

.PHONY: build run run-light test diff lab field workload apps report mac-app mac-watch mac-preview mac-dmg clean
