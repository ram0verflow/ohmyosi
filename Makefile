BIN := ohmyosi

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

clean:
	rm -f $(BIN)
	rm -rf dist/OhMyOSI.app dist/OhMyOSI.dmg

.PHONY: build run run-light test diff mac-app mac-watch mac-preview mac-dmg clean
