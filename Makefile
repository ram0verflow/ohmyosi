BIN := ohmyosi

build:
	go build -o $(BIN) ./cmd/ohmyosi

run: build
	sudo ./$(BIN)

# Headers only: much lower overhead, no SNI.
run-light: build
	sudo ./$(BIN) -snaplen 128 -no-icons

test:
	go test -race ./...

clean:
	rm -f $(BIN)

.PHONY: build run run-light test clean
