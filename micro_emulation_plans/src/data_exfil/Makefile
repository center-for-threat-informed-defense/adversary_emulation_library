BINARY_NAME=data_exfil

all: windows linux

windows:
	GOARCH=amd64 GOOS=windows go build -o bin/${BINARY_NAME}_windows.exe cmd/main.go

linux:
	GOARCH=amd64 GOOS=linux go build -o bin/${BINARY_NAME}_linux cmd/main.go

clean:
	go clean
	go mod tidy
	rm bin/*
