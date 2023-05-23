build_image:
	GOOS=linux GOARCH=amd64 go build -o webdav main.go
	docker build -t webdav:latest .