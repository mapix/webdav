build_image:
	GOOS=linux GOARCH=amd64 go build -o webdav main.go
	docker buildx build --network=host --platform linux/amd64 -t webdav:latest .