FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM nicolaka/netshoot:v0.11
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 80
COPY webdav /webdav

ENTRYPOINT [ "/webdav" ]
