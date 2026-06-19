# syntax=docker/dockerfile:1
#
# omniban — reproducible static build of the binary.
# omniban manages the host firewall directly, so production installs are native
# packages (.deb/.rpm) or the install script. This image is for CI builds and
# reproducible release artifacts only.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/omniban ./cmd/omniban

FROM alpine:3.21
RUN apk --no-cache add ca-certificates
COPY --from=build /out/omniban /usr/local/bin/omniban
ENTRYPOINT ["/usr/local/bin/omniban"]
