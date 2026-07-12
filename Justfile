desktop:
    nix-shell -p iw usbutils
build:
    GOOS=linux GOARCH=amd64 go build .
