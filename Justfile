desktop:
    nix-shell -p iw usbutils
    sudo iptables -I nixos-fw 5 -p udp --dport 67 -j nixos-fw-accept
    sudo iptables -I nixos-fw 6 -p udp --dport 53 -j nixos-fw-accept
build:
    GOOS=linux GOARCH=amd64 go build .
