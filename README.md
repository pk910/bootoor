# Bootoor - Ethereum Discovery v5 (discv5) Library

A complete, production-ready implementation of the Ethereum Discovery v5 protocol in Go.

## Features

- **Complete discv5 Protocol**: Full implementation of the discv5 wire protocol
- **ENR Support**: Ethereum Node Records with generic filtering
- **UDP Server**: Listen and serve PING/PONG, FINDNODE/NODES, TALKREQ/TALKRESP
- **Node Database**: Persistent storage with statistics tracking
- **Aliveness Monitoring**: Automatic PING checks with dead node removal
- **Generic Filtering**: Callback-based ENR filtering for application-specific logic
- **Session Management**: Encrypted messaging with handshake protocol
- **Kademlia Routing**: DHT-based routing table for efficient peer discovery

## Quick Start

```go
package main

import (
    "github.com/pk910/bootoor/client"
)

func main() {
    // Create a new discv5 client
    c, err := client.NewClient(
        client.WithPort(9000),
    )
    if err != nil {
        panic(err)
    }

    // Start the service
    if err := c.Start(); err != nil {
        panic(err)
    }
    defer c.Stop()

    // Discover peers
    peers := c.FindPeers(nil)
    for _, peer := range peers {
        println("Found peer:", peer.ID())
    }
}
```

## Installation

```bash
go get github.com/pk910/bootoor
```

## Development

```bash
# Build
make build

# Run tests
make test

# Run tests with coverage
make coverage

# Run linters
make lint

# Format code
make fmt
```

## License

MIT License - see LICENSE file for details.
