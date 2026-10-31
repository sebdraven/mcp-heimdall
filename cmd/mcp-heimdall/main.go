// Command mcp-heimdall serves the Heimdall API over MCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
	"github.com/sebdraven/mcp-heimdall/internal/mcptools"
	"github.com/sebdraven/mcp-heimdall/internal/service"
)

var version = "dev"

func main() {
	showVer := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	client, err := heimdall.FromEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "heimdall",
		Version: version,
	}, nil)
	mcptools.Register(server, service.New(client))

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server: %v", err)
	}
}
