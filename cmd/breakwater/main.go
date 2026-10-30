package main

import (
	"os"

	"github.com/stympy/breakwater-cli/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
