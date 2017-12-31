package cmd

import (
	"github.com/spf13/cobra"
)

var lbServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage load balancer services",
}

func init() {
	lbCmd.AddCommand(lbServiceCmd)
}
