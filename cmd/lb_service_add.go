package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jpignata/fargate/console"
	ECS "github.com/jpignata/fargate/ecs"
	ELBV2 "github.com/jpignata/fargate/elbv2"
	"github.com/spf13/cobra"
)

type LbServiceAddOperation struct {
	LoadBalancerName string
	ServiceName      string
	Ports            []Port
	Rules            []ELBV2.Rule
}

func (o *LbServiceAddOperation) SetPorts(inputPorts []string) {
	var msgs []string
	var protocols []string

	ports := inflatePorts(inputPorts)
	validProtocols := regexp.MustCompile(validProtocolsPattern)

	for _, port := range ports {
		if !validProtocols.MatchString(port.Protocol) {
			msgs = append(msgs, fmt.Sprintf("Invalid protocol %s [specify TCP, HTTP, or HTTPS]", port.Protocol))
		}

		if port.Port < minPort || port.Port > maxPort {
			msgs = append(msgs, fmt.Sprintf("Invalid port %d [specify within 1 - 65535]", port.Port))
		}

		if port.Protocol == protocolTcp {
			for _, protocol := range protocols {
				if protocol == protocolHttp || protocol == protocolHttps {
					msgs = append(msgs, "load balancers do not support comingled groups of TCP and HTTP/HTTPS ports")
				}
			}
		}

		if port.Protocol == protocolHttp || port.Protocol == protocolHttps {
			for _, protocol := range protocols {
				if protocol == protocolTcp {
					msgs = append(msgs, "load balancers do not support comingled groups of TCP and HTTP/HTTPS ports")
				}
			}
		}

		protocols = append(protocols, port.Protocol)
	}

	if len(msgs) > 0 {
		console.ErrorExit(fmt.Errorf(strings.Join(msgs, ", ")), "Invalid command line flags")
	}

	o.Ports = ports
}

func (o *LbServiceAddOperation) SetRules(inputRules []string) {
	var rules []ELBV2.Rule
	var msgs []string

	validRuleTypes := regexp.MustCompile(validRuleTypesPattern)

	for _, inputRule := range inputRules {
		splitInputRule := strings.SplitN(inputRule, "=", 2)

		if len(splitInputRule) != 2 {
			msgs = append(msgs, "rules must be in the form of type=value")
		}

		if !validRuleTypes.MatchString(splitInputRule[0]) {
			msgs = append(msgs, fmt.Sprintf("Invalid rule type %s [must be path or host]", splitInputRule[0]))
		}

		rules = append(rules,
			ELBV2.Rule{
				Type:  strings.ToUpper(splitInputRule[0]),
				Value: splitInputRule[1],
			},
		)
	}

	if len(msgs) > 0 {
		console.ErrorExit(fmt.Errorf(strings.Join(msgs, ", ")), "Invalid rule")
	}

	o.Rules = rules
}

var (
	flagLbServiceAddPorts []string
	flagLbServiceAddRules []string
)

var lbServiceAddCmd = &cobra.Command{
	Use:   "add <load-balancer-name> <service-name>",
	Short: "Add a service to a load balancer",
	Long:  "Add a service to a load balancer",

	Run: func(cmd *cobra.Command, args []string) {
		operation := &LbServiceAddOperation{
			LoadBalancerName: args[0],
			ServiceName:      args[1],
		}

		if len(flagLbServiceAddPorts) > 0 {
			operation.SetPorts(flagLbServiceAddPorts)
		}

		if len(flagLbServiceAddRules) > 0 {
			operation.SetRules(flagLbServiceAddRules)
		}

		addServiceToLoadBalancer(operation)
	},
}

func init() {
	lbServiceAddCmd.Flags().StringSliceVarP(&flagLbServiceAddPorts, "port", "p", []string{}, "Port from which to add service [e.g., 80, 443, http:8080, https:8443, tcp:1935] (can be specified multiple times)")
	lbServiceAddCmd.Flags().StringSliceVarP(&flagLbServiceAddRules, "rule", "r", []string{}, "Routing rule for the service [e.g. host=api.example.com, path=/api/*]; if omitted service will be the default route (can be specified multiple times)")

	lbServiceCmd.AddCommand(lbServiceAddCmd)
}

func addServiceToLoadBalancer(operation *LbServiceAddOperation) {
	var listeners []ELBV2.Listener

	elbv2 := ELBV2.New(sess)
	ecs := ECS.New(sess, clusterName)
	service := ecs.DescribeService(operation.ServiceName)
	loadBalancer := elbv2.DescribeLoadBalancer(operation.LoadBalancerName)

	if len(operation.Ports) > 0 {
		for _, listener := range elbv2.GetListeners(loadBalancer.Arn) {
			for _, port := range operation.Ports {
				if port.Port == listener.Port && port.Protocol == listener.Protocol {
					listeners = append(listeners, listener)
					break
				}

				console.IssueExit("Could not find port %s", port.String())
			}
		}
	} else {
		listeners = elbv2.GetListeners(loadBalancer.Arn)
	}

	for _, listener := range listeners {
		if len(operation.Rules) > 0 {
			for _, rule := range operation.Rules {
				elbv2.AddRuleToListener(listener.Arn, service.TargetGroupArn, rule)
			}
		} else {
			elbv2.ModifyLoadBalancerDefaultAction(loadBalancer.Arn, service.TargetGroupArn)
		}

		console.Info("Added service %s to %s", operation.ServiceName, operation.LoadBalancerName)
	}
}
