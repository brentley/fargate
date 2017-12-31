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

type LbServiceRemoveOperation struct {
	LoadBalancerName string
	ServiceName      string
	Ports            []Port
}

func (o *LbServiceRemoveOperation) SetPorts(inputPorts []string) {
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

var flagLbServiceRemovePorts []string

var lbServiceRemoveCmd = &cobra.Command{
	Use:   "remove <load-balancer-name> <service-name>",
	Short: "Remove a service from a load balancer",
	Long:  "Remove a service from a load balancer",

	Run: func(cmd *cobra.Command, args []string) {
		operation := &LbServiceRemoveOperation{
			LoadBalancerName: args[0],
			ServiceName:      args[1],
		}

		if len(flagLbServiceRemovePorts) > 0 {
			operation.SetPorts(flagLbServiceRemovePorts)
		}

		removeServiceFromLoadBalancer(operation)
	},
}

func init() {
	lbServiceRemoveCmd.Flags().StringSliceVarP(&flagLbServiceRemovePorts, "port", "p", []string{}, "Port from which to remove service [e.g., 80, 443, http:8080, https:8443, tcp:1935] (can be specified multiple times)")

	lbServiceCmd.AddCommand(lbServiceRemoveCmd)
}

func removeServiceFromLoadBalancer(operation *LbServiceRemoveOperation) {
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
		for _, rule := range elbv2.DescribeRules(listener.Arn) {
			if rule.TargetGroupArn == service.TargetGroupArn {
				if rule.IsDefault {
					defaultTargetGroupName := fmt.Sprintf(defaultTargetGroupFormat, loadBalancer.Name)
					defaultTargetGroupArn := elbv2.GetTargetGroupArn(defaultTargetGroupName)

					if defaultTargetGroupArn == "" {
						defaultTargetGroupArn = elbv2.CreateTargetGroup(
							&ELBV2.CreateTargetGroupInput{
								Name:     defaultTargetGroupName,
								Port:     listeners[0].Port,
								Protocol: listeners[0].Protocol,
								VpcId:    loadBalancer.VpcId,
							},
						)
						fmt.Println("%+v", rule)
						fmt.Println(rule.TargetGroupArn)
						fmt.Println(service.TargetGroupArn)
					}

					elbv2.ModifyLoadBalancerDefaultAction(loadBalancer.Arn, defaultTargetGroupArn)
				} else {
					elbv2.DeleteRule(rule.Arn)
				}
			}
		}

		console.Info("Removed service %s from %s", operation.ServiceName, operation.LoadBalancerName)
	}
}
