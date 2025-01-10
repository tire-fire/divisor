package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/joho/godotenv"
	"github.com/moby/moby/libnetwork/iptables"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

const (
	// InterfaceNamePrefix is the prefix for the interfaces created by Divisor
	InterfaceNamePrefix = "divisor"
)

var logLvels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

var opts struct {
	logger struct {
		level string
	}
}

func main() {
	// parse command line options
	flag.StringVar(&opts.logger.level, "log-level", "debug", "Set the log level")
	flag.Parse()

	logLevel, ok := logLvels[opts.logger.level]
	if !ok {
		log.Fatalf("Invalid log level: %s", opts.logger.level)
	}
	// use config to setup engine
	var handler slog.Handler
	handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	slog.Info("Starting the Divisor...")
	for {
		// reconnect to redis if needed
		err := subscribeAndListen()
		if err != nil {
			slog.Error("main loop errored out", "error", err)
		}
	}
}

func subscribeAndListen() error {
	slog.Debug("Connecting to redis...")
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: os.Getenv("REDIS_PASSWORD"),
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}
	slog.Debug("Connected to redis")

	events := redisClient.Subscribe(context.Background(), "events")
	defer events.Close()

	eventsChannel := events.Channel()

	for msg := range eventsChannel {
		slog.Info("Received message", "message", msg.String())

		if msg.Payload == "round_finished" {
			slog.Info("round_finished event received, changing interfaces")
		}

		numInterfaces, err := strconv.Atoi(os.Getenv("NUM_INTERFACES"))
		if err != nil {
			return fmt.Errorf("failed to convert NUM_INTERFACES to int: %w", err)
		}
		targetSubnets := strings.Split(os.Getenv("TARGET_SUBNETS"), ",")

		// setup
		table := iptables.GetIptable(iptables.IPv4)
		var dockerAddresses []string

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return fmt.Errorf("failed to create docker client: %w", err)
		}

		containers, err := cli.ContainerList(context.Background(), container.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		slog.Debug(fmt.Sprintf("found %d containers", len(containers)))

		for _, container := range containers {
			if !strings.Contains(container.Names[0], "quotient_runner_") {
				continue
			}
			slog.Debug("inspecting container", "container", container.Names[0])
			containerDetails, err := cli.ContainerInspect(context.Background(), container.ID)
			if err != nil {
				slog.Error("failed to inspect container", "container", container.ID, "error", err.Error())
				continue
			}

			// retrieve the IP address from the network settings
			for networkName, network := range containerDetails.NetworkSettings.Networks {
				if networkName != "lo" {
					dockerAddresses = append(dockerAddresses, network.IPAddress)
				}
			}
		}

		slog.Debug("docker addresses", "addresses", fmt.Sprintf("%v", dockerAddresses))

		// erase all existing interfaces controller by Divisor
		interfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %w", err)
		}

		foundDivisorInterface := false
		for _, iface := range interfaces {
			if strings.HasPrefix(iface.Name, InterfaceNamePrefix) {
				link, err := netlink.LinkByName(iface.Name)
				if err != nil {
					return fmt.Errorf("failed to get link %s by name: %w", iface.Name, err)
				}
				addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
				if err != nil {
					return fmt.Errorf("failed to get address list: %w", err)
				}

				for _, addr := range addrs {
					// brute force delete the address from all interfaces
					for _, dockerAddress := range dockerAddresses {
						for _, s := range targetSubnets {
							table.ProgramRule(iptables.Nat, "POSTROUTING", iptables.Delete, []string{"-s", dockerAddress, "-d", s, "-j snat --to-source", addr.IP.String()})
						}
					}
					if err := netlink.AddrDel(link, &addr); err != nil {
						return fmt.Errorf("failed to delete address: %w", err)
					}
				}
				foundDivisorInterface = true
				break
			}
		}

		if !foundDivisorInterface {
			slog.Info("no interface for divisor found, creating...")

			iface := &netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: InterfaceNamePrefix,
				},
			}

			if err := netlink.LinkAdd(iface); err != nil {
				return fmt.Errorf("failed to add link: %w", err)
			}

			link, err := netlink.LinkByName(InterfaceNamePrefix)
			if err != nil {
				return fmt.Errorf("failed to get link %s by name: %w", InterfaceNamePrefix, err)
			}

			// set the address
			if err := netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("failed to set link up: %w", err)
			}
			slog.Info("created interface", "name", InterfaceNamePrefix)
		}

		// update interfaces in case a new one was added
		interfaces, err = net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %w", err)
		}

		for _, iface := range interfaces {
			if strings.HasPrefix(iface.Name, InterfaceNamePrefix) {
				slog.Info("setting up routing", "name", iface.Name, "addresses", numInterfaces)
				// set link down before changing the address
				// set the address
				link, err := netlink.LinkByName(iface.Name)
				if err != nil {
					return fmt.Errorf("failed to get link %s by name: %w", iface.Name, err)
				}
				if err := netlink.LinkSetDown(link); err != nil {
					return fmt.Errorf("failed to set link down: %w", err)
				}
				for i := 0; i < numInterfaces; i++ {
					interfaceAddress, err := getUnusedAddress(os.Getenv("DESIRED_SUBNET"))
					if err != nil {
						return fmt.Errorf("failed to get unused address: %w", err)
					}

					slog.Debug("setting address", "name", iface.Name, "address", interfaceAddress)

					subnet := strings.Split(os.Getenv("DESIRED_SUBNET"), "/")[1]
					mask, err := strconv.Atoi(subnet)
					if err != nil {
						return fmt.Errorf("failed to convert subnet to int: %w", err)
					}
					ip := &net.IPNet{
						IP:   net.ParseIP(interfaceAddress),
						Mask: net.CIDRMask(mask, 32),
					}

					if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ip}); err != nil {
						return fmt.Errorf("failed to add address: %w", err)
					}

					// add the address to the NAT table
					for _, s := range targetSubnets {
						if err := table.ProgramRule(iptables.Nat, "POSTROUTING", iptables.Insert, []string{"-s", dockerAddresses[i], "-d", s, "-j", "SNAT", "--to-source", interfaceAddress}); err != nil {
							return fmt.Errorf("failed to add snat rule for %s: %w", dockerAddresses[i], err)
						}
					}
				}
				if err := netlink.LinkSetUp(link); err != nil {
					return fmt.Errorf("failed to set link up: %w", err)
				}
				break
			}
		}
		slog.Info("finished setting up routing, waiting for next event...")
	}
	return nil
}

func getUnusedAddress(desiredSubnet string) (string, error) {
	// calculate an unused address in the desired subnet
	_, desiredNet, err := net.ParseCIDR(desiredSubnet)
	if err != nil {
		return "", fmt.Errorf("failed to parse desired subnet: %w", err)
	}

	// calculate how many addresses are in the subnet
	ones, bits := desiredNet.Mask.Size()
	numAddresses := 1 << uint(bits-ones)

	// randomly pick a number between 0 and numAddresses as n
	// pick the nth address in the subnet

	for {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		n := rng.Intn(numAddresses - 1)
		address := net.IP(make([]byte, 4))
		copy(address, desiredNet.IP)
		for i := 0; i < n; i++ {
			for j := 3; j >= 0; j-- {
				address[j]++
				if address[j] != 0 {
					break
				}
			}
		}

		// ping the address to see if it's in use
		pinger, err := probing.NewPinger(address.String())
		if err != nil {
			return "", fmt.Errorf("failed to create pinger: %w", err)
		}

		pinger.Count = 1
		pinger.Timeout = 1 * time.Second
		pinger.SetPrivileged(true)
		err = pinger.Run()
		if err != nil {
			return "", fmt.Errorf("failed to run pinger: %w", err)
		}

		if pinger.Statistics().PacketsRecv == 0 {
			return address.String(), nil
		}
	}
}
