package client

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bvantagelimited/freeradius_exporter/freeradius"
	"github.com/prometheus/client_golang/prometheus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

// Statistics type.
type Statistics struct {
	Error           string
	Access          Access
	Auth            Auth
	ProxyAccess     Access
	ProxyAuth       Auth
	Accounting      Accounting
	ProxyAccounting Accounting
	Internal        Internal
	Server          Server
}

// Server specific stats.
type Server struct {
	OutstandingRequests uint32
	State               uint32
	TimeOfDeath         time.Time
	TimeOfLife          time.Time
	LastPacketRecv      time.Time
	LastPacketSent      time.Time
	StartTime           time.Time
	HUPTime             time.Time
	EmaWindow           uint32
	EmaUsecWindow1      uint32
	EmaUsecWindow10     uint32
	QueuePPSIn          uint32
	QueuePPSOut         uint32
	QueueUsePercentage  uint32
}

// Access type.
type Access struct {
	Requests   uint32
	Accepts    uint32
	Rejects    uint32
	Challenges uint32
}

// Auth type.
type Auth struct {
	Responses         uint32
	DuplicateRequests uint32
	MalformedRequests uint32
	InvalidRequests   uint32
	DroppedRequests   uint32
	UnknownTypes      uint32
}

// Accounting type.
type Accounting struct {
	Requests          uint32
	Responses         uint32
	DuplicateRequests uint32
	MalformedRequests uint32
	InvalidRequests   uint32
	DroppedRequests   uint32
	UnknownTypes      uint32
}

// Internal type.
type Internal struct {
	QueueLenInternal uint32
	QueueLenProxy    uint32
	QueueLenAuth     uint32
	QueueLenAcct     uint32
	QueueLenDetail   uint32
}

// FreeRADIUSClient fetches metrics from status server.
type FreeRADIUSClient struct {
	mainAddr string
	packets  []packetWrapper
	timeout  time.Duration
	metrics  map[string]*prometheus.Desc
}

type packetWrapper struct {
	address  string
	packet   *radius.Packet
	addrtype string
}

func newPacket(secret []byte, address string, statAttr radius.Attribute, addrType string) (*radius.Packet, error) {
	auth := make([]byte, 16)
	hash := hmac.New(md5.New, secret)
	packet := radius.New(radius.CodeStatusServer, secret)

	rfc2869.MessageAuthenticator_Set(packet, auth)
	freeradius.SetValue(packet, freeradius.StatisticsType, statAttr)

	if addrType == "server" {
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("failed parsing home server ip ('%v'): %w", address, err)
		}
		portStr = strings.TrimPrefix(portStr, ":")

		var ip net.IP
		ip = net.ParseIP(host)
		if ip == nil {
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 {
				ip = ips[0]
			}
		}

		attrIP, err := radius.NewIPAddr(ip)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed parsing port ('%v') to uint: %v", port, err)
		}

		freeradius.SetValue(packet, freeradius.ServerIPAddress, attrIP)
		//freeradius.SetValue(packet, freeradius.ServerPort, radius.NewInteger(uint32(port)))
	} else {
		var ip net.IP
		ip = net.ParseIP(address)

		if ip == nil {
			ips, err := net.LookupIP(address)
			if err == nil && len(ips) > 0 {
				ip = ips[0]
			}
		}

		attrIP, err := radius.NewIPAddr(ip)
		if err != nil {
			return nil, err
		}
		freeradius.SetValue(packet, freeradius.ClientIPAddress, attrIP)
	}

	encode, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	hash.Write(encode)
	rfc2869.MessageAuthenticator_Set(packet, hash.Sum(nil))

	return packet, err
}

// NewFreeRADIUSClient creates an FreeRADIUSClient.
func NewFreeRADIUSClient(addr string, homeServers []string, radClients []string, secret string, timeout int) (*FreeRADIUSClient, error) {
	client := &FreeRADIUSClient{}
	client.mainAddr = addr
	client.timeout = time.Duration(timeout) * time.Millisecond
	client.metrics = metrics
	packet, err := newPacket([]byte(secret), addr, radius.NewInteger(uint32(freeradius.StatisticsTypeAll)), "server")
	if err != nil {
		log.Fatalf("failed creating new packet for address '%v': %v\n", addr, err)
	}
	client.packets = append(client.packets, packetWrapper{packet: packet, address: addr, addrtype: "internal"})

	// add clients stats
	for _, rc := range radClients {
		if rc == "" {
			continue
		}

		statAttr := radius.NewInteger(uint32(
			freeradius.StatisticsTypeAuthAcct |
				freeradius.StatisticsTypeClient,
		))

		packet, err := newPacket([]byte(secret), rc, statAttr, "client")
		if err != nil {
			log.Fatalf("failed creating new packet for address '%v': %v\n", addr, err)
		}
		client.packets = append(client.packets, packetWrapper{packet: packet, address: rc, addrtype: "client"})
	}

	// add home server stats
	for _, hs := range homeServers {
		if hs == "" {
			continue
		}

		statAttr := radius.NewInteger(uint32(
			freeradius.StatisticsTypeAuthAcctProxyAuthAcct |
				freeradius.StatisticsTypeHomeServer,
		))

		if strings.Count(hs, ":") == 2 { // has third parameter
			index := strings.LastIndex(hs, ":")
			hsType := hs[index+1:]
			hs = hs[:index]

			if hsType == "auth" {
				statAttr = radius.NewInteger(uint32(
					freeradius.StatisticsTypeAuthentication |
						freeradius.StatisticsTypeInternal |
						freeradius.StatisticsTypeHomeServer,
				))
			} else if hsType == "acct" {
				statAttr = radius.NewInteger(uint32(
					freeradius.StatisticsTypeAccounting |
						freeradius.StatisticsTypeInternal |
						freeradius.StatisticsTypeHomeServer,
				))
			} else {
				log.Fatalf("unknown server type: '%v'", hsType)
			}
		}

		packet, err := newPacket([]byte(secret), hs, statAttr, "server")
		if err != nil {
			log.Fatalf("failed creating new packet for address '%v': %v\n", addr, err)
		}
		client.packets = append(client.packets, packetWrapper{packet: packet, address: hs, addrtype: "homeserver"})
	}

	return client, nil
}

// Stats fetches statistics.
func (f *FreeRADIUSClient) Stats() ([]prometheus.Metric, error) {
	var allStats []prometheus.Metric

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()

	for _, p := range f.packets {
		stats := Statistics{}

		response, err := radius.Exchange(ctx, p.packet, f.mainAddr)
		if err != nil {
			return nil, fmt.Errorf("exchange failed: %w", err)

		}

		if response.Code != radius.CodeAccessAccept {
			return nil, fmt.Errorf("got response code '%v'", response.Code)
		}

		statsErr, err := freeradius.GetString(response, freeradius.StatsError)
		if err == nil { // when there is no lookup error for this attribute, there is a freeradius-stats-error
			log.Printf("error form stats server (main %v or home server: %v): '%v'", f.mainAddr, p.address, statsErr)
		}

		stats.Error = statsErr
		m := prometheus.MustNewConstMetric(f.metrics["freeradius_stats_error"], prometheus.GaugeValue, 1, stats.Error, p.address)
		allStats = append(allStats, m)

		if stats.Server.LastPacketRecv, err = freeradius.GetDate(response, freeradius.LastPacketRecv); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_last_packet_recv"], prometheus.GaugeValue, float64(stats.Server.LastPacketRecv.Unix()), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}
		if stats.Server.LastPacketSent, err = freeradius.GetDate(response, freeradius.LastPacketSent); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_last_packet_sent"], prometheus.GaugeValue, float64(stats.Server.LastPacketSent.Unix()), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.HUPTime, err = freeradius.GetDate(response, freeradius.HUPTime); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_hup_time"], prometheus.GaugeValue, float64(stats.Server.HUPTime.Unix()), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}
		if stats.Server.StartTime, err = freeradius.GetDate(response, freeradius.StartTime); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_start_time"], prometheus.GaugeValue, float64(stats.Server.StartTime.Unix()), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.State, err = freeradius.GetInt(response, freeradius.ServerState); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_state"], prometheus.GaugeValue, float64(stats.Server.State), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.TimeOfDeath, err = freeradius.GetDate(response, freeradius.ServerTimeOfDeath); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_time_of_death"], prometheus.GaugeValue, float64(stats.Server.TimeOfDeath.Unix()), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}
		if stats.Server.TimeOfLife, err = freeradius.GetDate(response, freeradius.ServerTimeOfLife); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_time_of_life"], prometheus.GaugeValue, float64(stats.Server.TimeOfLife.Unix()), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.EmaWindow, err = freeradius.GetInt(response, freeradius.EmaWindow); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_ema_window"], prometheus.GaugeValue, float64(stats.Server.EmaWindow), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.EmaUsecWindow1, err = freeradius.GetInt(response, freeradius.EmaUsecWindow1); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_ema_window1_usec"], prometheus.GaugeValue, float64(stats.Server.EmaUsecWindow1), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.EmaUsecWindow10, err = freeradius.GetInt(response, freeradius.EmaUsecWindow10); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_ema_window10_usec"], prometheus.GaugeValue, float64(stats.Server.EmaUsecWindow10), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.OutstandingRequests, err = freeradius.GetInt(response, freeradius.ServerOutstandingRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_outstanding_requests"], prometheus.GaugeValue, float64(stats.Server.OutstandingRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.QueuePPSIn, err = freeradius.GetInt(response, freeradius.QueuePPSIn); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_pps_in"], prometheus.GaugeValue, float64(stats.Server.QueuePPSIn), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.QueuePPSOut, err = freeradius.GetInt(response, freeradius.QueuePPSOut); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_pps_out"], prometheus.GaugeValue, float64(stats.Server.QueuePPSOut), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.QueueUsePercentage, err = freeradius.GetInt(response, freeradius.QueueUsePercentage); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_use_percentage"], prometheus.GaugeValue, float64(stats.Server.QueuePPSOut), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Requests, err = freeradius.GetInt(response, freeradius.TotalAccessRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_requests"], prometheus.CounterValue, float64(stats.Access.Requests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Accepts, err = freeradius.GetInt(response, freeradius.TotalAccessAccepts); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_accepts"], prometheus.CounterValue, float64(stats.Access.Accepts), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Rejects, err = freeradius.GetInt(response, freeradius.TotalAccessRejects); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_rejects"], prometheus.CounterValue, float64(stats.Access.Rejects), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Challenges, err = freeradius.GetInt(response, freeradius.TotalAccessChallenges); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_challenges"], prometheus.CounterValue, float64(stats.Access.Challenges), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.Responses, err = freeradius.GetInt(response, freeradius.TotalAuthResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_responses"], prometheus.CounterValue, float64(stats.Auth.Responses), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalAuthDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_duplicate_requests"], prometheus.CounterValue, float64(stats.Auth.DuplicateRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalAuthMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_malformed_requests"], prometheus.CounterValue, float64(stats.Auth.MalformedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalAuthInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_invalid_requests"], prometheus.CounterValue, float64(stats.Auth.InvalidRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalAuthDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_dropped_requests"], prometheus.CounterValue, float64(stats.Auth.DroppedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalAuthUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_unknown_types"], prometheus.CounterValue, float64(stats.Auth.UnknownTypes), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Requests, err = freeradius.GetInt(response, freeradius.TotalProxyAccessRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_requests"], prometheus.CounterValue, float64(stats.ProxyAccess.Requests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Accepts, err = freeradius.GetInt(response, freeradius.TotalProxyAccessAccepts); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_accepts"], prometheus.CounterValue, float64(stats.ProxyAccess.Accepts), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Rejects, err = freeradius.GetInt(response, freeradius.TotalProxyAccessRejects); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_rejects"], prometheus.CounterValue, float64(stats.ProxyAccess.Rejects), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Challenges, err = freeradius.GetInt(response, freeradius.TotalProxyAccessChallenges); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_challenges"], prometheus.CounterValue, float64(stats.ProxyAccess.Challenges), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.Responses, err = freeradius.GetInt(response, freeradius.TotalProxyAuthResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_responses"], prometheus.CounterValue, float64(stats.ProxyAuth.Responses), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_duplicate_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.DuplicateRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_malformed_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.MalformedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_invalid_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.InvalidRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_dropped_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.DroppedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalProxyAuthUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_unknown_types"], prometheus.CounterValue, float64(stats.ProxyAuth.UnknownTypes), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.Requests, err = freeradius.GetInt(response, freeradius.TotalAccountingRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_requests"], prometheus.CounterValue, float64(stats.Accounting.Requests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.Responses, err = freeradius.GetInt(response, freeradius.TotalAccountingResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_responses"], prometheus.CounterValue, float64(stats.Accounting.Responses), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalAcctDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_duplicate_requests"], prometheus.CounterValue, float64(stats.Accounting.DuplicateRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalAcctMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_malformed_requests"], prometheus.CounterValue, float64(stats.Accounting.MalformedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalAcctInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_invalid_requests"], prometheus.CounterValue, float64(stats.Accounting.InvalidRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalAcctDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_dropped_requests"], prometheus.CounterValue, float64(stats.Accounting.DroppedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalAcctUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_unknown_types"], prometheus.CounterValue, float64(stats.Accounting.UnknownTypes), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.Requests, err = freeradius.GetInt(response, freeradius.TotalProxyAccountingRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.Requests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.Responses, err = freeradius.GetInt(response, freeradius.TotalProxyAccountingResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_responses"], prometheus.CounterValue, float64(stats.ProxyAccounting.Responses), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_duplicate_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.DuplicateRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_malformed_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.MalformedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_invalid_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.InvalidRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_dropped_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.DroppedRequests), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalProxyAcctUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_unknown_types"], prometheus.CounterValue, float64(stats.ProxyAccounting.UnknownTypes), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenInternal, err = freeradius.GetInt(response, freeradius.QueueLenInternal); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_internal"], prometheus.GaugeValue, float64(stats.Internal.QueueLenInternal), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenProxy, err = freeradius.GetInt(response, freeradius.QueueLenProxy); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_proxy"], prometheus.GaugeValue, float64(stats.Internal.QueueLenProxy), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenAuth, err = freeradius.GetInt(response, freeradius.QueueLenAuth); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_auth"], prometheus.GaugeValue, float64(stats.Internal.QueueLenAuth), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenAcct, err = freeradius.GetInt(response, freeradius.QueueLenAcct); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_acct"], prometheus.GaugeValue, float64(stats.Internal.QueueLenAcct), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenDetail, err = freeradius.GetInt(response, freeradius.QueueLenDetail); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_detail"], prometheus.GaugeValue, float64(stats.Internal.QueueLenDetail), p.address, p.addrtype))
		} else if err != radius.ErrNoAttribute {
			log.Println(err)
		}
	}

	return allStats, nil
}

var metrics = map[string]*prometheus.Desc{
	"freeradius_total_access_requests":               prometheus.NewDesc("freeradius_total_access_requests", "Total access requests", []string{"address", "type"}, nil),
	"freeradius_total_access_accepts":                prometheus.NewDesc("freeradius_total_access_accepts", "Total access accepts", []string{"address", "type"}, nil),
	"freeradius_total_access_rejects":                prometheus.NewDesc("freeradius_total_access_rejects", "Total access rejects", []string{"address", "type"}, nil),
	"freeradius_total_access_challenges":             prometheus.NewDesc("freeradius_total_access_challenges", "Total access challenges", []string{"address", "type"}, nil),
	"freeradius_total_auth_responses":                prometheus.NewDesc("freeradius_total_auth_responses", "Total auth responses", []string{"address", "type"}, nil),
	"freeradius_total_auth_duplicate_requests":       prometheus.NewDesc("freeradius_total_auth_duplicate_requests", "Total auth duplicate requests", []string{"address", "type"}, nil),
	"freeradius_total_auth_malformed_requests":       prometheus.NewDesc("freeradius_total_auth_malformed_requests", "Total auth malformed requests", []string{"address", "type"}, nil),
	"freeradius_total_auth_invalid_requests":         prometheus.NewDesc("freeradius_total_auth_invalid_requests", "Total auth invalid requests", []string{"address", "type"}, nil),
	"freeradius_total_auth_dropped_requests":         prometheus.NewDesc("freeradius_total_auth_dropped_requests", "Total auth dropped requests", []string{"address", "type"}, nil),
	"freeradius_total_auth_unknown_types":            prometheus.NewDesc("freeradius_total_auth_unknown_types", "Total auth unknown types", []string{"address", "type"}, nil),
	"freeradius_total_proxy_access_requests":         prometheus.NewDesc("freeradius_total_proxy_access_requests", "Total proxy access requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_access_accepts":          prometheus.NewDesc("freeradius_total_proxy_access_accepts", "Total proxy access accepts", []string{"address", "type"}, nil),
	"freeradius_total_proxy_access_rejects":          prometheus.NewDesc("freeradius_total_proxy_access_rejects", "Total proxy access rejects", []string{"address", "type"}, nil),
	"freeradius_total_proxy_access_challenges":       prometheus.NewDesc("freeradius_total_proxy_access_challenges", "Total proxy access challenges", []string{"address", "type"}, nil),
	"freeradius_total_proxy_auth_responses":          prometheus.NewDesc("freeradius_total_proxy_auth_responses", "Total proxy auth responses", []string{"address", "type"}, nil),
	"freeradius_total_proxy_auth_duplicate_requests": prometheus.NewDesc("freeradius_total_proxy_auth_duplicate_requests", "Total proxy auth duplicate requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_auth_malformed_requests": prometheus.NewDesc("freeradius_total_proxy_auth_malformed_requests", "Total proxy auth malformed requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_auth_invalid_requests":   prometheus.NewDesc("freeradius_total_proxy_auth_invalid_requests", "Total proxy auth invalid requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_auth_dropped_requests":   prometheus.NewDesc("freeradius_total_proxy_auth_dropped_requests", "Total proxy auth dropped requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_auth_unknown_types":      prometheus.NewDesc("freeradius_total_proxy_auth_unknown_types", "Total proxy auth unknown types", []string{"address", "type"}, nil),
	"freeradius_total_acct_requests":                 prometheus.NewDesc("freeradius_total_acct_requests", "Total acct requests", []string{"address", "type"}, nil),
	"freeradius_total_acct_responses":                prometheus.NewDesc("freeradius_total_acct_responses", "Total acct responses", []string{"address", "type"}, nil),
	"freeradius_total_acct_duplicate_requests":       prometheus.NewDesc("freeradius_total_acct_duplicate_requests", "Total acct duplicate requests", []string{"address", "type"}, nil),
	"freeradius_total_acct_malformed_requests":       prometheus.NewDesc("freeradius_total_acct_malformed_requests", "Total acct malformed requests", []string{"address", "type"}, nil),
	"freeradius_total_acct_invalid_requests":         prometheus.NewDesc("freeradius_total_acct_invalid_requests", "Total acct invalid requests", []string{"address", "type"}, nil),
	"freeradius_total_acct_dropped_requests":         prometheus.NewDesc("freeradius_total_acct_dropped_requests", "Total acct dropped requests", []string{"address", "type"}, nil),
	"freeradius_total_acct_unknown_types":            prometheus.NewDesc("freeradius_total_acct_unknown_types", "Total acct unknown types", []string{"address", "type"}, nil),
	"freeradius_total_proxy_acct_requests":           prometheus.NewDesc("freeradius_total_proxy_acct_requests", "Total proxy acct requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_acct_responses":          prometheus.NewDesc("freeradius_total_proxy_acct_responses", "Total proxy acct responses", []string{"address", "type"}, nil),
	"freeradius_total_proxy_acct_duplicate_requests": prometheus.NewDesc("freeradius_total_proxy_acct_duplicate_requests", "Total proxy acct duplicate requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_acct_malformed_requests": prometheus.NewDesc("freeradius_total_proxy_acct_malformed_requests", "Total proxy acct malformed requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_acct_invalid_requests":   prometheus.NewDesc("freeradius_total_proxy_acct_invalid_requests", "Total proxy acct invalid requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_acct_dropped_requests":   prometheus.NewDesc("freeradius_total_proxy_acct_dropped_requests", "Total proxy acct dropped requests", []string{"address", "type"}, nil),
	"freeradius_total_proxy_acct_unknown_types":      prometheus.NewDesc("freeradius_total_proxy_acct_unknown_types", "Total proxy acct unknown types", []string{"address", "type"}, nil),
	"freeradius_queue_len_internal":                  prometheus.NewDesc("freeradius_queue_len_internal", "Interal queue length", []string{"address", "type"}, nil),
	"freeradius_queue_len_proxy":                     prometheus.NewDesc("freeradius_queue_len_proxy", "Proxy queue length", []string{"address", "type"}, nil),
	"freeradius_queue_len_auth":                      prometheus.NewDesc("freeradius_queue_len_auth", "Auth queue length", []string{"address", "type"}, nil),
	"freeradius_queue_len_acct":                      prometheus.NewDesc("freeradius_queue_len_acct", "Acct queue length", []string{"address", "type"}, nil),
	"freeradius_queue_len_detail":                    prometheus.NewDesc("freeradius_queue_len_detail", "Detail queue length", []string{"address", "type"}, nil),
	"freeradius_last_packet_recv":                    prometheus.NewDesc("freeradius_last_packet_recv", "Epoch timestamp when the last packet was received", []string{"address", "type"}, nil),
	"freeradius_last_packet_sent":                    prometheus.NewDesc("freeradius_last_packet_sent", "Epoch timestamp when the last packet was sent", []string{"address", "type"}, nil),
	"freeradius_start_time":                          prometheus.NewDesc("freeradius_start_time", "Epoch timestamp when the server was started", []string{"address", "type"}, nil),
	"freeradius_hup_time":                            prometheus.NewDesc("freeradius_hup_time", "Epoch timestamp when the server hang up (If start == hup, it hasn't been hup'd yet)", []string{"address", "type"}, nil),
	"freeradius_state":                               prometheus.NewDesc("freeradius_state", "State of the server. Alive = 0; Zombie = 1; Dead = 2; Idle = 3", []string{"address", "type"}, nil),
	"freeradius_time_of_death":                       prometheus.NewDesc("freeradius_time_of_death", "Epoch timestamp when a home server is marked as 'dead'", []string{"address", "type"}, nil),
	"freeradius_time_of_life":                        prometheus.NewDesc("freeradius_time_of_life", "Epoch timestamp when a home server is marked as 'alive'", []string{"address", "type"}, nil),
	"freeradius_ema_window":                          prometheus.NewDesc("freeradius_ema_window", "Exponential moving average of home server response time", []string{"address", "type"}, nil),
	"freeradius_ema_window1_usec":                    prometheus.NewDesc("freeradius_ema_window1_usec", "Window-1 is the average is calculated over 'window' packets", []string{"address", "type"}, nil),
	"freeradius_ema_window10_usec":                   prometheus.NewDesc("freeradius_ema_window10_usec", "Window-10 is the average is calculated over '10 * window' packets", []string{"address", "type"}, nil),
	"freeradius_outstanding_requests":                prometheus.NewDesc("freeradius_outstanding_requests", "Outstanding requests", []string{"address", "type"}, nil),
	"freeradius_queue_pps_in":                        prometheus.NewDesc("freeradius_queue_pps_in", "Queue PPS in", []string{"address", "type"}, nil),
	"freeradius_queue_pps_out":                       prometheus.NewDesc("freeradius_queue_pps_out", "Queue PPS out", []string{"address", "type"}, nil),
	"freeradius_queue_use_percentage":                prometheus.NewDesc("freeradius_queue_use_percentage", "Queue usage percentage", []string{"address", "type"}, nil),
	"freeradius_stats_error":                         prometheus.NewDesc("freeradius_stats_error", "Stats error as label with a const value of 1", []string{"error", "address"}, nil),
}
