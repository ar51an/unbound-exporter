/*
 *  Prometheus Unbound Exporter
 *  Copyright (c) 2023 - ar51an - https://github.com/ar51an/unbound-exporter
 *  Released under Apache-2.0 license on an "AS-IS" BASIS
 *  Do not remove above information for distribution purpose
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/integrii/flaggy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type UnboundCollector struct {
	socketType string
	scrapeURI  string
	tlsConfig  *tls.Config
}

type metric struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

const NAMESPACE = `unbound`

var blockFilename = `/opt/unbound/blocklists/unbound.block.conf`
var listenAddress = `0.0.0.0:9167`
var metricsPath = `/metrics`
var unboundURI = `tcp://localhost:8953`
var unboundServerCert = `/etc/unbound/unbound_server.pem`
var unboundControlCert = `/etc/unbound/unbound_control.pem`
var unboundControlKey = `/etc/unbound/unbound_control.key`

var blocklistMetric = initMetric(`blocklist_domain_count`, `Blocklist domain count`, nil, prometheus.GaugeValue)

var multiMetrics = map[*regexp.Regexp]*metric{
	regexp.MustCompile(`^thread([0-9]+)\.requestlist\.current\.user$`): initMetric(`request_list_current_user`, `Request list current size`, []string{`thread`}, prometheus.GaugeValue),
	regexp.MustCompile(`^time\.up$`):                                   initMetric(`time_up_seconds`, `Unbound uptime in seconds`, []string{"Uptime"}, prometheus.CounterValue),
	regexp.MustCompile(`^mem\.cache\.([a-z]+)$`):                       initMetric(`memory_caches_bytes`, `Caches memory in bytes`, []string{"cache"}, prometheus.GaugeValue),
	regexp.MustCompile(`^mem\.mod\.([a-z]+)$`):                         initMetric("memory_modules_bytes", "Modules memory in bytes", []string{"module"}, prometheus.GaugeValue),
	regexp.MustCompile(`^histogram\.([\d\.]+)\.to\.([\d\.]+)$`):        initMetric(`response_time_buckets`, `Recursive queries count grouped into lower-upper bound lookup time`, []string{"direct", "lower", "upper"}, prometheus.CounterValue),
	regexp.MustCompile(`^num\.query\.type\.([A-Z0-9]+)$`):              initMetric(`query_types_count`, `Number of queries with given resource record type`, []string{"type"}, prometheus.CounterValue),
	regexp.MustCompile(`^num\.answer\.rcode\.([A-Za-z]+)$`):            initMetric(`answer_rcodes_count`, `Number of answers by response code (cache and recursive both)`, []string{"rcode"}, prometheus.CounterValue),
}

var flatMetrics = map[string]*metric{
	`total.num.queries`:           initMetric(`queries_total`, `Total number of queries received`, nil, prometheus.CounterValue),
	`total.num.cachehits`:         initMetric(`cache_hit_total`, `Total number of queries answered from cache`, nil, prometheus.CounterValue),
	`total.num.cachemiss`:         initMetric(`cache_miss_total`, `Total number of queries that needed recursive processing`, nil, prometheus.CounterValue),
	`total.num.prefetch`:          initMetric(`prefetch_total`, `Total number of cache prefetches performed`, nil, prometheus.CounterValue),
	`total.num.expired`:           initMetric(`expired_total`, `Total number of replies that served an expired cache entry`, nil, prometheus.CounterValue),
	`total.requestlist.avg`:       initMetric(`request_list_avg`, `Average requests in request list on new recursive query`, nil, prometheus.GaugeValue),
	`total.requestlist.max`:       initMetric(`request_list_max`, `Maximum size attained by recursive request list`, nil, prometheus.CounterValue),
	`total.recursion.time.avg`:    initMetric(`recursion_time_avg_seconds`, `Average time to answer recursive queries`, nil, prometheus.GaugeValue),
	`total.recursion.time.median`: initMetric(`recursion_time_median_seconds`, `Median time to answer recursive queries`, nil, prometheus.GaugeValue),
	`num.query.tcpout`:            initMetric(`query_tcpout_count`, `Number of TCP outgoing queries`, nil, prometheus.CounterValue),
	`num.query.udpout`:            initMetric(`query_udpout_count`, `Number of UDP outgoing queries`, nil, prometheus.CounterValue),
	`num.query.ipv6`:              initMetric(`query_ipv6_count`, `Number of IPv6 incoming queries`, nil, prometheus.CounterValue),
	`num.answer.secure`:           initMetric(`answer_secure_count`, `Number of answers that were secure`, nil, prometheus.CounterValue),
	`num.answer.bogus`:            initMetric(`answer_bogus_count`, `Number of answers that were bogus`, nil, prometheus.CounterValue),
	`msg.cache.count`:             initMetric(`msg_cache_count`, `Number of DNS replies in the message cache`, nil, prometheus.GaugeValue),
	`rrset.cache.count`:           initMetric("rrset_cache_count", "Number of RRsets in the rrset cache", nil, prometheus.GaugeValue),
	`infra.cache.count`:           initMetric("infra_cache_count", "Number of items in the infra cache", nil, prometheus.GaugeValue),
	`key.cache.count`:             initMetric(`key_cache_count`, `Number of items in the key cache`, nil, prometheus.GaugeValue),
}

func initMetric(name string, help string, labels []string, metricType prometheus.ValueType) *metric {
	var m = &metric{}
	m.desc = prometheus.NewDesc(prometheus.BuildFQName(NAMESPACE, ``, name), help, labels, nil)
	m.valueType = metricType
	return m
}

func addMetric(ch chan<- prometheus.Metric, desc *prometheus.Desc, metricType prometheus.ValueType, value float64, labelValue ...string) {
	ch <- prometheus.MustNewConstMetric(desc, metricType, value, labelValue[0:]...)
}

func roundBucket(duration time.Duration) string {
	replacer := strings.NewReplacer(`µs`, ` µs`, `ms`, ` ms`)

	switch {
	case duration > time.Millisecond:
		duration = duration.Round(time.Millisecond)
	case duration > time.Microsecond:
		duration = duration.Round(time.Microsecond)
	}
	return replacer.Replace(duration.String())
}

func formatBucket(labelValue string) string {
	var bound time.Duration
	var formattedBound string
	value, _ := strconv.ParseFloat(labelValue, 64)

	switch {
	case value == 0.0:
		formattedBound = strconv.FormatFloat(value, 'f', -1, 64) + ` µs`
	case value < 1.0:
		_, fraction := math.Modf(value)
		bound = time.Duration(fraction/1e-06) * time.Microsecond
		formattedBound = roundBucket(bound)
	case value >= 1.0:
		formattedBound = strconv.FormatFloat(value, 'f', -1, 64) + ` s`
	}
	return formattedBound
}

func formatUptime(sec int64) string {
	var uptime string
	ds, sec := sec/86400, sec%86400
	hrs, sec := sec/3600, sec%3600
	mins := sec / 60

	if ds != 0 {
		uptime += strconv.FormatInt(ds, 10) + ` d `
	}
	if hrs != 0 {
		uptime += strconv.FormatInt(hrs, 10) + ` h `
	}
	if mins != 0 && (ds < 1 || hrs < 1) {
		uptime += strconv.FormatInt(mins, 10) + ` m`
	}
	return strings.TrimRight(uptime, ` `)
}

func bsToF(bs []byte) float64 {
	f, err := strconv.ParseFloat(string(bs), 64)
	if err != nil {
		log.Error(err)
	}
	return f
}

func scrapeStats(stream io.Reader, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(stream)
	var labelValues []string
	var sKey string
	var value float64
	var skip bool
	var direct = 1.0

	for scanner.Scan() {
		bKey, bValue, found := bytes.Cut(scanner.Bytes(), []byte(`=`))
		if found {
			skip = false
			sKey = string(bKey)
			for k := range multiMetrics {
				if matches := k.FindStringSubmatch(sKey); matches != nil {
					value = bsToF(bValue)
					switch {
					case strings.Contains(sKey, `histogram`):
						labelValues = make([]string, 3)
						labelValues[0] = strconv.FormatFloat(direct, 'f', 1, 64)
						labelValues[1] = formatBucket(matches[1])
						labelValues[2] = formatBucket(matches[2])
						direct += 0.1
					case strings.Contains(sKey, `time.up`):
						uptime := formatUptime(int64(value))
						labelValues = []string{uptime}
					default:
						labelValues = matches[1:]
					}
					addMetric(ch, multiMetrics[k].desc, multiMetrics[k].valueType, value, labelValues[0:]...)
					labelValues = nil
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			if m, ok := flatMetrics[sKey]; ok {
				value = bsToF(bValue)
				addMetric(ch, m.desc, m.valueType, value)
			}
		}
	}
	return scanner.Err()
}

func collectStats(collector *UnboundCollector, ch chan<- prometheus.Metric) error {
	var conn net.Conn
	var err error
	var stats = []byte("UBCT1 stats_noreset\n")

	switch collector.socketType {
	case "unix":
		conn, err = net.Dial(collector.socketType, collector.scrapeURI)
	case "tcp":
		conn, err = tls.Dial(collector.socketType, collector.scrapeURI, collector.tlsConfig)
	default:
		err = fmt.Errorf("invalid socket type")
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(stats)
	if err != nil {
		return err
	}
	return scrapeStats(conn, ch)
}

func collectBlocklist(ch chan<- prometheus.Metric) {
	var count = 0
	var err error
	var numBytes int
	var isLocalData = false
	var pattern = []byte("\n")

	blocklist, fileErr := os.Open(blockFilename)
	if fileErr != nil {
		log.Error("blocklist not found: ", fileErr)
		return
	}
	buffer := make([]byte, bufio.MaxScanTokenSize)
	for {
		numBytes, err = blocklist.Read(buffer)
		count += bytes.Count(buffer[:numBytes], pattern)
		if err == io.EOF {
			break
		}
	}
	if bytes.Contains(buffer, []byte(`local-data:`)) {
		isLocalData = true
	}
	count -= 1
	if isLocalData {
		count /= 2
	}
	addMetric(ch, blocklistMetric.desc, blocklistMetric.valueType, float64(count))
	buffer = nil
	blocklist.Close()
}

func (collector *UnboundCollector) Collect(ch chan<- prometheus.Metric) {
	collectBlocklist(ch)
	err := collectStats(collector, ch)
	if err != nil {
		log.Error("failed to scrape unbound statistics: ", err)
	}
}

func (collector *UnboundCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range multiMetrics {
		ch <- m.desc
	}
	for _, m := range flatMetrics {
		ch <- m.desc
	}
	ch <- blocklistMetric.desc
}

func initCollector() (*UnboundCollector, error) {
	var collector = &UnboundCollector{}
	var err error

	parsedAddr := strings.Split(unboundURI, `://`)
	if len(parsedAddr) != 2 {
		return collector, fmt.Errorf("invalid unbound socket uri format")
	}
	scheme := parsedAddr[0]
	address := parsedAddr[1]
	switch scheme {
	case "unix":
		collector.socketType = scheme
		collector.scrapeURI = `/` + address
		return collector, nil
	case "tcp":
		serverCert, err := os.ReadFile(unboundServerCert)
		if err != nil {
			return collector, err
		}
		serverCertPool := x509.NewCertPool()
		if !serverCertPool.AppendCertsFromPEM(serverCert) {
			return collector, fmt.Errorf("failed to parse unbound server certificate")
		}
		controlCert, err := os.ReadFile(unboundControlCert)
		if err != nil {
			return collector, err
		}
		controlKey, err := os.ReadFile(unboundControlKey)
		if err != nil {
			return collector, err
		}
		keyPair, err := tls.X509KeyPair(controlCert, controlKey)
		if err != nil {
			return collector, err
		}
		collector.socketType = scheme
		collector.scrapeURI = address
		collector.tlsConfig = &tls.Config{Certificates: []tls.Certificate{keyPair}, RootCAs: serverCertPool, ServerName: `unbound`}
		return collector, nil
	default:
		err = fmt.Errorf("invalid socket type")
	}
	return collector, err
}

func init() {
	flaggy.DefaultParser.DisableShowVersionWithVersion()
	flaggy.String(&blockFilename, `b`, `block-file`, `Unbound blocklist file.`)
	flaggy.String(&listenAddress, `a`, `web.listen-address`, `Address to listen on for web interface.`)
	flaggy.String(&metricsPath, `p`, `web.metrics-path`, `Path under which to expose metrics.`)
	flaggy.String(&unboundURI, `u`, `unbound.uri`, `Unix/TCP unbound socket path for scraping.`)
	flaggy.String(&unboundServerCert, `s`, `unbound.server-cert`, `Unbound server certificate.`)
	flaggy.String(&unboundControlCert, `c`, `unbound.control-cert`, `Unbound control certificate.`)
	flaggy.String(&unboundControlKey, `k`, `unbound.control-key`, `Unbound control private key.`)
}

func main() {
	flaggy.Parse()
	collector, err := initCollector()
	if err != nil {
		log.Fatal(err)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	http.Handle(metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Unbound Exporter</title></head>
			<body>
			<h3>Unbound Metrics</h3>
			<p><a href='` + metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})
	log.Info("Providing metrics at ", listenAddress, metricsPath)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
	os.Exit(1)
}
