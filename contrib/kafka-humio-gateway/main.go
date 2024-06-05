// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 SUSE LLC. All Rights Reserved.
//
// This is a Kafka Consumer that feeds Velociraptor events to a Humio server.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/IBM/sarama"
	"github.com/go-yaml/yaml"
	"github.com/hashicorp/go-retryablehttp"
)

var (
	debug                    = false
	verbose                  = false
	pprofPort                int
	configFile               string
	defaultConsumerGroup     = "velociraptor-consumer"
	defaultEventBatchSize    = 500
	defaultBatchingTimeoutMs = 3000
	certFile                 string
	keyFile                  string
	caFile                   string
	tlsSkipVerify            bool
	useTLS                   bool
	errMaxRetriesExceded     = errors.New("max retries exceeded")
	errContextCancelOnRetry  = errors.New("context canceled while waiting for retry")
	errNonRetryable          = errors.New("non retryable error")
)

type TransportConfig struct {
	Kafka struct {
		Brokers       []string
		Topics        []string
		ConsumerGroup string `yaml:"consumer_group"`
	}
	Humio struct {
		EndpointUrl       string `yaml:"endpoint_url"`
		IngestToken       string `yaml:"ingest_token"`
		BatchingTimeoutMs int    `yaml:"batching_timeout_ms"`
		EventBatchSize    int    `yaml:"event_batch_size"`
	}
}

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.IntVar(&pprofPort, "pprof-port", 0, "enable go pprof debugging on this port")
	flag.StringVar(&configFile, "config", "config.yml", "Path to YaML file containing configuration")
	flag.StringVar(&certFile, "cert", "", "Optional certificate file for kafka client authentication")
	flag.StringVar(&keyFile, "key", "", "Optional key file for kafka client authentication")
	flag.StringVar(&caFile, "cacert", "", "Optional certificate authority file for kafka client authentication")
	flag.BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "Whether to skip TLS server cert verification with kafka")
	flag.BoolVar(&useTLS, "use-tls", false, "Use TLS to communicate with the kafka cluster")
}

func saramaBackoff(retries, maxRetries int) time.Duration {
	seconds := 1
	for i := 0; i < retries; i += 1 {
		seconds *= 2
	}
	if seconds > 30 {
		seconds = 30
	}

	return time.Duration(seconds) * time.Second
}

func createTLSConfiguration() (t *tls.Config) {
	t = &tls.Config{
		InsecureSkipVerify: tlsSkipVerify,
	}

	if certFile != "" && keyFile != "" && caFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal(err)
		}

		caCert, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatal(err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Fatal("failed to append cacert to pool")
		}

		t = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: tlsSkipVerify,
		}
	}
	return t
}

func main() {
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	body, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("error: could not open config file `%s': %s",
			configFile, err)
	}

	if pprofPort != 0 {
		pprofBaseURL := fmt.Sprintf("localhost:%d", pprofPort)
		log.Printf("pprof on: http://%s/debug/pprof/", pprofBaseURL)
		go func() {
			if err := http.ListenAndServe(pprofBaseURL, nil); err != nil {
				log.Panicf("starting pprof server: %v", err)
			}
		}()
	}

	consumer := Consumer{
		readyWg: &sync.WaitGroup{},
	}

	err = yaml.Unmarshal(body, &consumer.config)
	if err != nil {
		log.Fatalf("error: could not parse config file `%s': %s",
			configFile, err)
	}

	if len(consumer.config.Kafka.Brokers) == 0 {
		log.Fatalf("error: config has missing or empty kafka.brokers")
	}

	if len(consumer.config.Kafka.Topics) == 0 {
		log.Fatalf("error: config has missing or empty kafka.topics")
	}

	if consumer.config.Kafka.ConsumerGroup == "" {
		consumer.config.Kafka.ConsumerGroup = defaultConsumerGroup
		log.Printf("warning: config missing `kafka.consumer_group'.  Using default `%s'",
			consumer.config.Kafka.ConsumerGroup)
	}

	if consumer.config.Humio.EndpointUrl == "" {
		log.Fatalf("error: config missing `humio.endpoint_url'")
	}

	if consumer.config.Humio.BatchingTimeoutMs == 0 {
		consumer.config.Humio.BatchingTimeoutMs = defaultBatchingTimeoutMs
	}

	if consumer.config.Humio.EventBatchSize == 0 {
		consumer.config.Humio.EventBatchSize = defaultEventBatchSize
	}

	_, err = url.ParseRequestURI(consumer.config.Humio.EndpointUrl)
	if err != nil {
		log.Fatalf("Humio Endpoint Url `%s' is not valid: %v",
			consumer.config.Humio.EndpointUrl, err)
	}

	if consumer.config.Humio.IngestToken == "" {
		log.Fatalf("error: config missing `humio.ingest_token'")
	}

	log.Printf("Joining consumer group `%s'", consumer.config.Kafka.ConsumerGroup)
	log.Printf("Will post events to Humio Endpoint `%s'", consumer.config.Humio.EndpointUrl)

	consumer.httpClient = RetryableClient{
		client:           &http.Client{Timeout: 60 * time.Second},
		url:              consumer.config.Humio.EndpointUrl,
		token:            consumer.config.Humio.IngestToken,
		minRetryInterval: 1 * time.Second,
		maxRetryInterval: 30 * time.Second,
		maxRetries:       12,
	}

	if verbose {
		sarama.Logger = log.New(os.Stdout, "[sarama] ", log.LstdFlags)
	}

	saramaConfig := sarama.NewConfig()
	saramaConfig.ClientID = "Kafka-Humio-Gateway"
	saramaConfig.Metadata.Retry.Max = 15
	saramaConfig.Metadata.Retry.BackoffFunc = saramaBackoff
	maxTime := time.Duration(consumer.config.Humio.BatchingTimeoutMs+500) * time.Millisecond
	saramaConfig.Consumer.MaxProcessingTime = maxTime

	if useTLS {
		saramaConfig.Net.TLS.Enable = true
		saramaConfig.Net.TLS.Config = createTLSConfiguration()
	}

	client, err := sarama.NewConsumerGroup(consumer.config.Kafka.Brokers,
		consumer.config.Kafka.ConsumerGroup, saramaConfig)
	if err != nil {
		log.Panicf("Error creating consumer group client: %v", err)
	}

	// Wait group for goroutine exit
	wg := &sync.WaitGroup{}
	wg.Add(1)

	// Wait group for consumer initial setup completion
	consumer.readyWg.Add(1)

	// Context for consumer to be cancelable
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer wg.Done()
		for {
			// `Consume` should be called inside an infinite loop, when a
			// server-side rebalance happens, the consumer session will need to be
			// recreated to get the new claims
			err := client.Consume(ctx, consumer.config.Kafka.Topics, &consumer)
			if err != nil {
				log.Panicf("Error from consumer: %v", err)
			}
			// check if context was cancelled, signaling that the consumer should stop
			if ctx.Err() != nil {
				return
			}
		}
	}()

	// Wait on the consumer to finish setup successfully.  If the consumer fails setup,
	// we'll panic instead of erroring.  This is fine.  This helper is meant to be run
	// as service which will automatically restart.
	consumer.readyWg.Wait()
	log.Println("Sarama consumer ready.")

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)

	keepRunning := true
	for keepRunning {
		select {
		case <-ctx.Done():
			log.Println("terminating: context cancelled")
			keepRunning = false
		case <-sigterm:
			log.Println("terminating: via signal")
			keepRunning = false
		}
	}
	cancel()
	wg.Wait()
	if err = client.Close(); err != nil {
		log.Panicf("Error closing client: %v", err)
	}
}

// Consumer represents a Sarama consumer group consumer
type Consumer struct {
	setupOnce  sync.Once
	readyWg    *sync.WaitGroup
	httpClient RetryableClient
	config     TransportConfig
}

// Setup is run at the beginning of a new session, before ConsumeClaim
func (consumer *Consumer) Setup(sarama.ConsumerGroupSession) error {
	consumer.setupOnce.Do(consumer.readyWg.Done)
	return nil
}

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited
func (consumer *Consumer) Cleanup(sarama.ConsumerGroupSession) error {
	return nil
}

// VRRKafkaMessage RowData can be string or int. We don't care which. We just pass it through.
type VRRKafkaMessage struct {
	Tags    map[string]interface{} `json:"tags"`
	RowData map[string]interface{} `json:"row_data"`
	Version int                    `json:"version"`
}

type HumioEvent struct {
	// Could be string or int.  We don't need to care which.
	Timestamp  interface{}            `json:"timestamp"`
	Attributes map[string]interface{} `json:"attributes"`
	Timezone   string                 `json:"timezone,omitempty"`
}

type HumioPayload struct {
	Events []HumioEvent           `json:"events"`
	Tags   map[string]interface{} `json:"tags,omitempty"`
}

type HumioSubmission struct {
	Payload HumioPayload
	Message *sarama.ConsumerMessage
}

// Queues events until we hit a timeout since last submission or a set
// count of events.  Once the conditions are met, the entire queue is marshaled
// as JSON and submitted synchronously to the Humio server.
// The messages will only be marked/cleared after the submission is successful.
// If the session ends (due to kafka rebalance or program shutdown) any messages
// that have been claimed but not yet posted will be dropped and left on Kafka
// for a future session to reclaim and retry posting them.
// If posting fails after all retries then we exit with an error code, and the
// messages will remain on Kafka for a future incarnation to retry them.
func (consumer *Consumer) sendEvents(session sarama.ConsumerGroupSession,
	eventChannel chan HumioSubmission, wg *sync.WaitGroup) {

	postData := []HumioPayload{}
	messageQueue := make([]*sarama.ConsumerMessage, 0)
	eventCount := 0

	tickerTimeout := time.Duration(consumer.config.Humio.BatchingTimeoutMs) * time.Millisecond
	ticker := time.NewTicker(tickerTimeout)

	defer ticker.Stop()
	defer wg.Done()

	for {
		postEvents := false

		select {
		case <-ticker.C:
			if eventCount > 0 {
				postEvents = true
			}
		case message, ok := <-eventChannel:
			if !ok {
				if debug {
					log.Printf("sendEvents exiting")
				}
				return
			}

			postData = append(postData, message.Payload)
			messageQueue = append(messageQueue, message.Message)

			eventCount += 1
			if eventCount > consumer.config.Humio.EventBatchSize {
				postEvents = true
			}
		}

		if postEvents {
			data, err := json.Marshal(postData)
			if err != nil {
				log.Printf("Failed to Marshal %v: %s", postData, err)
			}

			err = consumer.httpClient.postWithRetry(session.Context(), data)
			if err != nil && session.Context().Err() != nil {
				log.Printf("Session expired while posting to Humio. A future session will try the messages again.")
				return
			} else if err != nil {
				log.Printf("Failed posting to Humio: %v", err)
				os.Exit(1)
			}

			// the messages can be cleared as they were successfully posted to Humio
			for _, message := range messageQueue {
				session.MarkMessage(message, "")
			}

			postData = []HumioPayload{}
			messageQueue = make([]*sarama.ConsumerMessage, 0)
			eventCount = 0
			ticker.Reset(tickerTimeout)
		}
	}
}

// ConsumeClaim must start a consumer loop of ConsumerGroupClaim's Messages().
func (consumer *Consumer) ConsumeClaim(session sarama.ConsumerGroupSession,
	claim sarama.ConsumerGroupClaim) error {

	// This WaitGroup tracks the sendEvents goroutine
	wg := sync.WaitGroup{}
	eventChannel := make(chan HumioSubmission, 1)

	wg.Add(1)
	go consumer.sendEvents(session, eventChannel, &wg)

	// NOTE:
	// Do not move the code below to a goroutine.
	// The `ConsumeClaim` itself is called within a goroutine, see:
	// https://github.com/Shopify/sarama/blob/main/consumer_group.go#L27-L29
	for message := range claim.Messages() {
		var err error
		if debug {
			log.Printf("Received message Topic[%s] Key[%s] Value[%s] Timestamp[%v]",
				message.Topic, message.Key, message.Value, message.Timestamp)
		}

		var values VRRKafkaMessage
		err = json.Unmarshal(message.Value, &values)
		if err != nil {
			log.Printf("Failed to unmarshal [%s]: %v", message.Value, err)
			session.MarkMessage(message, "")
			continue
		}

		timestamp, ok := values.RowData["Time"]
		timezone := ""
		if !ok {
			timestamp, ok = values.RowData["timestamp"]
		}

		_, isint := timestamp.(uint64)
		if isint {
			timezone = "UTC"
		}

		if !ok {
			log.Printf("Failed to gather timestamp from event: %s", message.Value)
			session.MarkMessage(message, "")
			continue
		}

		payload := HumioPayload{
			Events: []HumioEvent{
				{
					Timestamp:  timestamp,
					Timezone:   timezone,
					Attributes: values.RowData,
				},
			},
			Tags: values.Tags,
		}

		eventChannel <- HumioSubmission{payload, message}
	}

	close(eventChannel)
	wg.Wait()

	return nil
}

// RetryableClient sends http POST requests to Logscale/Humio
type RetryableClient struct {
	client           *http.Client
	url              string
	token            string
	minRetryInterval time.Duration
	maxRetryInterval time.Duration
	maxRetries       int
}

func (rc RetryableClient) doPost(ctx context.Context, payload []byte) (*http.Response, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rc.url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("NewRequestWithContext: %s", err)
		return nil, err
	}

	req.Header.Add("User-Agent", "kakfa-humio-gateway")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", rc.token))

	return rc.client.Do(req)
}

func (rc RetryableClient) postWithRetry(ctx context.Context, payload []byte) error {
	retries := 0
	for {
		resp, err := rc.doPost(ctx, payload)
		if err == nil && resp.StatusCode == http.StatusOK {
			if retries > 0 {
				log.Printf("retry was successful")
			}

			return nil
		}

		if err != nil {
			log.Printf("request failed: %v", err)
		} else {
			body := &bytes.Buffer{}
			_, err = io.Copy(body, resp.Body)
			if err != nil {
				resp.Body.Close()
				return fmt.Errorf("copy of response body failed: %v, %v", resp.Status, err)
			}
			log.Printf("request failed: %v, %s", resp.Status, body)
			resp.Body.Close()
		}

		shouldRetry, _ := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err)
		if shouldRetry {
			retries += 1
			if rc.maxRetries >= 0 && retries > rc.maxRetries {
				return fmt.Errorf("%w: %w", errMaxRetriesExceded, err)
			}

			wait := retryablehttp.DefaultBackoff(rc.minRetryInterval, rc.maxRetryInterval, retries, resp)
			log.Printf("failed to post. Will retry #%d in %v", retries, wait)
			ticker := time.NewTicker(wait)
			select {
			case <-ctx.Done():
				return errContextCancelOnRetry
			case <-ticker.C:
			}
			continue
		}

		return fmt.Errorf("%w: %w", errNonRetryable, err)
	}
}
