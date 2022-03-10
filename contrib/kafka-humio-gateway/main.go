package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-yaml/yaml"
	"github.com/Shopify/sarama"
)

var (
	verbose  = false
	configFile string
	defaultConsumerGroup = "velociraptor-consumer"
)


type TransportConfig struct {
	Kafka struct {
		Brokers []string
		Topics []string
		ConsumerGroup string `yaml:"consumer_group"`
	}
	Humio struct {
		EndpointUrl string `yaml:"endpoint_url"`
		IngestToken string `yaml:"ingest_token"`
	}
}

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&configFile, "config", "config.yml", "Path to YaML file containing configuration")
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
		log.Printf("warning: config missing `kafka.consumer_group'.  Using default `%s'", consumer.config.Kafka.ConsumerGroup)
	}

	if consumer.config.Humio.EndpointUrl == "" {
		log.Fatalf("error: config missing `humio.endpoint_url'")
	}

	_, err = url.ParseRequestURI(consumer.config.Humio.EndpointUrl)
	if err != nil {
		log.Fatalf("Humio Endpoint Url `%s' is not valid: %v", consumer.config.Humio.EndpointUrl, err)
	}

	if consumer.config.Humio.IngestToken == "" {
		log.Fatalf("error: config missing `humio.ingest_token'")
	}

	log.Printf("Joining consumer group `%s'", consumer.config.Kafka.ConsumerGroup)
	log.Printf("Will post events to Humio Endpoint `%s'", consumer.config.Humio.EndpointUrl)

	consumer.httpClient = http.Client{Timeout: time.Duration(1) * time.Second}

	if verbose {
		sarama.Logger = log.New(os.Stdout, "[sarama] ", log.LstdFlags)
	}

	saramaConfig := sarama.NewConfig()
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
	httpClient http.Client
	config     TransportConfig
}

// Setup is run at the beginning of a new session, before ConsumeClaim
func (consumer *Consumer) Setup(sarama.ConsumerGroupSession) error {
	consumer.setupOnce.Do(consumer.readyWg.Done())
	return nil
}

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited
func (consumer *Consumer) Cleanup(sarama.ConsumerGroupSession) error {
	return nil
}


// The Row data can be string or int.  We don't care which.  We just pass it through.
type VRRKafkaMessage struct {
        Tags       map[string]interface{}    `json:"tags"`
        RowData    map[string]interface{}    `json:"row_data"`
        Version    int                       `json:"version"`
}

type HumioEvent struct {
	// Could be string or int.  We don't need to care which.
        Timestamp interface{}               `json:"timestamp"`
        Attributes  map[string]interface{}  `json:"attributes"`
        Timezone string                     `json:"timezone,omitempty"`
}

type HumioPayload struct {
        Events []HumioEvent                 `json:"events"`
        Tags map[string]interface{}         `json:"tags,omitempty"`
}

// ConsumeClaim must start a consumer loop of ConsumerGroupClaim's Messages().
func (consumer *Consumer) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	// NOTE:
	// Do not move the code below to a goroutine.
	// The `ConsumeClaim` itself is called within a goroutine, see:
	// https://github.com/Shopify/sarama/blob/main/consumer_group.go#L27-L29
	for message := range claim.Messages() {
		var data []byte
		var err error
		if verbose {
			log.Printf("Received message Topic[%s] Key[%s] Value[%s] Timestamp[%v]", message.Topic, message.Key, message.Value, message.Timestamp)
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
			timezone = "UTC"
		}


		if !ok {
			log.Printf("Failed to gather timestamp from event: %s", message.Value)
			session.MarkMessage(message, "")
			continue
		}

		payload := HumioPayload{
			Events: []HumioEvent {
				HumioEvent{
					Timestamp: timestamp,
					Timezone: timezone,
					Attributes: values.RowData,
				},
			},
			Tags: values.Tags,
		}

		// We now know we have a valid message.  Any failures must not MarkMessage
		// the message.  It will be left in the queue until the failure has been resolved.

		wrapped := []HumioPayload{payload}

		data, err = json.Marshal(wrapped)
		if err != nil {
			log.Printf("Failed to marshal %v: %v", wrapped, err)
			continue
		}

		if verbose {
			log.Printf("POSTing data: [%s]", data)
		}

		req, err := http.NewRequest("POST", consumer.config.Humio.EndpointUrl, bytes.NewReader(data))
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", consumer.config.Humio.IngestToken))

		resp, err := consumer.httpClient.Do(req)
		if err != nil {
			log.Printf("Error while POSTing data: %v", err)

			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Failed to POST data [%s]: %s", resp.Status, body)

			// We didn't land it in Humio - let the message sit until we can get to it
			continue
		}

		if verbose {
			log.Printf("POSTed successfully.")
		}

		// Message has landed, clear it
		session.MarkMessage(message, "")
	}

	return nil
}
