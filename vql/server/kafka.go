/* Plugin Kafka.

 */
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"time"

	"github.com/Shopify/sarama"
	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/artifacts"
	"www.velocidex.com/golang/velociraptor/crypto"
	"www.velocidex.com/golang/velociraptor/json"
	"www.velocidex.com/golang/velociraptor/services"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

type _KafkaPluginArgs struct {
	Query              vfilter.StoredQuery `vfilter:"required,field=query,doc=Source for rows to upload."`
	Addresses          []string            `vfilter:"required,field=addresses,doc=A list of Kafka nodes to use."`
	Topic		   string              `vfilter:"required,field=topic,doc=Kafka topic to use to post rows."`
	Threads            int64               `vfilter:"optional,field=threads,doc=How many threads to use."`
	Partition          int                 `vfilter:"optional,field=partition,doc=Kafka partition to use."`
	KeyField           string              `vfilter:"optional,field=key_field,doc=Name of field in row to be used as Key for message."`
	TagFields	   []string            `vfilter:"optional,field=tag_fields,doc=Name of fields to be used as tags. Fields can be renamed using =<newname>"`
	DisableSSLSecurity bool                `vfilter:"optional,field=disable_ssl_security,doc=Disable ssl certificate verifications."`
	RootCerts          string              `vfilter:"optional,field=root_ca,doc=As a better alternative to disable_ssl_security, allows root ca certs to be added here."`
	Retries		   int                 `vfilter:"optional,field=retries,doc=Number of connection retries before failing"`
}

type _KafkaPlugin struct{}

func newProducer(arg *_KafkaPluginArgs, scope vfilter.Scope) (sarama.AsyncProducer, error) {

	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 2

	if arg.RootCerts != "" {

		config_obj, _ := artifacts.GetConfig(scope)

		CA_Pool := x509.NewCertPool()
		crypto.AddPublicRoots(CA_Pool)
		err := crypto.AddDefaultCerts(config_obj, CA_Pool)
		if err != nil {
			scope.Log("kafka: %v", err)
			return nil, err
		}

		if !CA_Pool.AppendCertsFromPEM([]byte(arg.RootCerts)) {
			scope.Log("kafka: Unable to add root certs")
			return nil, err
		}
		config.Net.TLS.Config = &tls.Config{RootCAs: CA_Pool}
		config.Net.TLS.Enable = true
	}

	producer, err := sarama.NewAsyncProducer(arg.Addresses, config)
	if err != nil {
		return nil, err
	}

	return producer, nil
}

func (self _KafkaPlugin) Call(ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	outputChan := make(chan vfilter.Row)

	go func() {
		defer close(outputChan)

		err := vql_subsystem.CheckAccess(scope, acls.COLLECT_SERVER)
		if err != nil {
			scope.Log("kafka: %v", err)
			return
		}

		arg := _KafkaPluginArgs{
			Threads: 1,
			Partition: -1,
		}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, &arg)
		if err != nil {
			scope.Log("kafka: %v", err)
			return
		}

		var tagMapping map[string]string
		if len(arg.TagFields) > 0 {
			tagMapping = map[string]string{}

			for _, descr := range arg.TagFields {
				mapping := strings.Split(descr, "=")
				tagName := mapping[0]

				var mappedName string

				if len(mapping) == 1 {
					mappedName = mapping[0]
				} else {
					if len(mapping) > 2 {
						scope.Log("kafka: Mapping %v contains multiple `=' characters.  Anything following the second `=' will be ignored.")
					}
					mappedName = mapping[1]
				}
				tagMapping[tagName] = mappedName
			}
		}

		scope.Log("Connecting to brokers @%v", arg.Addresses)
		producer, err := newProducer(&arg, scope)

		if err != nil {
			scope.Log("kafka: Could not establish connection to broker(s): %v", err)
			return
		}

		wg := sync.WaitGroup{}
		wg.Add(2)
		go handleSuccesses(ctx, &wg, producer, outputChan)
		go handleErrors(ctx, &wg, producer, outputChan)

		if arg.Threads <= 0 {
			arg.Threads = 1
		}

		rowChan := arg.Query.Eval(ctx, scope)
		for i := 0; i < int(arg.Threads); i++ {
			wg.Add(1)

			// Start an uploader on a thread.
			go processRows(ctx, scope, outputChan, rowChan, &wg, producer, arg.Topic,
				       arg.KeyField, arg.Partition, &tagMapping)
		}

		wg.Wait()
		producer.AsyncClose()
	}()
	return outputChan
}

func logSuccesses(ctx context.Context, outputChan chan vfilter.Row, count int) {
	select {
	case <- ctx.Done():
		return
	case outputChan <- ordereddict.NewDict().
		Set("Report", "Success").
		Set("Count", count):
	}
}

// Batch the success reports so we don't flood the log
func handleSuccesses(ctx context.Context, wg *sync.WaitGroup, producer sarama.AsyncProducer,
		     outputChan chan vfilter.Row) {
	count := 0

	defer logSuccesses(ctx, outputChan, count)
	defer wg.Done()

	for {
		do_update_client := false

		select {
		case _, ok := <- producer.Successes():
			if !ok {
				return
			}
			count += 1
			if count % 100 == 0 {
				do_update_client = true
			}
		case <- time.After(60 * time.Second):
			do_update_client = true
		}

		if do_update_client {
			logSuccesses(ctx, outputChan, count)
			count = 0
		}
	}
}

// Report errors immediately
func handleErrors(ctx context.Context, wg *sync.WaitGroup, producer sarama.AsyncProducer,
		  outputChan chan vfilter.Row) {
	defer wg.Done()

	for err := range producer.Errors() {
		select {
		case <- ctx.Done():
			return
		case outputChan <- ordereddict.NewDict().
			Set("Report", "Error").
			Set("Message", err.Msg).
			Set("Error", err.Err):
		}
	}
}

type VRRKafkaMessage struct {
	Tags       map[string]interface{}   `json:"tags"`
	RowData	   *ordereddict.Dict        `json:"row_data"`
	Version    int                      `json:"version"`
}

// Copy rows from rowChan to a local buffer and push it up to kafka.
func processRows(ctx context.Context, scope vfilter.Scope, outputChan chan vfilter.Row,
		 rowChan <-chan vfilter.Row, wg *sync.WaitGroup, producer sarama.AsyncProducer,
		 topic string, keyField string, partition int, tagMapping *map[string]string) {

	defer wg.Done()

	config_obj, ok := vql_subsystem.GetServerConfig(scope)
	if !ok {
		scope.Log("Command can only run on the server")
		return
	}

	for {
		select {
		case <- ctx.Done():
			return
		case row, ok := <-rowChan:
			if !ok {
				return
			}

			vrrmsg := VRRKafkaMessage{
				RowData: vfilter.RowToDict(ctx, scope, row),
				Version: 1,
				Tags: map[string]interface{}{},
			}

			// Provide the hostname for the client host if it's a client query
			// since an external system will not have a way to map it to a hostname.
			client_id, ok  := vrrmsg.RowData.GetString("ClientId")
			if ok {
				vrrmsg.Tags["ClientId"] = client_id

				hostname := services.GetHostname(ctx, config_obj, client_id)
				if hostname != "" {
					vrrmsg.Tags["ClientHostname"] = hostname
				}
			}

			for name, mappedName := range *tagMapping {
				var value interface{}
				value, ok = vrrmsg.RowData.Get(name)

				if ok {
					vrrmsg.Tags[mappedName] = value
				}
			}

			opts := vql_subsystem.EncOptsFromScope(scope)
			data, err := json.MarshalWithOptions(&vrrmsg, opts)
			if err != nil {
				scope.Log("Row encountered that cannot be marshaled: %v", err)
				continue
			}

			msg := &sarama.ProducerMessage{
				Topic:	topic,
				Partition: int32(partition),
				Value:	   sarama.StringEncoder(data),
			}

			if keyField != "" {
				key, ok := vrrmsg.RowData.GetString(keyField)
				if !ok {
					scope.Log("key_field specified as `%s' but there is no field with that name.  Message [%s] has been dropped.",
						  keyField, data)
					continue
				}
				msg.Key = sarama.StringEncoder(key)
			}

			producer.Input() <- msg
		}
	}
}

func (self _KafkaPlugin) Info(
	scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "kafka_producer",
		Doc:  "Submit rows to kafka.",

		ArgType: type_map.AddType(scope, &_KafkaPluginArgs{}),
	}
}

func init() {
	vql_subsystem.RegisterPlugin(&_KafkaPlugin{})
}
