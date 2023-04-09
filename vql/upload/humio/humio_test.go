package humio

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"net"
	"net/http"
	"net/http/httptest"

        "github.com/stretchr/testify/require"
        "github.com/stretchr/testify/suite"

	"github.com/Velocidex/ordereddict"
        actions_proto "www.velocidex.com/golang/velociraptor/actions/proto"
        "www.velocidex.com/golang/velociraptor/datastore"

        "www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/json"
	"www.velocidex.com/golang/velociraptor/logging"
        "www.velocidex.com/golang/velociraptor/paths"
        "www.velocidex.com/golang/velociraptor/services"
        "www.velocidex.com/golang/velociraptor/services/indexing"
        "www.velocidex.com/golang/velociraptor/vql/acl_managers"
        vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/functions"
        "www.velocidex.com/golang/velociraptor/vtesting"

	vfilter "www.velocidex.com/golang/vfilter"
)

var (
	validUrl = "https://cloud.community.humio.com/api"
	validAuthToken = "valid-ingest-token"
	validWorkerCount = 1
	invalidWorkerCount = -11
	testTimestampStringTZ = "2023-04-05T13:36:51-04:00"
	testTimestampUNIX = uint64(1680716211)  // json ints are uint64
	testTimestamp = "2023-04-05T17:36:51Z"
	testClientId = "C.0030300330303000"
	testHostname = "testhost12"
)

type HumioQueueTestSuite struct {
	test_utils.TestSuite

	queue		*HumioQueue
	scope		vfilter.Scope
	ctx		context.Context

	repoManager	services.RepositoryManager
	timestamp	time.Time
        clients		[]string

	server		*httptest.Server
}

func formatTimestamp(ts time.Time) string {
	// json.MarshalWithOptions(payloads, opts) will turn this into UTC
	return ts.UTC().Format(time.RFC3339Nano)
}

func (self *HumioQueueTestSuite) SetupTest() {
	self.ConfigObj = self.LoadConfig()
	self.TestSuite.SetupTest()

	self.queue = NewHumioQueue(self.ConfigObj)
	self.queue.SetHttpClientTimeoutDuration(time.Duration(1) * time.Second)
	self.queue.SetMaxRetries(1)
	self.scope = self.getScope()

	self.ctx = context.Background()
	self.populateClients()
}

func (self *HumioQueueTestSuite) populateClients() {
        self.clients = nil
        db, err := datastore.GetDB(self.ConfigObj)
        require.NoError(self.T(), err)

	indexer, err := services.GetIndexer(self.ConfigObj)
        require.NoError(self.T(), err)

	count := 0

        bytes := []byte("00000000")
        for i := 0; i < 4; i++ {
                bytes[0] = byte(i)
                for k := 0; k < 4; k++ {
                        bytes[3] = byte(k)
                        for j := 0; j < 4; j++ {
                                bytes[7] = byte(j)
                                client_id := fmt.Sprintf("C.%02x", bytes)
				hostname := ""
				if count != 10 {
					hostname = fmt.Sprintf("testhost%v", count)
				}
                                self.clients = append(self.clients, client_id)
                                err := indexer.SetIndex(client_id, client_id)
                                require.NoError(self.T(), err)

                                path_manager := paths.NewClientPathManager(client_id)
				record := &actions_proto.ClientInfo{ClientId: client_id, Hostname: hostname}
                                err = db.SetSubject(self.ConfigObj, path_manager.Path(), record)
                                require.NoError(self.T(), err)

				count += 1
                        }
                }
        }

        // Wait here until the indexer is ready
        vtesting.WaitUntil(2*time.Second, self.T(), func() bool {
                return indexer.(*indexing.Indexer).IsReady()
        })
}

func (self *HumioQueueTestSuite) getScope() vfilter.Scope {
        manager, err := services.GetRepositoryManager(self.ConfigObj)
	require.NoError(self.T(), err)

        builder := services.ScopeBuilder{
                Config:     self.ConfigObj,
                ACLManager: acl_managers.NullACLManager{},
                Logger:     logging.NewPlainLogger(self.ConfigObj,
						   &logging.FrontendComponent),
                Env:        ordereddict.NewDict(),
        }

	return manager.BuildScope(builder)
}

func generateRow() *ordereddict.Dict {
	return ordereddict.NewDict().
		Set("_ts", testTimestampUNIX).
		Set("TestValue1", "value1").
		Set("TestValue2", "value2").
		Set("TestValue3", "value3").
		Set("TestValue4", "value4").
		Set("Artifact", "Humio.Client.Events"). 
		Set("ClientId", testClientId)
}

func (self *HumioQueueTestSuite) TearDownTest() {
	if self.queue != nil {
		self.queue.Close(self.scope)
	}
}

func (self *HumioQueueTestSuite) TestEmptyUrl() {
	err := self.queue.Open(self.scope, "", validAuthToken)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestInvalidUrl() {
	err := self.queue.Open(self.scope, "invalid-url", validAuthToken)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestValidUrl() {
	err := self.queue.Open(self.scope, validUrl, validAuthToken)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestEmptyAuthToken() {
	err := self.queue.Open(self.scope, validUrl, "")
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestValidAuthToken() {
	err := self.queue.Open(self.scope, validUrl, validAuthToken)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestInvalidThreads() {
	err := self.queue.SetWorkerCount(-1)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestValidThreads() {
	err := self.queue.SetWorkerCount(validWorkerCount)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestSetEventBatchSizeValid() {
	err := self.queue.SetEventBatchSize(10)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestSetEventBatchSizeZero() {
	err := self.queue.SetEventBatchSize(0)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetEventBatchSizeNegative() {
	err := self.queue.SetEventBatchSize(-10)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetBatchingTimeoutDurationValid() {
	err := self.queue.SetBatchingTimeoutDuration(10 * time.Second)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestSetBatchingTimeoutDurationZero() {
	err := self.queue.SetBatchingTimeoutDuration(0 * time.Second)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetBatchingTimeoutDurationNegative() {
	err := self.queue.SetBatchingTimeoutDuration(-10 * time.Second)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetHttpClientTimeoutDurationValid() {
	err := self.queue.SetHttpClientTimeoutDuration(10 * time.Second)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestSetHttpClientTimeoutDurationZero() {
	err := self.queue.SetHttpClientTimeoutDuration(0 * time.Second)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetHttpClientTimeoutDurationNegative() {
	err := self.queue.SetHttpClientTimeoutDuration(-10 * time.Second)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetTaggedFieldsValid() {
	args := []string{"x=y", "y=z", "z"}
	expected := map[string]string{
		"x" : "y",
		"y" : "z",
		"z" : "z",
	}
	err := self.queue.SetTaggedFields(args)
	require.NoError(self.T(), err)
	require.EqualValues(self.T(), self.queue.tagMap, expected)
}

func (self *HumioQueueTestSuite) TestSetTaggedFieldsEmptyTagName() {
	args := []string{"=y", "y=z", "z"}
	err := self.queue.SetTaggedFields(args)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetTaggedFieldsMultipleEquals() {
	args := []string{"x=y", "y=z=z", }
	err := self.queue.SetTaggedFields(args)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) TestSetTaggedFieldsEmptyTagArg() {
	args := []string{}
	err := self.queue.SetTaggedFields(args)
	require.NoError(self.T(), err)
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioQueueTestSuite) TestSetTaggedFieldsEmptyTagString() {
	args := []string{"",}
	err := self.queue.SetTaggedFields(args)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioQueueTestSuite) checkTimestamp(payload *HumioPayload) {
	require.Equal(self.T(), testTimestamp, formatTimestamp(payload.Events[0].Timestamp))
	require.Equal(self.T(), "", payload.Events[0].Timezone)
}

func (self *HumioQueueTestSuite) TestTimestamp_TimeString() {
	row := ordereddict.NewDict().
		Set("Time", testTimestampStringTZ).
		Set("timestamp", testTimestampStringTZ).
		Set("_ts", testTimestampStringTZ).
		Set("TestValue", "value")

	payload := NewHumioPayload(row)

	self.queue.addTimestamp(self.scope, row, payload)

	self.checkTimestamp(payload)
}

func (self *HumioQueueTestSuite) TestTimestamp_timestampString() {
	row := ordereddict.NewDict().
		Set("timestamp", testTimestampStringTZ).
		Set("_ts", testTimestampStringTZ).
		Set("TestValue", "value")

	payload := NewHumioPayload(row)

	self.queue.addTimestamp(self.scope, row, payload)

	self.checkTimestamp(payload)
}

func (self *HumioQueueTestSuite) TestTimestamp__tsString() {
	row := ordereddict.NewDict().
		Set("_ts", testTimestampStringTZ).
		Set("TestValue", "value")

	payload := NewHumioPayload(row)

	self.queue.addTimestamp(self.scope, row, payload)

	self.checkTimestamp(payload)
}

func (self *HumioQueueTestSuite) TestTimestamp_TimeUNIX() {
	row := ordereddict.NewDict().
		Set("Time", testTimestampUNIX).
		Set("timestamp", testTimestampUNIX).
		Set("_ts", testTimestampUNIX).
		Set("TestValue", "value")

	payload := NewHumioPayload(row)

	self.queue.addTimestamp(self.scope, row, payload)

	self.checkTimestamp(payload)
}

func (self *HumioQueueTestSuite) TestTimestamp_timestampUNIX() {
	row := ordereddict.NewDict().
		Set("timestamp", testTimestampUNIX).
		Set("_ts", testTimestampUNIX).
		Set("TestValue", "value")

	payload := NewHumioPayload(row)

	self.queue.addTimestamp(self.scope, row, payload)

	self.checkTimestamp(payload)
}

func (self *HumioQueueTestSuite) TestTimestamp__tsUNIX() {
	row := ordereddict.NewDict().
		Set("_ts", testTimestampUNIX).
		Set("TestValue", "value")

	payload := NewHumioPayload(row)

	self.queue.addTimestamp(self.scope, row, payload)

	self.checkTimestamp(payload)
}

func (self *HumioQueueTestSuite) TestAddMappedTags() {
	row := generateRow()

	expected := map[string]string{
		"TestValue3": "value3",
		"TestValue4": "value4",
	}

	expectedTags := []string{}
	for k := range expected {
		expectedTags = append(expectedTags, k)
	}

	payload := NewHumioPayload(row)

	self.queue.SetTaggedFields(expectedTags)
	self.queue.addMappedTags(row, payload)

	actualTags := []string{}
	for k := range payload.Tags {
		actualTags = append(actualTags, k)
	}

	require.ElementsMatch(self.T(), expectedTags, actualTags)
	for k := range expected {
		require.Equal(self.T(), expected[k], payload.Tags[k])
	}
}

func (self *HumioQueueTestSuite) TestAddClientInfo() {
	row := generateRow()

	payload := NewHumioPayload(row)
	self.queue.addClientInfo(self.ctx, row, payload)

	require.Contains(self.T(), payload.Tags, "ClientHostname")
	require.EqualValues(self.T(), payload.Tags["ClientHostname"], testHostname)
}

func (self *HumioQueueTestSuite) TestRowToPayload() {
	row := generateRow()

	expectedTags := []string{
		"TestValue3",
		"TestValue4",
		"ClientId",
		"ClientHostname",
	}

	self.queue.SetTaggedFields(expectedTags)

	payload := self.queue.rowToPayload(self.ctx, self.scope, row)

	expectedAttributes := row.Keys()
	actualAttributes := payload.Events[0].Attributes.Keys()

	require.EqualValues(self.T(), expectedAttributes, actualAttributes)
	for _, k := range expectedAttributes {
		expected, ok := row.Get(k)
		require.True(self.T(), ok)

		actual, ok := row.Get(k)
		require.True(self.T(), ok)

		require.EqualValues(self.T(), expected, actual)
	}

	actualTags := []string{}
	for k := range payload.Tags {
		actualTags = append(actualTags, k)
	}

	require.ElementsMatch(self.T(), expectedTags, actualTags)
	for _, k := range expectedTags {
		var val interface{}
		if k == "ClientHostname" {
			val = testHostname
		} else {
			var ok bool
			val, ok = row.Get(k)
			require.True(self.T(), ok)
		} 
		require.EqualValues(self.T(), val, payload.Tags[k])
	}

	self.checkTimestamp(payload)
}

func (self *HumioQueueTestSuite) handleEndpointRequest(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || strings.ToLower(strings.TrimSpace(auth))[0:7] != "bearer " {
	        w.WriteHeader(http.StatusUnauthorized)
	        w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	        fmt.Fprintf(w, "The supplied authentication is invalid")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
	        w.WriteHeader(http.StatusInternalServerError)
	        w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		fmt.Fprintf(w, "Internal failure. reason=%s", err)
		return
	}

	data := []HumioPayload{}

	err = json.Unmarshal(body, &data)
	if err != nil {
	        w.WriteHeader(http.StatusBadRequest)
	        w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	        fmt.Fprintf(w, "Could not handle input. reason=%s", err)
	        return
	}

	// Empty submission is valid
	if len(data) > 0 {
		if len(data[0].Events) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			fmt.Fprintf(w, "Could not handle input. reason=%s", "Could not parse JSON")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w,  "{}")
}

func handler401(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	fmt.Fprintf(w, "unauthorized")
}

func handler500(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	fmt.Fprintf(w, "internal server error")
}

func handlerTimeout(w http.ResponseWriter, r *http.Request) {
	time.Sleep(time.Duration(3) * time.Second)
}


func (self *HumioQueueTestSuite) startMockServerWithHandler(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	    switch strings.TrimSpace(r.URL.Path) {
	    case apiEndpoint:
		    handler(w, r)
	    default:
		http.NotFoundHandler().ServeHTTP(w, r)
	    }
	}))
}

func (self *HumioQueueTestSuite) startMockServer() *httptest.Server {
	return self.startMockServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		self.handleEndpointRequest(w, r)
	})
}

func (self *HumioQueueTestSuite) updateEndpointUrl(server *httptest.Server) {
	self.queue.endpointUrl = server.URL + apiEndpoint
}

func (self *HumioQueueTestSuite) preparePayloads(payloads []*HumioPayload) []byte {
	opts := vql_subsystem.EncOptsFromScope(self.scope)                            
        data, err := json.MarshalWithOptions(payloads, opts)
	require.NoError(self.T(), err)
	return data
}

func (self *HumioQueueTestSuite) TestPostBytesValid() {
	row := generateRow()
	timestamp, _ := functions.TimeFromAny(self.scope, testTimestampStringTZ)
	payloads := []*HumioPayload{
			&HumioPayload{
				Events: []HumioEvent{
					HumioEvent{
						Attributes: row,
						Timestamp: timestamp,
					},
				},
				Tags: map[string]interface{}{
					"ClientId" : testClientId,
					"ClientHostname" : testHostname,
				},
			},
		}

	server := self.startMockServer()
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	data := self.preparePayloads(payloads)

	err, retry := self.queue.postBytes(self.ctx, self.scope, data, len(payloads))
	require.NoError(self.T(), err)
	require.False(self.T(), retry)
}

// Pointless but still valid
func (self *HumioQueueTestSuite) TestPostBytesEmpty() {
	payloads := []*HumioPayload{}

	server := self.startMockServer()
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	data := self.preparePayloads(payloads)

	err, retry := self.queue.postBytes(self.ctx, self.scope, data, len(payloads))
	require.NoError(self.T(), err)
	require.False(self.T(), retry)
}

func (self *HumioQueueTestSuite) TestPostBytesEmptyTimeout() {
	payloads := []*HumioPayload{}

	server := self.startMockServerWithHandler(handlerTimeout)
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	data := self.preparePayloads(payloads)

	err, retry := self.queue.postBytes(self.ctx, self.scope, data, len(payloads))
	var netErr net.Error
	require.ErrorAs(self.T(), err, &netErr)
	require.True(self.T(), netErr.Timeout())
	require.True(self.T(), retry)
}

func (self *HumioQueueTestSuite) TestPostBytesEmptyConnRefused() {
	payloads := []*HumioPayload{}

	err := self.queue.Open(self.scope, "http://localhost:1", validAuthToken)
	require.NoError(self.T(), err)

	data := self.preparePayloads(payloads)

	err, retry := self.queue.postBytes(self.ctx, self.scope, data, len(payloads))
	var netErr net.Error
	require.ErrorAs(self.T(), err, &netErr)
	require.ErrorIs(self.T(), err, syscall.ECONNREFUSED)
	require.True(self.T(), retry)
}

func (self *HumioQueueTestSuite) TestPostBytesNoEvents() {
	payloads := []*HumioPayload{
			&HumioPayload{
				Tags: map[string]interface{}{
					"ClientId" : testClientId,
					"ClientHostname" : testHostname,
				},
			},
		}

	server := self.startMockServer()
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	data := self.preparePayloads(payloads)
	err, retry := self.queue.postBytes(self.ctx, self.scope, data, len(payloads))
	clientError := errHttpClientError{}
	require.True(self.T(), errors.As(err, &clientError))
	require.Equal(self.T(), clientError.StatusCode, http.StatusBadRequest)
	require.False(self.T(), retry)
}

func (self *HumioQueueTestSuite) TestPostEventsEmpty() {
	rows := []*ordereddict.Dict{}

	server := self.startMockServer()
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	err = self.queue.postEvents(self.ctx, self.scope, rows)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestPostEventsSingle() {
	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())

	server := self.startMockServer()
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	err = self.queue.postEvents(self.ctx, self.scope, rows)
	require.Equal(self.T(), 1, len(rows))
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestPostEventsSingleTimeout() {
	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())

	server := self.startMockServerWithHandler(handlerTimeout)
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	err = self.queue.postEvents(self.ctx, self.scope, rows)
	require.NotNil(self.T(), err)
	expectedErr := errMaxRetriesExceeded{}
	require.ErrorAs(self.T(), err, &expectedErr)

	var netErr net.Error
	require.ErrorAs(self.T(), err, &netErr)
	require.True(self.T(), netErr.Timeout())
}

func (self *HumioQueueTestSuite) TestPostEventsSingleConnRefused() {
	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())

	server := self.startMockServerWithHandler(handlerTimeout)
	defer server.Close()

	err := self.queue.Open(self.scope, "http://localhost:1", validAuthToken)
	require.NoError(self.T(), err)

	err = self.queue.postEvents(self.ctx, self.scope, rows)
	require.NotNil(self.T(), err)
	expectedErr := errMaxRetriesExceeded{}
	require.ErrorAs(self.T(), err, &expectedErr)

	var netErr net.Error
	require.ErrorAs(self.T(), err, &netErr)
	require.ErrorIs(self.T(), err, syscall.ECONNREFUSED)
}

func (self *HumioQueueTestSuite) TestPostEventsMultiple() {
	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())

	server := self.startMockServer()
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	err = self.queue.postEvents(self.ctx, self.scope, rows)
	require.NoError(self.T(), err)
}

func (self *HumioQueueTestSuite) TestPostEventsMultipleTimeout() {
	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())

	server := self.startMockServerWithHandler(handlerTimeout)
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	err = self.queue.postEvents(self.ctx, self.scope, rows)
	require.NotNil(self.T(), err)
	expectedErr := errMaxRetriesExceeded{}
	require.ErrorAs(self.T(), err, &expectedErr)

	var netErr net.Error
	require.ErrorAs(self.T(), err, &netErr)
	require.True(self.T(), netErr.Timeout())
}

func (self *HumioQueueTestSuite) TestPostEventsMultipleConnRefused() {
	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())

	server := self.startMockServerWithHandler(handlerTimeout)
	defer server.Close()

	err := self.queue.Open(self.scope, "http://localhost:1", validAuthToken)
	require.NoError(self.T(), err)

	err = self.queue.postEvents(self.ctx, self.scope, rows)
	require.NotNil(self.T(), err)
	expectedErr := errMaxRetriesExceeded{}
	require.ErrorAs(self.T(), err, &expectedErr)

	var netErr net.Error
	require.ErrorAs(self.T(), err, &netErr)
	require.ErrorIs(self.T(), err, syscall.ECONNREFUSED)
}

// Test whether events just make it into the queue properly
func (self *HumioQueueTestSuite) TestQueueEvents_Queued() {
	server := self.startMockServer()
	defer server.Close()

	// Special case: We want to do the processing ourselves
	self.queue.nWorkers = 0

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}

	require.Equal(self.T(), len(rows), int(atomic.LoadInt32(&self.queue.currentQueueDepth)))

	// Nothing is clearing the queue, so clear it so we don't get stuck during close
	for _, _ = range(rows) {
		<- self.queue.listener.Output()
	}
}

// Test whether events just make it back out of the queue and post properly
func (self *HumioQueueTestSuite) TestQueueEventsOpen_Dequeued() {
	server := self.startMockServer()
	defer server.Close()

	// Special case: We want to do the processing ourselves
	self.queue.nWorkers = 0

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())

	ctx, cancel := context.WithTimeout(self.ctx, time.Duration(1) * time.Second)

	// This is a worker.  It would've been started as part of Open()
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		count := 0
		L:
		for {
			select {
			case <- ctx.Done():
				break L
			case row, ok := <- self.queue.listener.Output():
				if !ok {
					break L
				}

				// Don't build up a list, just push one at a time for testing
				post := []*ordereddict.Dict{row}
				err = self.queue.postEvents(ctx, self.scope, post)
				require.NoError(self.T(), err)

				count += 1
			}
		}
		require.Equal(self.T(), len(rows), count)
	}()

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}

	wg.Wait()
	require.Equal(self.T(), len(rows), int(atomic.LoadInt32(&self.queue.currentQueueDepth)))
	require.Equal(self.T(), 4, int(atomic.LoadInt32(&self.queue.postedEvents)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.failedEvents)))
	cancel()
}

// Test whether events just make it back out of the queue and are handled properly when the post fails
func (self *HumioQueueTestSuite) TestQueueEventsOpen_DequeuedFailure() {
	server := self.startMockServer()
	defer server.Close()

	// Special case: We want to do the processing ourselves
	self.queue.nWorkers = 0

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())

	ctx, cancel := context.WithTimeout(self.ctx, time.Duration(5) * time.Second)

	// This is a worker.  It would've been started as part of Open()
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		count := 0
		L:
		for {
			select {
			case <- ctx.Done():
				break L
			case row, ok := <- self.queue.listener.Output():
				if !ok {
					break L
				}
				atomic.AddInt32(&self.queue.currentQueueDepth, -1)

				if count == 2 {
					server.Close()
					server = self.startMockServerWithHandler(handler500)
					self.updateEndpointUrl(server)
				}

				// Don't build up a list, just push one at a time for testing
				post := []*ordereddict.Dict{row}
				err = self.queue.postEvents(ctx, self.scope, post)
				if count >= 2 {
					require.NotNil(self.T(), err)
					expectedErr := errMaxRetriesExceeded{}
					require.ErrorAs(self.T(), err, &expectedErr)
				} else {
					require.NoError(self.T(), err)
				}

				count += 1
			}
		}
		require.Equal(self.T(), len(rows), count)
	}()

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}

	wg.Wait()
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.currentQueueDepth)))
	require.Equal(self.T(), 2, int(atomic.LoadInt32(&self.queue.failedEvents)))
	require.Equal(self.T(), 2, int(atomic.LoadInt32(&self.queue.postedEvents)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.droppedEvents)))
	cancel()
}

func (self *HumioQueueTestSuite) TestQueueEventsOpen_DequeuedConnRefused() {
	server := self.startMockServer()
	defer server.Close()

	// Special case: We want to do the processing ourselves
	self.queue.nWorkers = 0

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())
	rows = append(rows, generateRow())

	ctx, cancel := context.WithTimeout(self.ctx, time.Duration(5) * time.Second)

	// This is a worker.  It would've been started as part of Open()
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		count := 0
		L:
		for {
			select {
			case <- ctx.Done():
				break L
			case row, ok := <- self.queue.listener.Output():
				if !ok {
					break L
				}
				atomic.AddInt32(&self.queue.currentQueueDepth, -1)

				if count == 2 {
					self.queue.endpointUrl = "http://localhost:1" + apiEndpoint
				}

				// Don't build up a list, just push one at a time for testing
				post := []*ordereddict.Dict{row}
				err = self.queue.postEvents(ctx, self.scope, post)
				if count >= 2 {
					require.NotNil(self.T(), err)
					expectedErr := errMaxRetriesExceeded{}
					require.ErrorAs(self.T(), err, &expectedErr)
				} else {
					require.NoError(self.T(), err)
				}

				count += 1
			}
		}
		require.Equal(self.T(), len(rows), count)
	}()

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}


	wg.Wait()
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.currentQueueDepth)))
	require.Equal(self.T(), 2, int(atomic.LoadInt32(&self.queue.failedEvents)))
	require.Equal(self.T(), 2, int(atomic.LoadInt32(&self.queue.postedEvents)))
	cancel()
}

func (self *HumioQueueTestSuite) TestProcessEvents_Working() {
	nRows := 100

	server := self.startMockServer()
	defer server.Close()

	err := self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	for i := 0; i < nRows; i += 1 {
		rows = append(rows, generateRow())
	}

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}

	self.queue.Close(self.scope)

	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.currentQueueDepth)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.failedEvents)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.droppedEvents)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.totalRetries)))
	require.Equal(self.T(), nRows, int(atomic.LoadInt32(&self.queue.postedEvents)))
}

func (self *HumioQueueTestSuite) TestProcessEvents_ShutdownWhileFailing() {
	nRows := 100

	server := self.startMockServer()
	defer server.Close()

	self.queue.SetEventBatchSize(1)
	err := self.queue.addDebugCallback(nRows / 2, func(count int) {
			self.queue.endpointUrl = "http://localhost:1" + apiEndpoint
		})

	err = self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	for i := 0; i < nRows; i += 1 {
		rows = append(rows, generateRow())
	}

	require.NoError(self.T(), err)

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}

	self.queue.Close(self.scope)

	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.currentQueueDepth)))
	require.Equal(self.T(), 1, int(atomic.LoadInt32(&self.queue.failedEvents)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.totalRetries)))
	require.Equal(self.T(), (nRows / 2) - 1, int(atomic.LoadInt32(&self.queue.droppedEvents)))
	require.Equal(self.T(), nRows / 2, int(atomic.LoadInt32(&self.queue.postedEvents)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.totalRetries)))
}

func (self *HumioQueueTestSuite) TestProcessEvents_ShutdownAfterRecovery() {
	nRows := 100

	server := self.startMockServer()
	defer server.Close()

	self.queue.SetEventBatchSize(1)

	wg1 := sync.WaitGroup{}
	wg1.Add(1)
	err := self.queue.addDebugCallback(25, func(count int) {
			server.Close()
			server = self.startMockServerWithHandler(handler500)
			self.updateEndpointUrl(server)

		})

	err = self.queue.addDebugCallback(26, func(count int) {
			server.Close()
			server = self.startMockServer()
			self.updateEndpointUrl(server)

		})

	err = self.queue.addDebugCallback(99, func(count int) {
		wg1.Done()
		})

	err = self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	for i := 0; i < nRows; i += 1 {
		rows = append(rows, generateRow())
	}

	require.NoError(self.T(), err)

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}

	wg1.Wait()

	self.queue.Close(self.scope)

	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.currentQueueDepth)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.droppedEvents)))
	require.Equal(self.T(), nRows - 1, int(atomic.LoadInt32(&self.queue.postedEvents)))
	require.Equal(self.T(), 1, int(atomic.LoadInt32(&self.queue.totalRetries)))
	require.Equal(self.T(), 1, int(atomic.LoadInt32(&self.queue.failedEvents)))
}

func (self *HumioQueueTestSuite) TestProcessEvents_4xx() {
	nRows := 100

	server := self.startMockServer()
	defer server.Close()

	self.queue.SetEventBatchSize(1)
	wg1 := sync.WaitGroup{}
	wg1.Add(1)
	err := self.queue.addDebugCallback(25, func(count int) {
			server.Close()
			server = self.startMockServerWithHandler(handler401)
			self.updateEndpointUrl(server)

		})

	err = self.queue.addDebugCallback(30, func(count int) {
			server.Close()
			server = self.startMockServer()
			self.updateEndpointUrl(server)

		})

	err = self.queue.addDebugCallback(99, func(count int) {
		wg1.Done()
		})

	err = self.queue.Open(self.scope, server.URL, validAuthToken)
	require.NoError(self.T(), err)

	rows := []*ordereddict.Dict{}

	for i := 0; i < nRows; i += 1 {
		rows = append(rows, generateRow())
	}

	require.NoError(self.T(), err)

	for _, row := range rows {
		self.queue.QueueEvent(row)
	}

	wg1.Wait()

	self.queue.Close(self.scope)

	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.currentQueueDepth)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.droppedEvents)))
	require.Equal(self.T(), 95, int(atomic.LoadInt32(&self.queue.postedEvents)))
	require.Equal(self.T(), 0, int(atomic.LoadInt32(&self.queue.totalRetries)))
	require.Equal(self.T(), 5, int(atomic.LoadInt32(&self.queue.failedEvents)))
}

func TestHumioQueue(t *testing.T) {                                               
	gMaxPoll = 1
	gMaxPollDev = 1
        suite.Run(t, new(HumioQueueTestSuite))                                        
}
