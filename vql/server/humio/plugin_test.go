package humio

import (
	"testing"
	"time"

        "github.com/stretchr/testify/require"
        "github.com/stretchr/testify/suite"
)

type HumioPluginTestSuite struct {
	suite.Suite

	args humioPluginArgs
	queue *HumioQueue
}

func (self *HumioPluginTestSuite) SetupTest() {
	self.args = humioPluginArgs{
		ApiBaseUrl: validUrl,
		IngestToken: validAuthToken,
	}

	// config isn't used for these tests
	self.queue = NewHumioQueue(nil)
}

func (self *HumioPluginTestSuite) TestValidateEmptyUrl() {
	self.args.ApiBaseUrl = ""
	err := self.args.validate()
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioPluginTestSuite) TestValidateInvalidUrl() {
	self.args.ApiBaseUrl = "invalid-url"
	err := self.args.validate()
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioPluginTestSuite) TestValidateValid() {
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateEmptyAuthToken() {
	self.args.IngestToken = ""
	err := self.args.validate()
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioPluginTestSuite) TestValidateInvalidThreads() {
	self.args.Threads = -1
	err := self.args.validate()
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioPluginTestSuite) TestValidateValidThreads() {
	self.args.Threads = validWorkerCount
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateSetEventBatchSizeValid() {
	self.args.EventBatchSize = 10
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateSetEventBatchSizeZero() {
	self.args.EventBatchSize = 0
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateSetEventBatchSizeNegative() {
	self.args.EventBatchSize = -10
	err := self.args.validate()
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioPluginTestSuite) TestValidateSetBatchingTimeoutDurationValid() {
	self.args.BatchingTimeoutMs = 10
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateSetBatchingTimeoutDurationZero() {
	self.args.BatchingTimeoutMs = 0
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateSetBatchingTimeoutDurationNegative() {
	self.args.BatchingTimeoutMs = -10
	err := self.args.validate()
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioPluginTestSuite) TestValidateHttpClientTimeoutDurationValid() {
	self.args.HttpTimeoutSec = 10
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateHttpClientTimeoutDurationZero() {
	self.args.HttpTimeoutSec = 0
	err := self.args.validate()
	require.NoError(self.T(), err)
}

func (self *HumioPluginTestSuite) TestValidateHttpClientTimeoutDurationNegative() {
	self.args.HttpTimeoutSec = -10
	err := self.args.validate()
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
}

func (self *HumioPluginTestSuite) CheckApply() {
	// URL and Token are assumed to be correct

	if self.args.Threads == 0 {
		require.Equal(self.T(), defaultNWorkers, self.queue.nWorkers)
	} else {
		require.Equal(self.T(), self.args.Threads, self.queue.nWorkers)
	}
	if self.args.BatchingTimeoutMs == 0 {
		require.Equal(self.T(), defaultBatchingTimeoutDuration, self.queue.batchingTimeoutDuration)
	} else {
		require.Equal(self.T(), time.Duration(self.args.BatchingTimeoutMs) * time.Millisecond, self.queue.batchingTimeoutDuration)
	}
	if self.args.HttpTimeoutSec == 0 {
		require.Equal(self.T(), defaultHttpClientTimeoutDuration, self.queue.httpClientTimeoutDuration)
	} else {
		require.Equal(self.T(), time.Duration(self.args.HttpTimeoutSec) * time.Second, self.queue.httpClientTimeoutDuration)
	}
	if self.args.EventBatchSize == 0 {
		require.Equal(self.T(), defaultEventBatchSize, self.queue.eventBatchSize)
	} else {
		require.Equal(self.T(), self.args.EventBatchSize, self.queue.eventBatchSize)
	}
	require.Equal(self.T(), self.args.Debug , self.queue.debug)
}

func (self *HumioPluginTestSuite) TestApplyValid() {
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyValidThreads() {
	self.args.Threads = validWorkerCount
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyEventBatchSizeValid() {
	self.args.EventBatchSize = 10
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyEventBatchSizeZero() {
	self.args.EventBatchSize = 0
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyBatchingTimeoutDurationValid() {
	self.args.BatchingTimeoutMs = 10
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyBatchingTimeoutDurationZero() {
	self.args.BatchingTimeoutMs = 0
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyHttpClientTimeoutDurationValid() {
	self.args.HttpTimeoutSec = 10
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyHttpClientTimeoutDurationZero() {
	self.args.HttpTimeoutSec = 0
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyTagMapValid() {
	self.args.TagFields = []string{"x=y", "y=z", }
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.NotNil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyTagMapEmptyTagName() {
	self.args.TagFields = []string{"x=y", "=z", }
	err := applyArgs(&self.args, self.queue)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyTagMapMultipleEquals() {
	self.args.TagFields = []string{"x=y", "y=z=z", }
	err := applyArgs(&self.args, self.queue)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyTagMapEmptyTagArg() {
	self.args.TagFields = []string{}
	err := applyArgs(&self.args, self.queue)
	require.NoError(self.T(), err)
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func (self *HumioPluginTestSuite) TestApplyTagMapEmptyTagArgString() {
	self.args.TagFields = []string{"",}
	err := applyArgs(&self.args, self.queue)
	require.NotNil(self.T(), err)
	require.ErrorAs(self.T(), err, &errInvalidArgument{})
	self.CheckApply()
	require.Nil(self.T(), self.queue.tagMap)
}

func TestHumioPlugin(t *testing.T) {
	gMaxPoll = 1
	gMaxPollDev = 1
        suite.Run(t, new(HumioPluginTestSuite))
}
