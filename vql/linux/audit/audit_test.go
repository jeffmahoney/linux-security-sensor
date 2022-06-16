package audit

import (
	"errors"
	"github.com/elastic/go-libaudit/v2"
        "www.velocidex.com/golang/velociraptor/file_store/test_utils"
)


type MockCommandClient struct {
	status AuditStatus
	rules []*auditrule.WireFormat
}

func NewMockCommandClient() *MockCommandClient{
	return &MockCommandClient{
		status: AuditStatus{},
		rules: [][]byte{},
	}
}

func (self *MockCommandClient) AddRule(rule []byte) error {
	for _, currentRule := range self.rules {
		if currentRule == rule {
			return errors.New("rule exists")
		}
	}

	self.rules = append(self.rules, rule)
	return nil
}

func (self *MockCommandClient) DeleteRule(rule []byte) error {
	rules := [][]byte{}
	found := false
	for _, currentRule := range self.rules {
		if currentRule == rule {
			return libaudit.ErrNoSuchRule
		}
		rules = append(rules, currentRule)
	}

	self.rules = rules
	return nil
}

func (self *MockCommandClient) GetRules() ([][]byte, error) {
	return self.rules
}

func (self *MockCommandClient) GetStatus() (*AuditStatus, error) {
	return &self.status
}

func (self *MockCommandClient) SetEnabled(enabled bool, wm WaitMode) error {
	self.status.Enabled = enabled
	return nil
}

func (self *MockCommandClient) Close() error {
	self.rules = [][]byte{}
	return nil
}

type AuditTestSuite struct {
	test_utils.TestSuite

	client *MockCommandClient
	scope  vfilter.Scope
}

func (self *AuditTestSuite) SetupTest() {
        self.ConfigObj = self.LoadConfig()
        self.TestSuite.SetupTest()

}
