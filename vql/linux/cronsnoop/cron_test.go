//go:build linux
// +build linux

package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testFileName = "test.cron"
	nonUserString = "alksfjgi9"
)

func assertUserExists(user string, s *CronSnooper, t *testing.T) {
	if _, ok := s.user_cron_registry[user]; !ok {
		t.Fatal("No cron entry for user", user)
	}
}

func assertUserDoesntExist(user string, s *CronSnooper, t *testing.T) {
	if _, ok := s.user_cron_registry[user]; ok {
		t.Fatal("Cron entries present for user", user)
	}
}

func assertUserCmdCount(user string, expected int, s *CronSnooper, t *testing.T) {
	user_cmd_count := len(s.user_cron_registry[user])
	if user_cmd_count != expected {
		t.Fatal("Unexpected number of commands for user:", user, "has:",
			user_cmd_count, " expected:", expected)
	}
}

func assertMUserExists(user string, filepath string, s *CronSnooper, t *testing.T) {
	if _, ok := s.system_cron_registry[filepath][user]; !ok {
		t.Fatal("No cron entry for user", user)
	}
}

func assertMUserDoesntExist(user string, filepath string, s *CronSnooper, t *testing.T) {
	if _, ok := s.system_cron_registry[filepath][user]; ok {
		t.Fatal("Cron entries present for user", user)
	}
}

func assertMUserCmdCount(user string, filepath string, expected int, s *CronSnooper, t *testing.T) {
	user_cmd_count := len(s.system_cron_registry[filepath][user])
	if user_cmd_count != expected {
		t.Fatal("Unexpected number of commands for user:", user, "has:",
			user_cmd_count, " expected:", expected)
	}
}

func assertCronEvent(e CronEvent, cmd, user, path string, a Action, t *testing.T) {
	if e.Cmd != cmd {
		t.Fatal("[CronEvent] Unexpected command:", e.Cmd, "expecting:", cmd)
	}

	if e.User != user {
		t.Fatal("[CronEvent] Unexpected user:", e.User, "expecting:", user)
	}

	if e.Action != a.String() {
		t.Fatal("[CronEvent] Unexpected action:", e.Action, "expecting:", a)
	}

	if e.File != path {
		t.Fatal("[CronEvent] Unexpected file path:", e.File, "expecting:", path)
	}
}

func writeFileContents(fName string, content []string, t *testing.T) {
	f, err := os.Create(fName)
	if err != nil {
		t.Fatal("Failed to create ", fName, ": ", err)
	}

	for _, v := range content {
		f.WriteString(v + "\n")
	}

	f.Close()
}

func createNamedFile(tempdir string, filename string, content []string, t *testing.T) string {
	fName := filepath.Join(tempdir, filename)

	writeFileContents(fName, content, t)

	return fName
}

// Basic test to ensure addition works
func TestCronAdd(t *testing.T) {
	tempdir := t.TempDir()

	var cmd []string
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	data := []string{"*/5 * * * * echo \"command1\"",
		"*/5 * * * * echo \"command2\""}

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(testFileName, s, t)
	assertUserCmdCount(testFileName, 2, s, t)
	cmds := s.user_cron_registry[fName]

	for _, v := range data {
		cmd = append(cmd, strings.Join(strings.Split(v, " ")[5:], " "))
	}

	for i, v := range cmds {
		if cmd[i] != v {
			t.Fatalf("[%d] wrong cmd. Has %s expected %s\n", i, v, cmd[i])
		}
	}

	if len(c) != 2 {
		t.Fatal("Unexpected number of events:", len(c), "expected: 2")
	}

	assertCronEvent(<-c, cmd[0], testFileName, fName, Added, t)
	assertCronEvent(<-c, cmd[1], testFileName, fName, Added, t)

}

// Ensure deleting a single command for a user works
func TestCronDeleteSingleJob(t *testing.T) {
	tempdir := t.TempDir()

	data := []string{"*/5 * * * * echo \"command1\"",
		"*/5 * * * * echo \"command2\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	data2 := []string{"*/5 * * * * echo \"command1\""}
	writeFileContents(fName, data2, t)

	err = s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(testFileName, s, t)
	assertUserCmdCount(testFileName, 1, s, t)

	cmds := s.user_cron_registry[testFileName]
	cmd := strings.Join(strings.Split(data[0], " ")[5:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0])
	}

	if len(c) != 3 {
		t.Fatal("Unexpected number of events:", len(c), "expected: 3")
	}

	// ommit the 2 add events
	<-c
	<-c

	assertCronEvent(<-c, "echo \"command2\"", testFileName, fName, Deleted, t)
}

// Deleting the last command for an entry in the cron registry
// shall delete the entry itself. Also test that all events are fine.
func TestCronDeleteAllCommands(t *testing.T) {
	tempdir := t.TempDir()
	data := []string{"*/5 * * * * echo \"command1\"",
		"*/5 * * * * echo \"command2\""}
	c := make(chan CronEvent, 10)

	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	defer s.Close()
	s.WatchCrons()

	fName := createNamedFile(tempdir, "root", data, t)

	//Ignore add events
	t.Log("Waiting for event 1")
	<-c
	t.Log("Waiting for event 2")
	<-c

	t.Log("Removing file")
	os.Remove(fName)

	t.Log("Waiting for event 3")
	assertCronEvent(<-c, "echo \"command1\"", "root", fName, Deleted, t)
	t.Log("Waiting for event 4")
	assertCronEvent(<-c, "echo \"command2\"", "root", fName, Deleted, t)
}

// Test that comment lines are ignored
func TestIgnoreCommentLines(t *testing.T) {
	tempdir := t.TempDir()
	data := []string{"*/5 * * * * echo \"command1\"",
		"#this shall be ignored"}

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)
	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(testFileName, s, t)
	assertUserCmdCount(testFileName, 1, s, t)

	cmds := s.user_cron_registry[testFileName]
	cmd := strings.Join(strings.Split(data[0], " ")[5:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0], "cmd: ", cmd)
	}

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", testFileName, fName, Added, t)
}

// Test that comment lines are ignored
func TestIgnoreTabSpace(t *testing.T) {
	tempdir := t.TempDir()
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	data := []string{" */5 * * * * echo \"command1\""}

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(testFileName, s, t)
	assertUserCmdCount(testFileName, 1, s, t)

	cmds := s.user_cron_registry[testFileName]
	cmd := strings.Join(strings.Split(data[0], " ")[6:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0], "cmd: ", cmd)
	}

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", testFileName, fName, Added, t)
}

// Verify support for lines which have their time fields replaced by a special
// keyword
func TestSpecialStringHandling(t *testing.T) {
	tempdir := t.TempDir()
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	data := []string{"@yearly echo \"command1\""}

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(testFileName, s, t)
	assertUserCmdCount(testFileName, 1, s, t)

	cmds := s.user_cron_registry[testFileName]
	cmd := strings.Join(strings.Split(data[0], " ")[1:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0], "cmd: ", cmd)
	}

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", testFileName, fName, Added, t)
}

// ========================================================================

func TestMultiUserCronAdd(t *testing.T) {
	tempdir := t.TempDir()

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"*/5 * * * * user2 echo \"command2\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserExists("user1", fName, s, t)
	assertMUserExists("user2", fName, s, t)
	assertMUserCmdCount("user1", fName, 1, s, t)
	assertMUserCmdCount("user2", fName, 1, s, t)

	user1_cmd := s.system_cron_registry[fName]["user1"]
	user2_cmd := s.system_cron_registry[fName]["user2"]

	user1_raw_cmd := strings.Join(strings.Split(data[0], " ")[6:], " ")
	if user1_raw_cmd != user1_cmd[0] {
		t.Fatal("User 1 cmd:", user1_cmd, "has different value, expected:", user1_raw_cmd)
	}

	user2_raw_cmd := strings.Join(strings.Split(data[1], " ")[6:], " ")
	if user2_raw_cmd != user2_cmd[0] {
		t.Fatal("User 2 cmd:", user2_cmd, "has different value, expected:", user2_raw_cmd)
	}

	if len(c) != 2 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", "user1", fName, Added, t)
	assertCronEvent(<-c, "echo \"command2\"", "user2", fName, Added, t)
}

func TestMultiUserCommentIgnore(t *testing.T) {
	tempdir := t.TempDir()

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"#*/5 * * * * user3 echo \"command2\""}
	s, _ := NewCronSnooper("", nil)

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserDoesntExist("user3", fName, s, t)
}

func TestMultiUserSpecialStringHandling(t *testing.T) {
	tempdir := t.TempDir()

	data := []string{"@yearly user3 echo \"command1\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserExists("user3", fName, s, t)
	assertMUserCmdCount("user3", fName, 1, s, t)

	cmds := s.system_cron_registry[fName]["user3"]
	cmd := strings.Join(strings.Split(data[0], " ")[2:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0], "cmd: ", cmd)
	}

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", "user3", fName, Added, t)
}

func TestMultiUserCronDelete(t *testing.T) {
	tempdir := t.TempDir()

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"*/5 * * * * user2 echo \"command2\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	// discard added users event
	<-c
	<-c

	data = []string{"*/5 * * * * user1 echo \"command1\""}
	writeFileContents(fName, data, t)

	err = s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserExists("user1", fName, s, t)
	assertMUserDoesntExist("user2", fName, s, t)

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command2\"", "user2", fName, Deleted, t)
}

func TestMultiUserPartialCronDelete(t *testing.T) {
	tempdir := t.TempDir()

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"*/5 * * * * user2 echo \"command2\"",
		"*/5 * * * * user2 echo \"command3\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)

	fName := createNamedFile(tempdir, testFileName, data, t)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	// discard added users event
	<-c
	<-c
	<-c

	// we need to delete 1 command of a user and leave 1 command for the user
	data = []string{"*/5 * * * * user1 echo \"command1\"",
		"*/5 * * * * user2 echo \"command3\""}
	writeFileContents(fName, data, t)

	err = s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserExists("user1", fName, s, t)
	assertMUserExists("user2", fName, s, t)

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command2\"", "user2", fName, Deleted, t)
}

func TestMultiUserCronDeleteAcrossFiles(t *testing.T) {
	tempdir := t.TempDir()

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(tempdir, nil, c)
	data := []string{"*/5 * * * * user1 echo \"command1\""}
	data2 := []string{"*/5 * * * * user2 echo \"command1\""}


	// create entries for the same user in 2 different files
	fName := createNamedFile(tempdir, testFileName, data, t)
	other_file := createNamedFile(tempdir, "other-file", data, t)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	err = s.parse_system_cron_file(other_file)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	//ensure they exist
	assertMUserExists("user1", fName, s, t)
	assertMUserExists("user1", other_file, s, t)

	// now delete one of the entries in the files
	writeFileContents(other_file, data2, t)
	err = s.parse_system_cron_file(other_file)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserExists("user1", fName, s, t)
	assertMUserDoesntExist("user1", other_file, s, t)

	// skip events for user creation
	<-c
	<-c
	<-c

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", "user1", other_file, Deleted, t)
}

func createSpoolDir(t *testing.T) string {
	tempdir := t.TempDir()

	spoolDir := filepath.Join(tempdir, "test-spool-dir")

	err := os.Mkdir(spoolDir, 0755)
	if err != nil {
		t.Fatalf("Could not create dir %s: %v", spoolDir, err)
	}

	return spoolDir
}

func TestSpoolUserCreation(t *testing.T) {
	spoolDir := createSpoolDir(t)

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(spoolDir, nil, c)
	data := []string{"*/5 * * * * echo \"command1\""}

	defer s.Close()
	s.WatchCrons()

	userFile := createNamedFile(spoolDir, "root", data, t)
	assertCronEvent(<-c, "echo \"command1\"", "root", userFile, Added, t)
}

func TestIgnoreNonSystemSpoolFile(t *testing.T) {
	spoolDir := createSpoolDir(t)

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan(spoolDir, nil, c)
	data := []string{"*/5 * * * * user1 echo \"command1\""}

	defer s.Close()
	s.WatchCrons()

	_ = createNamedFile(spoolDir, nonUserString, data, t)

	if len(c) != 0 {
		t.Fatal("Non-user spool file not ignored")
	}
}

func TestSystemCronFile(t *testing.T) {
	spoolDir := createSpoolDir(t)

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", []string{spoolDir}, c)

	data := []string{"*/5 * * * * user1 echo \"command1\""}

	defer s.Close()
	s.WatchCrons()

	nonUserFile := createNamedFile(spoolDir, nonUserString, data, t)

	assertCronEvent(<-c, "echo \"command1\"", "user1", nonUserFile, Added, t)

	os.Remove(nonUserFile)

	assertCronEvent(<-c, "echo \"command1\"", "user1", nonUserFile, Deleted, t)
}

func TestMain(m *testing.M) {
	m.Run()
}
