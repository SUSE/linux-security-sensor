//go:build linux
// +build linux

package linux

import (
	"os"
	"strings"
	"testing"
)

const (
	fName       = "test.cron"
	tmpfilepath = "test-spool-dir/alksfjgi9"
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

func createFile(content []string) {
	if f, err := os.Create(fName); err == nil {
		for _, v := range content {
			f.WriteString(v + "\n")
		}

		f.Close()
	}
}

func createFile2(filename string, content []string) {
	if f, err := os.Create(filename); err == nil {
		for _, v := range content {
			f.WriteString(v + "\n")
		}

		f.Close()
	}
}

func createDir(dir string) {
	os.RemoveAll(dir)
	os.Mkdir(dir, 0755)
}

// Basic test to ensure addition works
func TestCronAdd(t *testing.T) {

	var cmd []string
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	data := []string{"*/5 * * * * echo \"command1\"",
		"*/5 * * * * echo \"command2\""}

	createFile(data)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(fName, s, t)
	assertUserCmdCount(fName, 2, s, t)
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

	assertCronEvent(<-c, cmd[0], fName, fName, Added, t)
	assertCronEvent(<-c, cmd[1], fName, fName, Added, t)

}

// Ensure deleting a single command for a user works
func TestCronDeleteSingleJob(t *testing.T) {

	data := []string{"*/5 * * * * echo \"command1\"",
		"*/5 * * * * echo \"command2\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	createFile(data)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	data2 := []string{"*/5 * * * * echo \"command1\""}
	createFile(data2)

	err = s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(fName, s, t)
	assertUserCmdCount(fName, 1, s, t)

	cmds := s.user_cron_registry[fName]
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

	assertCronEvent(<-c, "echo \"command2\"", fName, fName, Deleted, t)
}

// Deleting the last command for an entry in the cron registry
// shall delete the entry itself. Also test that all events are fine.
func TestCronDeleteAllCommands(t *testing.T) {
	data := []string{"*/5 * * * * echo \"command1\"",
		"*/5 * * * * echo \"command2\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("./", nil, c)

	defer s.Close()
	s.WatchCrons()

	createFile2("./root", data)

	//Ignore add events
	<-c
	<-c

	os.Remove("root")

	assertCronEvent(<-c, "echo \"command1\"", "root", "./root", Deleted, t)
	assertCronEvent(<-c, "echo \"command2\"", "root", "./root", Deleted, t)
}

// Test that comment lines are ignored
func TestIgnoreCommentLines(t *testing.T) {
	data := []string{"*/5 * * * * echo \"command1\"",
		"#this shall be ignored"}

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)
	createFile(data)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(fName, s, t)
	assertUserCmdCount(fName, 1, s, t)

	cmds := s.user_cron_registry[fName]
	cmd := strings.Join(strings.Split(data[0], " ")[5:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0], "cmd: ", cmd)
	}

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", fName, fName, Added, t)
}

// Test that comment lines are ignored
func TestIgnoreTabSpace(t *testing.T) {
	os.Remove(fName)
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	data := []string{" */5 * * * * echo \"command1\""}

	createFile(data)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(fName, s, t)
	assertUserCmdCount(fName, 1, s, t)

	cmds := s.user_cron_registry[fName]
	cmd := strings.Join(strings.Split(data[0], " ")[6:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0], "cmd: ", cmd)
	}

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", fName, fName, Added, t)
}

// Verify support for lines which have their time fields replaced by a special
// keyword
func TestSpecialStringHandling(t *testing.T) {
	os.Remove(fName)

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	data := []string{"@yearly echo \"command1\""}

	createFile(data)

	err := s.parse_user_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertUserExists(fName, s, t)
	assertUserCmdCount(fName, 1, s, t)

	cmds := s.user_cron_registry[fName]
	cmd := strings.Join(strings.Split(data[0], " ")[1:], " ")

	if cmd != cmds[0] {
		t.Fatal("Remaining command unexpected: ", cmds[0], "cmd: ", cmd)
	}

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", fName, fName, Added, t)
}

// ========================================================================

func TestMultiUserCronAdd(t *testing.T) {

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"*/5 * * * * user2 echo \"command2\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	createFile(data)

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

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"#*/5 * * * * user3 echo \"command2\""}
	s, _ := NewCronSnooper("", nil)

	createFile(data)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserDoesntExist("user3", fName, s, t)
}

func TestMultiUserSpecialStringHandling(t *testing.T) {
	os.Remove(fName)

	data := []string{"@yearly user3 echo \"command1\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	createFile(data)

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

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"*/5 * * * * user2 echo \"command2\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	createFile(data)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	// discard added users event
	<-c
	<-c

	data = []string{"*/5 * * * * user1 echo \"command1\""}
	createFile(data)

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

	data := []string{"*/5 * * * * user1 echo \"command1\"",
		"*/5 * * * * user2 echo \"command2\"",
		"*/5 * * * * user2 echo \"command3\""}
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)

	createFile(data)

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
	createFile(data)

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

	const other_file = "other-file"
	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", nil, c)
	data := []string{"*/5 * * * * user1 echo \"command1\""}
	data2 := []string{"*/5 * * * * user2 echo \"command1\""}

	// create entries for the same user in 2 different files
	createFile2(fName, data)
	createFile2(other_file, data)

	err := s.parse_system_cron_file(fName)
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	err = s.parse_system_cron_file("other-file")
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	//ensure they exist
	assertMUserExists("user1", fName, s, t)
	assertMUserExists("user1", "other-file", s, t)

	// now delete one of the entries in the files
	createFile2(other_file, data2)
	err = s.parse_system_cron_file("other-file")
	if err != nil {
		t.Fatal("Error when parsing file", err)
	}

	assertMUserExists("user1", fName, s, t)
	assertMUserDoesntExist("user1", "other-file", s, t)

	// skip events for user creation
	<-c
	<-c
	<-c

	if len(c) != 1 {
		t.Fatal("Unexpected number of events generated", len(c))
	}

	assertCronEvent(<-c, "echo \"command1\"", "user1", "other-file", Deleted, t)
}

func TestSpoolUserCreation(t *testing.T) {

	createDir("./test-spool-dir")

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("test-spool-dir/", nil, c)
	data := []string{"*/5 * * * * echo \"command1\""}

	defer s.Close()
	s.WatchCrons()

	createFile2("./test-spool-dir/root", data)
	assertCronEvent(<-c, "echo \"command1\"", "root", "test-spool-dir/root", Added, t)
}

func TestIgnoreNonSystemSpoolFile(t *testing.T) {
	createDir("./test-spool-dir")

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("test-spool-dir/", nil, c)
	data := []string{"*/5 * * * * user1 echo \"command1\""}

	defer s.Close()
	s.WatchCrons()

	createFile2(tmpfilepath, data)

	if len(c) != 0 {
		t.Fatal("Non-user spool file not ignored")
	}
}

func TestSystemCronFile(t *testing.T) {

	createDir("./test-spool-dir")

	c := make(chan CronEvent, 10)
	s, _ := NewCronSnooperWithChan("", []string{"test-spool-dir/"}, c)

	data := []string{"*/5 * * * * user1 echo \"command1\""}

	defer s.Close()
	s.WatchCrons()

	createFile2(tmpfilepath, data)

	assertCronEvent(<-c, "echo \"command1\"", "user1", tmpfilepath, Added, t)

	os.Remove(tmpfilepath)

	assertCronEvent(<-c, "echo \"command1\"", "user1", tmpfilepath, Deleted, t)
}

func TestMain(m *testing.M) {
	m.Run()
	os.Remove(fName)
}
