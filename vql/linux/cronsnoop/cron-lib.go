//go:build linux
// +build linux

package linux

/*
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Action int

type Logger interface {
	Info(format string, v ...interface{})
	Warn(format string, v ...interface{})
}

const (
	Deleted Action = iota
	Added
)

type CronEvent struct {
	Timestamp string
	File      string
	Cmd       string
	User      string
	Action    string
}

func (a Action) String() string {
	return [...]string{"Deleted", "Added"}[a]
}

type CronSnooper struct {
	user_cron_registry   map[string][]string
	system_cron_registry map[string]map[string][]string
	cron_system_paths    []string
	cron_spool_path      string
	watcher              *fsnotify.Watcher
	result_chan          chan<- CronEvent
	done                 chan int
	logger               Logger
}

func NewCronSnooperWithChan(spool_path string, system_paths []string, c chan<- CronEvent) (*CronSnooper, error) {
	var err error

	snooper := &CronSnooper{
		cron_system_paths:    system_paths,
		cron_spool_path:      spool_path,
		user_cron_registry:   make(map[string][]string),
		system_cron_registry: make(map[string]map[string][]string),
		result_chan:          c,
		done:                 make(chan int),
	}

	snooper.watcher, err = fsnotify.NewWatcher()

	if err != nil {
		return nil, err
	}

	return snooper, nil
}

func NewCronSnooper(spool_path string, system_paths []string) (*CronSnooper, error) {
	return NewCronSnooperWithChan(spool_path, system_paths, nil)
}

func (snooper *CronSnooper) SetLogger(logger Logger) {
	snooper.logger = logger
}

func (snooper *CronSnooper) Info(format string, v ...interface{}) {
	if snooper.logger != nil {
		snooper.Info("cronsnoop: "+format, v...)
		return
	}

	log.Printf(format, v...)
}

func (snooper *CronSnooper) Warn(format string, v ...interface{}) {
	if snooper.logger != nil {
		snooper.logger.Warn("cronsnoop: "+format, v...)
		return
	}

	log.Printf(format, v...)
}

func (snooper *CronSnooper) emit_event(cmd, user, file string, action Action) {
	if snooper.result_chan == nil {
		return
	}

	// non-blocking send, consumer of CronSnooper better use sufficiently large
	// buffered channel
	select {
	case snooper.result_chan <- CronEvent{
		Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05"),
		Cmd:       cmd,
		User:      user,
		Action:    action.String(),
		File:      file,
	}:

	default:
		snooper.Info("Dropped event cmd: %v user %v action %v", cmd, user, action)
	}
}

func (snooper *CronSnooper) add_cron_watches() error {
	for _, v := range snooper.cron_system_paths {
		err := snooper.watcher.Add(v)
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("Еrror adding a watch for: %v err: %v", v, err)
		}
	}

	err := snooper.watcher.Add(snooper.cron_spool_path)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("Еrror adding a watch for: %v err: %v",
			snooper.cron_spool_path, err)
	}

	return nil
}

// As per cron's man page user crontab files shall have identical names
// to the user they pertain, so check this via the passwd db apis
func (snooper *CronSnooper) is_user_cron_event(event fsnotify.Event) bool {
	if strings.HasPrefix(event.Name, snooper.cron_spool_path) &&
		event.Op&(fsnotify.Remove|fsnotify.Rename|fsnotify.Write|
			fsnotify.Create) > 0 {
		uname := filepath.Base(event.Name)
		_, err := user.Lookup(uname)
		if err == nil {
			return true
		}
	}

	return false
}

func (snooper *CronSnooper) is_system_cron_event(event fsnotify.Event) bool {
	for _, prefix := range snooper.cron_system_paths {
		if strings.HasPrefix(event.Name, prefix) {
			return true
		}
	}

	return false
}

func exists(haystack []string, needle string) bool {
	for _, cmd := range haystack {
		if cmd == needle {
			return true
		}
	}

	return false
}

// returns a slice, containing only those entries which are both in a and b,
// entries existing in a, but not in b are removed from a
func filter_deleted_cmds(a, b []string) ([]string, []string) {
	// filtered re-uses the storage of cmds
	existing := a[:0]
	deleted := []string{}
	for _, cmd := range a {
		if exists(b, cmd) {
			existing = append(existing, cmd)
		} else {
			deleted = append(deleted, cmd)
		}
	}

	// ensure everything which got filtered in a is garbage collected
	for i := len(existing); i < len(a); i++ {
		a[i] = ""
	}

	return existing, deleted
}

func special_cron_string(line_fields []string) bool {
	return line_fields[0][0] == '@'
}

func should_skip_line(line_fields []string) bool {
	// ignore comments and empty lines
	if line_fields[0][0] == '#' || len(line_fields) == 0 {
		return true
	}

	// if line starts with @ special string instead of ordinary cron time/date
	// fields don't skip it.
	if special_cron_string(line_fields) {
		return false
	} else if len(line_fields) <= 5 {
		return true
	}

	return false
}

func (snooper *CronSnooper) parse_user_cron_file(path string) error {
	var existing_user_cmds, current_commands []string
	var cmd string
	var ok bool

	user := filepath.Base(path)

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// initialize user entries on first user modification detectioon
	if existing_user_cmds, ok = snooper.user_cron_registry[user]; !ok {
		snooper.user_cron_registry[user] = existing_user_cmds
	}

	for scanner.Scan() {
		line := strings.TrimLeft(scanner.Text(), " \t")
		split_line := strings.Split(line, " ")

		if should_skip_line(split_line) {
			continue
		}

		// Handle @-based entries in cron file
		if special_cron_string(split_line) {
			cmd = strings.Join(split_line[1:], " ")
		} else {
			cmd = strings.Join(split_line[5:], " ")
		}

		current_commands = append(current_commands, cmd)
		// only take note of unique commands
		if !exists(existing_user_cmds, cmd) {
			existing_user_cmds = append(existing_user_cmds, cmd)
			snooper.emit_event(cmd, user, path, Added)
		}
	}

	// Filter out deleted entries
	existing, deleted := filter_deleted_cmds(existing_user_cmds, current_commands)

	// emit events
	for _, deleted_cmd := range deleted {
		snooper.emit_event(deleted_cmd, user, path, Deleted)
	}

	// user got all of its entries deleted so just delete the user altogether
	if len(existing) == 0 {
		// TODO: Emit an event that all of user's entries are deleted
		delete(snooper.user_cron_registry, user)
	} else {
		// We have some entries left for the user and filtered contains the final
		// "view" of the user's cron entries
		snooper.user_cron_registry[user] = existing
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (snooper *CronSnooper) parse_system_cron_file(path string) error {
	var cmd, user string
	var cron_registry map[string][]string
	var ok bool

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	parsed_commands := make(map[string][]string)

	// initialize hashmap for the given file
	if cron_registry, ok = snooper.system_cron_registry[path]; !ok {
		cron_registry = make(map[string][]string)
		snooper.system_cron_registry[path] = cron_registry
	}

	for scanner.Scan() {
		line := strings.TrimLeft(scanner.Text(), " \t")
		split_line := strings.Split(line, " ")

		if should_skip_line(split_line) {
			continue
		}

		if special_cron_string(split_line) {
			user = string(split_line[1])
			cmd = strings.Join(split_line[2:], " ")
		} else {
			user = string(split_line[5])
			cmd = strings.Join(split_line[6:], " ")
		}

		existing_user_cmds := cron_registry[user]
		// parsed commands contain all commands added for the given user
		// in the given file, we can have many entries for different users
		parsed_commands[user] = append(parsed_commands[user], cmd)

		if !exists(existing_user_cmds, cmd) {
			existing_user_cmds = append(existing_user_cmds, cmd)
			cron_registry[user] = existing_user_cmds
			snooper.emit_event(cmd, user, path, Added)
		}
	}

	for k, v := range parsed_commands {
		var deleted []string
		// Filter out deleted entries, reusing the allocated array size
		cron_registry[k], deleted = filter_deleted_cmds(cron_registry[k], v)
		for _, deleted_cmd := range deleted {
			snooper.emit_event(deleted_cmd, k, path, Deleted)
		}
	}

	// Delete all existing user entries if there are no parsed commands for the
	// user in the current run
	for user := range cron_registry {
		if _, user_exists := parsed_commands[user]; !user_exists {
			for _, cmd := range cron_registry[user] {
				snooper.emit_event(cmd, user, path, Deleted)
			}
			delete(cron_registry, user)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (snooper *CronSnooper) Close() {
	close(snooper.done)
}

func (snooper *CronSnooper) WatchCrons() error {
	err := snooper.add_cron_watches()
	if err != nil {
		return err
	}

	go func() {
		defer snooper.watcher.Close()
		for {
			select {
			case event, ok := <-snooper.watcher.Events:
				if !ok {
					return
				}

				if snooper.is_user_cron_event(event) {
					user := filepath.Base(event.Name)

					// if a user file is deleted consider that all events for this user
					// are deleted as well
					if event.Op&fsnotify.Remove == fsnotify.Remove {
						for _, cmd := range snooper.user_cron_registry[user] {
							snooper.emit_event(cmd, user, event.Name, Deleted)
						}
						delete(snooper.user_cron_registry, user)
					} else {
						snooper.parse_user_cron_file(event.Name)
					}
				} else if snooper.is_system_cron_event(event) {
					if event.Op&fsnotify.Remove == fsnotify.Remove {
						// create delete events for every entry we have for this
						// file
						for user, cmds := range snooper.system_cron_registry[event.Name] {
							for _, cmd := range cmds {
								snooper.emit_event(cmd, user, event.Name, Deleted)
							}
						}
						delete(snooper.system_cron_registry, event.Name)
					} else {
						snooper.parse_system_cron_file(event.Name)
					}
				}
			case err, ok := <-snooper.watcher.Errors:
				if !ok {
					return
				}

				snooper.Warn("Error from inotify: %v", err)
			case _ = <-snooper.done:
				return
			}
		}
	}()

	return nil
}
