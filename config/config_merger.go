/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

var (
	ErrCircularInclude = fmt.Errorf("circular include is not allowed")
)

type Merger struct {
	entry             string
	entryDir          string
	entryToSectionMap map[string]map[string][]*config_parser.Item
	// visiting holds the files on the current DFS path; it detects real
	// cycles without rejecting a shared file included by two siblings
	// (a diamond), which entryToSectionMap alone used to misreport.
	visiting map[string]bool
	// path mirrors visiting in order so the cycle error names the real chain.
	path []string
	// merged marks files whose sections were already merged into a father;
	// a shared file contributes its items exactly once, so a diamond does
	// not duplicate them.
	merged map[string]bool
}

func NewMerger(entry string) *Merger {
	return &Merger{
		entry:             entry,
		entryDir:          filepath.Dir(entry),
		entryToSectionMap: map[string]map[string][]*config_parser.Item{},
		visiting:          map[string]bool{},
		merged:            map[string]bool{},
	}
}

func (m *Merger) Merge() (sections []*config_parser.Section, entries []string, err error) {
	err = m.dfsMerge(m.entry, "")
	if err != nil {
		return nil, nil, err
	}
	entries, err = common.MapKeys(m.entryToSectionMap)
	if err != nil {
		return nil, nil, err
	}
	return m.convertMapToSections(m.entryToSectionMap[m.entry]), entries, nil
}

func (m *Merger) readEntry(entry string) (err error) {
	// Already parsed on an earlier branch (e.g. a shared include): reuse it.
	if _, exist := m.entryToSectionMap[entry]; exist {
		return nil
	}
	// Check filename
	if !strings.HasSuffix(entry, ".dae") {
		return fmt.Errorf("invalid config filename %v: must has suffix .dae", entry)
	}
	// Check file path security.
	if err = common.EnsureFileInSubDir(entry, m.entryDir); err != nil {
		return fmt.Errorf("failed in checking path of config file %v: %w", entry, err)
	}
	f, err := os.Open(entry)
	if err != nil {
		return fmt.Errorf("failed to read config file %v: %w", entry, err)
	}
	defer func() { _ = f.Close() }()
	// Check file access.
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("cannot include a directory: %v", entry)
	}
	if fi.Mode()&0037 > 0 {
		return fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", fi.Mode()&0777, entry)
	}
	// Read and parse.
	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	entrySections, err := config_parser.Parse(string(b))
	if err != nil {
		return fmt.Errorf("failed to parse config file %v:\n%w", entry, err)
	}
	m.entryToSectionMap[entry] = m.convertSectionsToMap(entrySections)
	return nil
}

func unsqueezeEntries(patternEntries []string) (unsqueezed []string, err error) {
	unsqueezed = make([]string, 0, len(patternEntries))
	for _, pattern := range patternEntries {
		files, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			// We only support .dae
			if !strings.HasSuffix(file, ".dae") {
				continue
			}
			fi, err := os.Stat(file)
			if err != nil {
				return nil, err
			}
			if fi.IsDir() {
				continue
			}
			unsqueezed = append(unsqueezed, file)
		}
	}
	if len(unsqueezed) == 0 {
		unsqueezed = nil
	}
	return unsqueezed, nil
}

func (m *Merger) dfsMerge(entry string, fatherEntry string) (err error) {
	// A file already on the current DFS path is a real cycle. A file parsed
	// on a sibling branch is not: readEntry turns it into a cache hit.
	if m.visiting[entry] {
		return fmt.Errorf("%w: %s", ErrCircularInclude, strings.Join(append(m.path, entry), " -> "))
	}
	// Read entry (parse or reuse the cached sections).
	if err = m.readEntry(entry); err != nil {
		return err
	}
	m.visiting[entry] = true
	m.path = append(m.path, entry)
	defer func() {
		delete(m.visiting, entry)
		m.path = m.path[:len(m.path)-1]
	}()
	sectionMap := m.entryToSectionMap[entry]
	// Extract childEntries.
	includes := sectionMap["include"]
	var patterEntries = make([]string, 0, len(includes))
	for _, include := range includes {
		switch v := include.Value.(type) {
		case *config_parser.Param:
			nextEntry := v.String(true, false)
			if filepath.IsAbs(nextEntry) {
				patterEntries = append(patterEntries, nextEntry)
			} else {
				patterEntries = append(patterEntries, filepath.Join(m.entryDir, nextEntry))
			}
		default:
			return fmt.Errorf("unsupported include grammar in %v: %v", entry, include.String(false, false))
		}
	}
	// DFS and merge children recursively.
	childEntries, err := unsqueezeEntries(patterEntries)
	if err != nil {
		return err
	}
	for _, nextEntry := range childEntries {
		if err = m.dfsMerge(nextEntry, entry); err != nil {
			return err
		}
	}
	/// Merge into father. Do not need to retrieve sectionMap again because go map is a reference.
	if fatherEntry == "" {
		// We are already on the top.
		return nil
	}
	// A shared include contributes its items once, to the first father that
	// reached it; re-merging into every father would duplicate the items all
	// the way up to the entry.
	if m.merged[entry] {
		return nil
	}
	m.merged[entry] = true
	fatherSectionMap := m.entryToSectionMap[fatherEntry]
	for sec := range sectionMap {
		items := m.mergeItems(fatherSectionMap[sec], sectionMap[sec])
		fatherSectionMap[sec] = items
	}
	return nil
}

func (m *Merger) convertSectionsToMap(sections []*config_parser.Section) (sectionMap map[string][]*config_parser.Item) {
	sectionMap = make(map[string][]*config_parser.Item)
	for _, sec := range sections {
		items, ok := sectionMap[sec.Name]
		if ok {
			sectionMap[sec.Name] = m.mergeItems(items, sec.Items)
		} else {
			sectionMap[sec.Name] = sec.Items
		}
	}
	return sectionMap
}

func (m *Merger) convertMapToSections(sectionMap map[string][]*config_parser.Item) (sections []*config_parser.Section) {
	sections = make([]*config_parser.Section, 0, len(sectionMap))
	for name, items := range sectionMap {
		sections = append(sections, &config_parser.Section{
			Name:  name,
			Items: items,
		})
	}
	return sections
}

func (m *Merger) mergeItems(to, from []*config_parser.Item) (items []*config_parser.Item) {
	items = make([]*config_parser.Item, len(to)+len(from))
	copy(items, to)
	copy(items[len(to):], from)
	return items
}
