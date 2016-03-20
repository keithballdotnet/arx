// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package arx

import "sort"

// GetLatest will return the latest available key
func (key *Key) GetLatest() []byte {
	sort.Sort(KeyByVersion(key.Versions))

	return key.Versions[len(key.Versions)-1].Key
}

// GetLatestVersion will return the latest version number
func (key *Key) GetLatestVersion() int64 {
	sort.Sort(KeyByVersion(key.Versions))

	return key.Versions[len(key.Versions)-1].Version
}

// GetVersion will return a specific versioned key
func (key *Key) GetVersion(version int) []byte {
	return key.Versions[version-1].Key
}

// KeyByVersion - Will sort the Keys by Version (highest version at top i.e. Version 5 will be 4 in index, v3 index 2)
type KeyByVersion []*KeyVersion

func (a KeyByVersion) Len() int      { return len(a) }
func (a KeyByVersion) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a KeyByVersion) Less(i, j int) bool {
	return a[i].Version < a[j].Version
}
