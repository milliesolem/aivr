package model

// SyncPicklock — proof of concept for the syncthing introducer scope escape
// fixed by upstream commit 466857ae ("introducers should not be able to add
// themselves to folders").
//
// An introducer is a device trusted to vouch for other devices, but only for
// folders that are shared with the introducer. Before 466857a,
// handleIntroductions() never verified that the folder named in the remote
// ClusterConfig was actually shared with the introducer. A malicious (or
// compromised) introducer could therefore announce any folder that exists on
// the victim, including one it has no access to, and get itself added to that
// folder's share list — after which the folder's contents are served to it.
//
// This test drives the real model.handleIntroductions() security decision with
// real config/protocol types. POC_MODE=vulnerable asserts the bypass;
// POC_MODE=fixed asserts the patched behaviour.

import (
	"os"
	"testing"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/protocol"
)

func syncPicklockDevice(t *testing.T, s string) protocol.DeviceID {
	t.Helper()
	id, err := protocol.DeviceIDFromString(s)
	if err != nil {
		t.Fatalf("parse device id %q: %v", s, err)
	}
	return id
}

func TestSyncPicklockIntroducerSelfAdd(t *testing.T) {
	myID := syncPicklockDevice(t, "ZNWFSWE-RWRV2BD-45BLMCV-LTDE2UR-4LJDW6J-R5BPWEB-TXD27XJ-IZF5RA4")
	introducer := syncPicklockDevice(t, "AIR6LPZ-7K4PTTV-UXQSMUU-CPQ5YWH-OEDFIIQ-JUG777G-2YQXXR5-YD6AWQR")
	victimPeer := syncPicklockDevice(t, "GYRZZQB-IRNPV4Z-T7TC52W-EQYJ3TT-FDQW6MW-DFLMU42-SSSU6EM-FBK2VAY")

	m := &model{id: myID}

	// The victim has two folders. "private" is shared with victimPeer but NOT
	// with the introducer; "common" is shared with the introducer.
	folders := map[string]config.FolderConfiguration{
		"private": {
			ID:      "private",
			Devices: []config.FolderDeviceConfiguration{{DeviceID: victimPeer}},
		},
		"common": {
			ID:      "common",
			Devices: []config.FolderDeviceConfiguration{{DeviceID: introducer}},
		},
	}
	devices := map[protocol.DeviceID]config.DeviceConfiguration{
		introducer: {DeviceID: introducer, Introducer: true},
		victimPeer: {DeviceID: victimPeer},
	}

	// The introducer announces both folders, listing itself as a member of the
	// private one. A genuine ClusterConfig for "common" would also introduce
	// victimPeer, which must keep working after the fix.
	cc := &protocol.ClusterConfig{
		Folders: []protocol.Folder{
			{
				ID:      "private",
				Label:   "private",
				Devices: []protocol.Device{{ID: myID}, {ID: introducer}},
			},
			{
				ID:      "common",
				Label:   "common",
				Devices: []protocol.Device{{ID: myID}, {ID: introducer}, {ID: victimPeer}},
			},
		},
	}

	gotFolders, _, _, changed := m.handleIntroductions(devices[introducer], cc, folders, devices)

	private := gotFolders["private"]
	common := gotFolders["common"]

	t.Logf("introducer             = %s", introducer.Short())
	t.Logf("private shared with introducer after handling = %v", private.SharedWith(introducer))
	t.Logf("common  shared with victim peer after handling = %v", common.SharedWith(victimPeer))
	t.Logf("config changed = %v", changed)

	// Legitimate introduction of victimPeer into the folder shared with the
	// introducer must work in both builds.
	if !common.SharedWith(victimPeer) {
		t.Fatalf("legitimate introduction was not applied to folder 'common'")
	}

	switch os.Getenv("POC_MODE") {
	case "vulnerable":
		if !private.SharedWith(introducer) {
			t.Fatalf("expected the introducer self-add bypass, but folder 'private' was not shared")
		}
		t.Logf("VULNERABLE: introducer added itself to folder 'private', which is not shared with it")
	case "fixed":
		if private.SharedWith(introducer) {
			t.Fatalf("fixed build still shares folder 'private' with the introducer")
		}
		t.Logf("FIXED: introducer was refused access to folder 'private' while legitimate introductions still work")
	default:
		t.Fatalf("set POC_MODE=vulnerable or POC_MODE=fixed")
	}
}
