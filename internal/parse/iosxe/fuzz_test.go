package iosxe

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzParsers pasa un mismo texto por todos los parsers públicos de show: ninguno entra en pánico ni
// tarda más de un tope (sería una expresión regular o un bucle cuadrático).
func FuzzParsers(f *testing.F) {
	fx, _ := filepath.Glob("testdata/*.txt")
	for _, p := range fx {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(string(b))
		}
	}
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		ip := netip.MustParseAddr("10.0.0.1")
		start := time.Now()
		if c, ok := ParseInterfaceConfig(s); ok {
			ParseL2Port(c)
			ParseHelpers(c)
		}
		ParseSwitchportMode(s)
		ParseSwitchportOperMode(s)
		ParseVlanID(s, 10)
		NormMAC(s)
		ShortIf(s)
		ParseARP(s)
		ParseMACTable(s)
		ParseDHCPSnooping(s)
		ParseIfStatus(s)
		rs, _ := ParseRoute(s)
		LongestMatch(rs, ip)
		RouteUnread(s)
		ParseCEF(s)
		ParseNTP(s)
		ParseInventory(s)
		ParseVersion(s)
		ParseDir(s)
		ParseCPU(s)
		ParseMem(s)
		ParseProcessMemory(s)
		ParseInterfaces(s)
		ParseIPBrief(s)
		ParseCDP(s)
		ParseLLDP(s)
		ParseSTPRoots(s)
		ParsePortChannels(s)
		IOSDuration(s)
		ParseSTPDetail(s)
		ParseSTPRootTable(s)
		ParseBGP(s)
		ParseOSPF(s)
		ParseHSRP(s)
		ParseRouteSummary(s)
		ParseEgress(s)
		RoutingOff(s)
		ParseVlanBrief(s)
		ParseVlanDetail(s, 10)
		ParseTrunkActive(s)
		ParseVTP(s)
		ParseUsernames(s)
		TrunkAllowedSet([]string{s})
		ParseMemPools(s)
		ParseTrunks(s)
		ParseEtherChannels(s)
		ParsePortPos(s)
		ParseErrdisableRecovery(s)
		ParseBoot(s)
		ParseInstallSummary(s)
		ParseRedundancy(s)
		ParseVerifyMD5(s)
		ParseConfigHeader(s)
		ParseStaticRoutes(s)
		ParseNTPServers(s)
		ParseLoggingCfg(s)
		ParseSNMPCommunities(s)
		ParseSNMPGroups(s)
		ParseSNMPUsers(s)
		ParseBannerMOTD(s)
		ParseVtyBlocks(s)
		ParseAccessLists(s)
		ParseClock(s)
		LogUptimeStamp(s)
		ParseLogLine(s)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("los parsers tardaron %v con %d bytes", d, len(s))
		}
	})
}
