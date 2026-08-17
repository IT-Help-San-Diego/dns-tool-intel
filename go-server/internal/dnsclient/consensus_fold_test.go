package dnsclient

import (
        "reflect"
        "testing"
)

// voteFixture describes one resolver's answer for the consensus-fold tests.
type voteFixture struct {
        records []string
        outcome resolverOutcome
}

func vRes(records ...string) voteFixture {
        return voteFixture{records: records, outcome: outcomeResolved}
}
func vAbsent() voteFixture    { return voteFixture{outcome: outcomeAbsent} }
func vTransient() voteFixture { return voteFixture{outcome: outcomeTransient} }

func foldFixture(votes []voteFixture) (int, consensusOutcome) {
        keys := make([]string, len(votes))
        outcomes := make([]resolverOutcome, len(votes))
        for i, v := range votes {
                outcomes[i] = v.outcome
                if v.outcome == outcomeResolved {
                        keys[i] = canonicalRecordKey(v.records)
                }
        }
        return foldResolverConsensus(keys, outcomes)
}

// TestFoldConsensus_StaleOutlierOutvoted is the production regression: the live
// record is held by the majority of resolvers (Google + Cloudflare + ...), while a
// single stale recursive cache (Quad9) still serves the pre-change record. The old
// "first resolver to answer wins" logic could return the stale value; consensus must
// return the majority live record.
func TestFoldConsensus_StaleOutlierOutvoted(t *testing.T) {
        live := []string{"v=DMARC1; p=reject; sp=reject; rua=mailto:ryan@example.com"}
        stale := []string{"v=DMARC1; p=quarantine; rua=mailto:dmarc_rua@onsecureserver.net"}
        votes := []voteFixture{
                vRes(live...),  // Cloudflare
                vRes(live...),  // Google
                vRes(stale...), // Quad9 (stale cache)
                vRes(live...),  // OpenDNS
                vRes(stale...), // DNS4EU (also lagging) -> 3 live vs 2 stale
        }
        idx, outcome := foldFixture(votes)
        if outcome != consensusResolved {
                t.Fatalf("outcome = %v, want consensusResolved", outcome)
        }
        if !reflect.DeepEqual(votes[idx].records, live) {
                t.Fatalf("winner = %v, want the live majority record %v", votes[idx].records, live)
        }
}

func TestFoldConsensus_SimpleMajority(t *testing.T) {
        votes := []voteFixture{vRes("A"), vRes("A"), vRes("B")}
        idx, outcome := foldFixture(votes)
        if outcome != consensusResolved {
                t.Fatalf("outcome = %v, want consensusResolved", outcome)
        }
        if votes[idx].records[0] != "A" {
                t.Fatalf("winner = %q, want A", votes[idx].records[0])
        }
}

func TestFoldConsensus_Unanimous(t *testing.T) {
        _, outcome := foldFixture([]voteFixture{vRes("A"), vRes("A"), vRes("A")})
        if outcome != consensusResolved {
                t.Fatalf("outcome = %v, want consensusResolved", outcome)
        }
}

func TestFoldConsensus_SingleResolverResolved(t *testing.T) {
        // Only one resolver answered (rest timed out): a lone present answer still resolves.
        idx, outcome := foldFixture([]voteFixture{vRes("A"), vTransient(), vTransient()})
        if outcome != consensusResolved || idx != 0 {
                t.Fatalf("idx=%d outcome=%v, want idx=0 consensusResolved", idx, outcome)
        }
}

func TestFoldConsensus_TwoTwoTieIsConflict(t *testing.T) {
        _, outcome := foldFixture([]voteFixture{vRes("A"), vRes("A"), vRes("B"), vRes("B")})
        if outcome != consensusConflict {
                t.Fatalf("outcome = %v, want consensusConflict", outcome)
        }
}

func TestFoldConsensus_AllDifferentIsConflict(t *testing.T) {
        _, outcome := foldFixture([]voteFixture{vRes("A"), vRes("B"), vRes("C")})
        if outcome != consensusConflict {
                t.Fatalf("outcome = %v, want consensusConflict", outcome)
        }
}

func TestFoldConsensus_PluralityNotTieWins(t *testing.T) {
        // 3 vs 2 vs 1: the strict plurality (A) wins even though no absolute majority.
        votes := []voteFixture{vRes("A"), vRes("A"), vRes("A"), vRes("B"), vRes("B"), vRes("C")}
        idx, outcome := foldFixture(votes)
        if outcome != consensusResolved || votes[idx].records[0] != "A" {
                t.Fatalf("idx=%d outcome=%v winner=%q, want A consensusResolved", idx, outcome, votes[idx].records[0])
        }
}

func TestFoldConsensus_PresentBeatsAbsent(t *testing.T) {
        // A present record from even one resolver outranks authoritative-absence from the
        // rest: absence must never be fabricated from a present-vs-absent disagreement.
        idx, outcome := foldFixture([]voteFixture{vRes("A"), vAbsent(), vAbsent()})
        if outcome != consensusResolved || idx != 0 {
                t.Fatalf("idx=%d outcome=%v, want idx=0 consensusResolved", idx, outcome)
        }
}

func TestFoldConsensus_AbsentMajority(t *testing.T) {
        _, outcome := foldFixture([]voteFixture{vAbsent(), vAbsent(), vAbsent()})
        if outcome != consensusAbsent {
                t.Fatalf("outcome = %v, want consensusAbsent", outcome)
        }
}

func TestFoldConsensus_AbsentWithTransient(t *testing.T) {
        // One authoritative absence + transient failures: absence stands (a failed probe
        // cannot mask a real authoritative NXDOMAIN/NODATA).
        _, outcome := foldFixture([]voteFixture{vAbsent(), vTransient(), vTransient()})
        if outcome != consensusAbsent {
                t.Fatalf("outcome = %v, want consensusAbsent", outcome)
        }
}

func TestFoldConsensus_AllTransient(t *testing.T) {
        _, outcome := foldFixture([]voteFixture{vTransient(), vTransient()})
        if outcome != consensusTransient {
                t.Fatalf("outcome = %v, want consensusTransient", outcome)
        }
}

func TestFoldConsensus_Empty(t *testing.T) {
        idx, outcome := foldResolverConsensus(nil, nil)
        if idx != -1 || outcome != consensusTransient {
                t.Fatalf("idx=%d outcome=%v, want idx=-1 consensusTransient", idx, outcome)
        }
}

func TestCanonicalRecordKey_OrderIndependent(t *testing.T) {
        if canonicalRecordKey([]string{"a", "b"}) != canonicalRecordKey([]string{"b", "a"}) {
                t.Fatal("canonicalRecordKey must be order-independent")
        }
}

func TestCanonicalRecordKey_DistinctSets(t *testing.T) {
        if canonicalRecordKey([]string{"a", "b"}) == canonicalRecordKey([]string{"a", "c"}) {
                t.Fatal("distinct record sets must produce distinct keys")
        }
}

func TestCanonicalRecordKey_DoesNotMutate(t *testing.T) {
        in := []string{"b", "a"}
        _ = canonicalRecordKey(in)
        if !reflect.DeepEqual(in, []string{"b", "a"}) {
                t.Fatalf("canonicalRecordKey mutated its input: %v", in)
        }
}


// TestAbsentDenialAD pins the denial-authentication fold: UNANIMITY among
// absent voters is required — one loose AD-setter (measured: OpenDNS on
// NSEC3 opt-out denials) must never fake a cryptographic proof; resolved or
// transient voters' bits never count and never break unanimity.
func TestAbsentDenialAD(t *testing.T) {
        cases := []struct {
                name     string
                outcomes []resolverOutcome
                auth     []bool
                want     bool
        }{
                {"unanimous authenticated denial", []resolverOutcome{outcomeAbsent, outcomeAbsent}, []bool{true, true}, true},
                {"one loose AD-setter cannot fake proof (the OpenDNS opt-out case)", []resolverOutcome{outcomeAbsent, outcomeAbsent, outcomeAbsent}, []bool{false, true, false}, false},
                {"no authenticated denial", []resolverOutcome{outcomeAbsent, outcomeAbsent}, []bool{false, false}, false},
                {"AD on a RESOLVED voter never counts", []resolverOutcome{outcomeResolved, outcomeAbsent}, []bool{true, false}, false},
                {"transient voters do not break unanimity", []resolverOutcome{outcomeTransient, outcomeAbsent}, []bool{false, true}, true},
                {"AD on a transient voter never counts", []resolverOutcome{outcomeTransient, outcomeAbsent}, []bool{true, false}, false},
                {"empty", nil, nil, false},
        }
        for _, c := range cases {
                if got := absentDenialAD(c.outcomes, c.auth); got != c.want {
                        t.Errorf("%s: absentDenialAD = %v, want %v", c.name, got, c.want)
                }
        }
}
