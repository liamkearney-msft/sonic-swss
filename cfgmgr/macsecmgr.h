#ifndef __MACSECMGR__
#define __MACSECMGR__

#include <orch.h>
#include <timer.h>
#include <swss/schema.h>
#include <swss/boolean.h>

#include <boost/optional.hpp>

#include <cinttypes>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <sstream>

#include <sys/types.h>

// The MKA operational state HLD adds these to sonic-swss-common's common/schema.h.
// Until that lands there is no shared spelling for the two tables, so define them
// here; the guards hand over to swss-common without a source change.
#ifndef STATE_MACSEC_MKA_SESSION_TABLE_NAME
#define STATE_MACSEC_MKA_SESSION_TABLE_NAME     "MACSEC_MKA_SESSION_TABLE"
#endif
#ifndef STATE_MACSEC_MKA_PARTICIPANT_TABLE_NAME
#define STATE_MACSEC_MKA_PARTICIPANT_TABLE_NAME "MACSEC_MKA_PARTICIPANT_TABLE"
#endif

namespace swss {

class MACsecMgr : public Orch
{
public:
    using Orch::doTask;
    MACsecMgr(DBConnector *cfgDb, DBConnector *stateDb, const std::vector<std::string> &tableNames);
    ~MACsecMgr();
private:
    void doTask(Consumer &consumer);

public:
    using TaskArgs = std::vector<FieldValueTuple>;
    struct MACsecProfile
    {
        std::uint32_t       priority;
        enum CipherSuite
        {
            GCM_AES_128,
            GCM_AES_256,
            GCM_AES_XPN_128,
            GCM_AES_XPN_256,
        }                   cipher_suite;
        std::string         primary_cak;
        std::string         primary_ckn;
        std::string         fallback_cak;
        std::string         fallback_ckn;
        enum Policy
        {
            INTEGRITY_ONLY,
            SECURITY,
        }                   policy;
        swss::AlphaBoolean  enable_replay_protect;
        std::uint32_t       replay_window;
        swss::AlphaBoolean  send_sci;
        std::uint32_t       rekey_period;
        bool update(const TaskArgs & ta);
    };

    struct MKASession
    {
        std::string profile_name;
        // wpa_supplicant communication socket
        std::string sock;
        // wpa_supplicant process id
        pid_t       wpa_supplicant_pid;
        // Key material currently applied to wpa_supplicant, in the encoded form
        // held in CONFIG_DB. A hot update diffs against this rather than against
        // the previous profile, so a partially applied update is retried against
        // what the port actually has. The fallback pair is empty when the port
        // has no fallback CA.
        std::string primary_cak;
        std::string primary_ckn;
        std::string fallback_cak;
        std::string fallback_ckn;
        // wpa_supplicant network block holding the key material, so a hot update
        // can rewrite mka_ckn / mka_cak in place instead of adding a network.
        std::string network_id;
        // CKNs currently published to MACSEC_MKA_PARTICIPANT_TABLE. A validated
        // snapshot is complete, so whatever it omits is stale and can be deleted
        // without re-reading the table.
        std::set<std::string> published_ckns;
        // Whether a complete snapshot has ever been published for this port. Until
        // one has, a failed query must not publish success shaped defaults.
        bool         has_published_snapshot = false;
        // Consecutive failed status queries, and the number of poll ticks still to
        // skip, so a wedged port backs off instead of spending the tick budget.
        unsigned int query_failures = 0;
        unsigned int poll_backoff = 0;
    };

    // One participant block of a macsec_mka_list snapshot, normalised to the types
    // and spellings MACSEC_MKA_PARTICIPANT_TABLE publishes.
    struct MKAParticipantStatus
    {
        std::string   ckn;
        std::uint32_t participant_index = 0;
        std::string   mi;
        std::uint32_t mn = 0;
        bool          active = false;
        bool          participant = false;
        bool          retain = false;
        bool          is_principal = false;
        bool          is_fallback = false;
        std::uint32_t live_peers = 0;
        std::uint32_t potential_peers = 0;
        bool          is_key_server = false;
        bool          is_elected = false;
    };

    // A complete macsec_mka_list snapshot. Only ever filled in from a response that
    // passed every validation, so a truncated or malformed reply cannot reach
    // STATE_DB and look like a participant going away.
    struct MKAStatus
    {
        std::string   kay_status;
        bool          authenticated = false;
        bool          secured = false;
        bool          failed = false;
        std::string   actor_sci;
        std::string   key_server_sci;
        std::uint32_t actor_priority = 0;
        std::uint32_t key_server_priority = 0;
        bool          is_key_server = false;
        std::uint32_t keys_distributed = 0;
        std::uint32_t keys_received = 0;
        std::uint32_t mka_hello_time_ms = 0;
        std::vector<MKAParticipantStatus> participants;
    };

    // Parse a macsec_mka_list response. Returns false, and a reason in 'error',
    // for anything that is not a complete and self consistent snapshot.
    static bool parseMKAStatus(
        const std::string & output,
        MKAStatus & status,
        std::string & error);

private:
    std::map<std::string, struct MACsecProfile> m_profiles;
    std::map<std::string, MKASession>           m_macsec_ports;

    task_process_status removeProfile(const std::string & profile_name, const TaskArgs & profile_attr);
    task_process_status loadProfile(const std::string & profile_name, const TaskArgs & profile_attr);
    task_process_status enableMACsec(const std::string & port_name, const TaskArgs & port_attr);
    task_process_status disableMACsec(const std::string & port_name, const TaskArgs & port_attr);


    Table m_statePortTable;
    Table m_stateMkaSessionTable;
    Table m_stateMkaParticipantTable;

    // Periodic refresh of the MKA operational state of every configured port.
    SelectableTimer *m_mka_poll_timer = nullptr;
    // Round robin position in m_macsec_ports, so a tick refreshes a slice of the
    // ports rather than all of them.
    std::string m_mka_poll_cursor;

    void doTask(SelectableTimer &timer);
    // Collect one snapshot, bounded by its own deadline. Returns false when the
    // query fails or the response is rejected.
    bool queryMKAStatus(
        const MKASession & session,
        const std::string & port_name,
        MKAStatus & status) const;
    // Collect and publish, recording success or collection failure on 'session'.
    void refreshMKAStatus(const std::string & port_name, MKASession & session);
    void publishMKAStatus(
        const std::string & port_name,
        MKASession & session,
        const MKAStatus & status);
    void publishMKAQueryFailure(const std::string & port_name, MKASession & session);
    // Drop every MACSEC_MKA row of a port, including rows left by a previous
    // macsecmgrd, and forget what was published for it.
    void clearMKAStatus(const std::string & port_name, MKASession & session);

    bool isPortStateOk(const std::string & port_name);
    pid_t startWPASupplicant(const std::string & sock) const;
    bool stopWPASupplicant(pid_t pid) const;
    bool configureMACsec(const std::string & port_name, MKASession & session, const MACsecProfile & profile) const;
    bool unconfigureMACsec(const std::string & port_name, const MKASession & session) const;

    // One MKA participant reported by macsec_mka_list.
    struct MKAParticipant
    {
        std::string ckn;
        bool        fallback = false;
    };

    static const MKAParticipant * findParticipant(
        const std::vector<MKAParticipant> & participants,
        const std::string & ckn);

    // Runtime MKA participant management over the per-port wpa_supplicant ctrl
    // socket, wrapping macsec_add_mka / macsec_del_mka / macsec_mka_list.

    // Add an MKA participant. 'fallback' marks it as a standby CA. Idempotent,
    // and re-adds the CKN when it is present holding the other role.
    bool addMKA(
        const std::string & sock,
        const std::string & port_name,
        const std::string & ckn,
        const std::string & cak,
        bool fallback) const;
    // Remove an MKA participant. Absent CKN is a no-op success.
    bool delMKA(
        const std::string & sock,
        const std::string & port_name,
        const std::string & ckn) const;
    // Returns boost::none when the port could not be queried. That is not the
    // same answer as an empty list, and callers must not treat it as one.
    boost::optional<std::vector<MKAParticipant>> getMKAParticipants(
        const std::string & sock,
        const std::string & port_name) const;
    // Apply 'profile' to a live port with runtime commands instead of restarting
    // the MKA session, recording what was applied on 'session' and republishing
    // the operational state after each participant change.
    bool hotUpdateProfile(
        const std::string & port_name,
        MKASession & session,
        const MACsecProfile & profile);
};

}

#endif
