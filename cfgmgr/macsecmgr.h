#ifndef __MACSECMGR__
#define __MACSECMGR__

#include <orch.h>
#include <swss/schema.h>
#include <swss/boolean.h>

#include <cinttypes>
#include <map>
#include <vector>
#include <sstream>

#include <sys/types.h>

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
        // CKNs currently applied to wpa_supplicant for this port. They are
        // tracked so a profile hot-update can diff the previously applied keys
        // against the new ones and drive the runtime macsec_* commands
        // (add/remove/rotate) instead of restarting the MKA session.
        std::string primary_ckn;
        // Empty when no fallback CA is currently configured on the port.
        std::string fallback_ckn;
    };

private:
    std::map<std::string, struct MACsecProfile> m_profiles;
    std::map<std::string, MKASession>           m_macsec_ports;

    task_process_status removeProfile(const std::string & profile_name, const TaskArgs & profile_attr);
    task_process_status loadProfile(const std::string & profile_name, const TaskArgs & profile_attr);
    task_process_status enableMACsec(const std::string & port_name, const TaskArgs & port_attr);
    task_process_status disableMACsec(const std::string & port_name, const TaskArgs & port_attr);


    Table m_statePortTable;

    bool isPortStateOk(const std::string & port_name);
    pid_t startWPASupplicant(const std::string & sock) const;
    bool stopWPASupplicant(pid_t pid) const;
    bool configureMACsec(const std::string & port_name, const MKASession & session, const MACsecProfile & profile) const;
    bool unconfigureMACsec(const std::string & port_name, const MKASession & session) const;

    // Runtime MKA participant management over the per-port wpa_supplicant ctrl
    // socket. These wrap the macsec_add_mka / macsec_del_mka / macsec_mka_list
    // commands used to plumb a fallback CA and to perform hitless CAK rotation.

    // Add an MKA participant. 'fallback' marks it as a standby CA. Idempotent:
    // an already-present CKN is treated as success.
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
    // Parse macsec_mka_list into one map of field->value per participant.
    std::vector<std::map<std::string, std::string>> getMKAParticipants(
        const std::string & sock,
        const std::string & port_name) const;
    // Poll macsec_mka_list until the given CKN reports live_peers >= 1, or the
    // timeout elapses. Returns true once the CKN has converged with a peer.
    bool waitForCKNLive(
        const std::string & sock,
        const std::string & port_name,
        const std::string & ckn,
        std::uint64_t timeout_ms) const;
    // Drive the runtime commands needed to move a live port from old_profile to
    // new_profile without tearing down the MKA session (primary CAK rotation,
    // fallback add/remove/change). Updates the CKNs tracked on 'session'.
    bool hotUpdateProfile(
        const std::string & port_name,
        MKASession & session,
        const MACsecProfile & old_profile,
        const MACsecProfile & new_profile) const;
};

}

#endif
