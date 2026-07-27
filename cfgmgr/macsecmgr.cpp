#include "macsecmgr.h"

#include <exec.h>
#include <shellcmd.h>
#include <swss/stringutility.h>
#include <swss/redisutility.h>
#include <boost/algorithm/string/predicate.hpp>

#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <string.h>
#include <error.h>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <algorithm>
#include <sstream>
#include <cctype>
#include <thread>
#include <chrono>


using namespace std;
using namespace swss;

#define WPA_SUPPLICANT_CMD "/sbin/wpa_supplicant"
#define WPA_CLI_CMD        "/sbin/wpa_cli"
#define WPA_CONF           "/etc/wpa_supplicant.conf"
#define SOCK_DIR           "/var/run/"

constexpr std::uint64_t RETRY_TIME = 30;

/* retry interval, in millisecond */
constexpr std::uint64_t RETRY_INTERVAL = 100;

/* Max time to wait for a staged CKN to converge with the peer (report
 * live_peers >= 1) during a hitless CAK rotation, in milliseconds. */
constexpr std::uint64_t CKN_CONVERGE_TIMEOUT_MS = 30000;

/* Poll interval while waiting for CKN convergence, in milliseconds. */
constexpr std::uint64_t CKN_CONVERGE_INTERVAL_MS = 500;

/*
 * The input cipher_str is the encoded string which can be either of length 66 bytes or 130 bytes.
 *
 * 66 bytes of length, for 128-byte cipher suite
 *   - first 2 bytes of the string will be the index from the magic salt string.
 *   - remaining 64 bytes will be encoded string from the 32-byte plain text CAK input string.
 *
 * 130 bytes of length, for 256-byte cipher suite
 *   - first 2 bytes of the string will be the index from the magic salt string.
 *   - remaining 128 bytes will be encoded string from the 32 byte plain text CAK input string.
*/
constexpr std::size_t AES_LEN_128_BYTE = 66;
constexpr std::size_t AES_LEN_256_BYTE = 130;

static void lexical_convert(const std::string &policy_str, MACsecMgr::MACsecProfile::Policy & policy)
{
    SWSS_LOG_ENTER();

    if (boost::iequals(policy_str, "integrity_only"))
    {
        policy = MACsecMgr::MACsecProfile::Policy::INTEGRITY_ONLY;
    }
    else if (boost::iequals(policy_str, "security"))
    {
        policy = MACsecMgr::MACsecProfile::Policy::SECURITY;
    }
    else
    {
        throw std::invalid_argument("Invalid policy : " + policy_str);
    }
}

static void lexical_convert(const std::string &cipher_str, MACsecMgr::MACsecProfile::CipherSuite & cipher_suite)
{
    SWSS_LOG_ENTER();

    if (boost::iequals(cipher_str, "GCM-AES-128"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_128;
    }
    else if (boost::iequals(cipher_str, "GCM-AES-256"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_256;
    }
    else if (boost::iequals(cipher_str, "GCM-AES-XPN-128"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_128;
    }
    else if (boost::iequals(cipher_str, "GCM-AES-XPN-256"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_256;
    }
    else
    {
        throw std::invalid_argument("Invalid cipher_suite : " + cipher_str);
    }
}



/* Decodes a Type 7 encoded input.
 *
 * The Type 7 encoding consists of two decimal digits(encoding the salt), followed a series of hexadecimal characters,
 * two for every byte in the encoded password. An example encoding(of "password") is 044B0A151C36435C0D.
 * This has a salt/offset of 4 (04 in the example), and encodes password via 4B0A151C36435C0D.
 *
 * The algorithm is a straightforward XOR Cipher that relies on the following ascii-encoded 53-byte constant:
 *    "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
 *
 * Decode()
 *    Get the salt index from the first 2 chars
 *    For each byte in the provided text after the encoded salt:
 *        j = (salt index + 1) % 53
 *        XOR the i'th byte of the password with the j'th byte of the magic constant.
 *        append to the decoded string.
 */
static std::string decodeKey(const std::string &cipher_str, const MACsecMgr::MACsecProfile::CipherSuite & cipher_suite)
{
    int salts[] = { 0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F, 0x41, 0x2C, 0x2E, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6B, 0x6C, 0x64, 0x4A, 0x4B, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6E, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6B, 0x3B, 0x66, 0x67, 0x38, 0x37 };

    std::string decodedPassword = std::string("");
    std::string cipher_hex_str = std::string("");
    unsigned int hex_int, saltIdx;

    if ((cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_128) ||
        (cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_128))
    {
        if (cipher_str.length() != AES_LEN_128_BYTE)
            throw std::invalid_argument("Invalid length for cipher_string : " + cipher_str);
    }
    else if ((cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_256) ||
             (cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_256))
    {
        if (cipher_str.length() != AES_LEN_256_BYTE)
            throw std::invalid_argument("Invalid length for cipher_string : " + cipher_str);
    }

    // Get the salt index from the cipher_str
    saltIdx = (unsigned int) stoi(cipher_str.substr(0,2));

    // Convert the hex string (eg: "aabbcc") to hex integers (eg: 0xaa, 0xbb, 0xcc) taking a substring of 2 chars at a time
    // and do xor with the magic salt string
    for (size_t i = 2; i < cipher_str.length(); i += 2) {
        std::stringstream ss;
        ss << std::hex << cipher_str.substr(i,2);
        ss >> hex_int;
        decodedPassword += (char)(hex_int ^ salts[saltIdx++ % (sizeof(salts)/sizeof(salts[0]))]);
    }

    return decodedPassword;
}

template<class T>
static bool get_value(
    const MACsecMgr::TaskArgs & ta,
    const std::string & field,
    T & value)
{
    SWSS_LOG_ENTER();

    auto value_opt = swss::fvsGetValue(ta, field, true);
    if (!value_opt)
    {
        SWSS_LOG_DEBUG("Cannot find field : %s", field.c_str());
        return false;
    }

    try
    {
        lexical_convert(*value_opt, value);
    }
    catch(const boost::bad_lexical_cast &e)
    {
        SWSS_LOG_ERROR("Cannot convert value(%s) in field(%s)", value_opt->c_str(), field.c_str());
        return false;
    }

    return true;
}

static void wpa_cli_commands(std::ostringstream & ostream)
{
    // Intentionally emtpy function to adapt
    // the recursively calling of wpa_cli_commands
}

template<typename T, typename...Args>
static void wpa_cli_commands(
    std::ostringstream & ostream,
    T && t,
    Args && ... args)
{
    ostream << " " << t;
    wpa_cli_commands(ostream, args...);
}

template<typename...Args>
static void wpa_cli_commands(
    std::ostringstream & ostream,
    const std::string & t,
    Args && ... args)
{
    ostream << shellquote(t) << " ";
    wpa_cli_commands(ostream, args...);
}

template<typename...Args>
static void wpa_cli_commands(
    std::ostringstream & ostream,
    const std::string & sock,
    const std::string & port_name,
    const std::string & network_id,
    Args && ... args)
{
    ostream << WPA_CLI_CMD;
    wpa_cli_commands(ostream, "-g", sock);
    if (!port_name.empty())
    {
        wpa_cli_commands(ostream, "IFNAME=" + port_name);
    }
    if (!network_id.empty())
    {
        wpa_cli_commands(ostream, "set_network", network_id);
    }
    wpa_cli_commands(ostream, args...);
}

template<typename...Args>
static std::string wpa_cli_exec(
    const std::string & sock,
    const std::string & port_name,
    const std::string & network_id,
    Args && ... args)
{
    std::ostringstream ostream;
    std::string res;
    wpa_cli_commands(
        ostream,
        sock,
        port_name,
        network_id,
        std::forward<Args>(args)...);
    EXEC_WITH_ERROR_THROW(ostream.str(), res);
    return res;
}

template<typename...Args>
static void wpa_cli_exec_and_check(
    const std::string & sock,
    const std::string & port_name,
    const std::string & network_id,
    Args && ... args)
{
    std::string res = wpa_cli_exec(
        sock,
        port_name,
        network_id,
        std::forward<Args>(args)...);
    if (res.find("OK") != 0)
    {
        std::ostringstream ostream;
        wpa_cli_commands(
            ostream,
            sock,
            port_name,
            network_id,
            std::forward<Args>(args)...);
        throw std::runtime_error(
            "Wpa_cli command : " + ostream.str() + " -> " +res);
    }
}

MACsecMgr::MACsecMgr(
    DBConnector *cfgDb,
    DBConnector *stateDb,
    const vector<std::string> &tables) :
        Orch(cfgDb, tables),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME)
{
}

MACsecMgr::~MACsecMgr()
{
    // Disable MACsec for all ports
    while (!m_macsec_ports.empty())
    {
        auto port = m_macsec_ports.begin();
        const TaskArgs temp;
        disableMACsec(port->first, temp);
    }
}

void MACsecMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    using TaskType = std::tuple<const std::string,const std::string>;
    using TaskFunc = task_process_status (MACsecMgr::*)(const std::string &, const TaskArgs &);
    const static std::map<TaskType, TaskFunc > TaskMap = {
        { { CFG_MACSEC_PROFILE_TABLE_NAME, SET_COMMAND }, &MACsecMgr::loadProfile},
        { { CFG_MACSEC_PROFILE_TABLE_NAME, DEL_COMMAND }, &MACsecMgr::removeProfile},
        { { CFG_PORT_TABLE_NAME, SET_COMMAND }, &MACsecMgr::enableMACsec},
        { { CFG_PORT_TABLE_NAME, DEL_COMMAND }, &MACsecMgr::disableMACsec},
    };

    const std::string & table_name = consumer.getTableName();
    auto itr = consumer.m_toSync.begin();
    while (itr != consumer.m_toSync.end())
    {
        task_process_status task_done = task_failed;
        auto & message = itr->second;
        const std::string & op = kfvOp(message);

        auto task = TaskMap.find(std::make_tuple(table_name, op));
        if (task != TaskMap.end())
        {
            task_done = (this->*task->second)(
                kfvKey(message),
                kfvFieldsValues(message));
        }
        else
        {
            SWSS_LOG_ERROR(
                "Unknown task : %s - %s",
                table_name.c_str(),
                op.c_str());
        }

        if (task_done == task_need_retry)
        {
            SWSS_LOG_DEBUG(
                "Task %s - %s need retry",
                table_name.c_str(),
                op.c_str());
            ++itr;
        }
        else
        {
            if (task_done != task_success)
            {
                SWSS_LOG_WARN("Task %s - %s fail",
                    table_name.c_str(),
                    op.c_str());
            }
            else
            {
                SWSS_LOG_DEBUG(
                    "Task %s - %s success",
                    table_name.c_str(),
                    op.c_str());
            }

            itr = consumer.m_toSync.erase(itr);
        }
    }
}

#define GetValue(args, name) (get_value(args, #name, name))

bool MACsecMgr::MACsecProfile::update(const TaskArgs & ta)
{
    SWSS_LOG_ENTER();

    // The following fields are optional. Reset them first so that a CONFIG_DB
    // entry which no longer carries them (e.g. an operator HDEL of
    // fallback_cak/fallback_ckn) clears any previously applied fallback rather
    // than retaining stale key material. loadProfile() updates the stored
    // profile object in place (map::emplace is a no-op for an existing profile),
    // so without this reset the old fallback CKN/CAK would survive, the hot
    // update would not observe a fallback change, and its removal would never be
    // driven onto wpa_supplicant.
    fallback_cak.clear();
    fallback_ckn.clear();
    if (GetValue(ta, fallback_cak) && !GetValue(ta, fallback_ckn))
    {
        return false;
    }
    if (!GetValue(ta, enable_replay_protect))
    {
        enable_replay_protect = false;
    }
    if (!GetValue(ta, replay_window))
    {
        replay_window = 0;
    }
    if (!GetValue(ta, send_sci))
    {
        send_sci = true;
    }
    if (!GetValue(ta, rekey_period))
    {
        rekey_period = 0;
    }
    if (!GetValue(ta, priority))
    {
        priority = 255;
    }
    if (!GetValue(ta, policy))
    {
        policy = Policy::SECURITY;
    }

    // The following fields are necessary
    return GetValue(ta, cipher_suite)
        && GetValue(ta, primary_cak)
        && GetValue(ta, primary_ckn);
}

task_process_status MACsecMgr::loadProfile(
    const std::string & profile_name,
    const TaskArgs & profile_attr)
{
    SWSS_LOG_ENTER();

    // Capture the currently applied profile (if any) before update() overwrites
    // it in place, so a hot-update can diff old vs new key material.
    auto existing = m_profiles.find(profile_name);
    const bool existed = (existing != m_profiles.end());
    MACsecProfile old_profile;
    if (existed)
    {
        old_profile = existing->second;
    }

    auto profile = m_profiles.emplace(
        std::piecewise_construct,
        std::make_tuple(profile_name),
        std::make_tuple());
    try
    {
        auto & new_profile = profile.first->second;
        if (new_profile.update(profile_attr))
        {
            SWSS_LOG_NOTICE(
                "The MACsec profile '%s' is loaded",
                profile_name.c_str());
        }

        // Reject a fallback CA whose CKN collides with the primary CKN. The YANG
        // model enforces this too; this is defense in depth for direct CONFIG_DB
        // writes that bypass YANG validation.
        if (!new_profile.fallback_ckn.empty()
            && new_profile.fallback_ckn == new_profile.primary_ckn)
        {
            SWSS_LOG_WARN(
                "The MACsec profile '%s' has a fallback CKN equal to its "
                "primary CKN; rejecting the profile",
                profile_name.c_str());
            // update() mutates the stored profile in place, so undo it: restore
            // the previously applied profile, or drop the newly inserted one, to
            // avoid leaving invalid key material in the map.
            if (existed)
            {
                profile.first->second = old_profile;
            }
            else
            {
                m_profiles.erase(profile_name);
            }
            return task_failed;
        }

        // If the profile is already applied to one or more ports, drive the
        // change onto wpa_supplicant at run time instead of restarting the MKA
        // session (hitless CAK rotation / fallback add/remove).
        if (existed)
        {
            for (auto & port : m_macsec_ports)
            {
                if (port.second.profile_name == profile_name)
                {
                    SWSS_LOG_NOTICE(
                        "Hot-updating MACsec profile '%s' on port '%s'",
                        profile_name.c_str(),
                        port.first.c_str());
                    if (!hotUpdateProfile(
                            port.first,
                            port.second,
                            old_profile,
                            new_profile))
                    {
                        SWSS_LOG_WARN(
                            "Hot-update of MACsec profile '%s' on port '%s' "
                            "did not fully succeed",
                            profile_name.c_str(),
                            port.first.c_str());
                    }
                }
            }
        }
        return task_success;
    }
    catch(const std::invalid_argument & e)
    {
        SWSS_LOG_WARN("%s", e.what());
        return task_failed;
    }
}

task_process_status MACsecMgr::removeProfile(
    const std::string & profile_name,
    const TaskArgs & profile_attr)
{
    SWSS_LOG_ENTER();

    auto profile = m_profiles.find(profile_name);
    if (profile == m_profiles.end())
    {
        SWSS_LOG_WARN(
            "The MACsec profile '%s' wasn't loaded",
            profile_name.c_str());
        return task_invalid_entry;
    }

    // The MACsec profile cannot be removed if it is occupied
    auto port = std::find_if(
        m_macsec_ports.begin(),
        m_macsec_ports.end(),
        [&](const decltype(m_macsec_ports)::value_type & pair)
        {
            return pair.second.profile_name == profile_name;
        });
    if (port != m_macsec_ports.end())
    {
        // This MACsec profile is occupied by some ports
        // remove it after all ports disable MACsec
        SWSS_LOG_DEBUG(
            "The MACsec profile '%s' is used by the port '%s'",
            profile_name.c_str(),
            port->first.c_str());
        return task_need_retry;
    }
    SWSS_LOG_NOTICE("The MACsec profile '%s' is removed", profile_name.c_str());
    m_profiles.erase(profile);
    return task_success;
}

task_process_status MACsecMgr::enableMACsec(
    const std::string & port_name,
    const TaskArgs & port_attr)
{
    SWSS_LOG_ENTER();

    std::string profile_name;
    if (!get_value(port_attr, "macsec", profile_name)
        || profile_name.empty())
    {
        SWSS_LOG_DEBUG("MACsec field of port '%s' is empty", port_name.c_str());
        return disableMACsec(port_name, port_attr);
    }

    // If the MACsec profile is ready
    auto itr = m_profiles.find(profile_name);
    if (itr == m_profiles.end())
    {
        SWSS_LOG_DEBUG(
            "The MACsec profile '%s' for the port '%s' isn't ready",
            profile_name.c_str(),
            port_name.c_str());
        return task_need_retry;
    }
    auto & profile = itr->second;

    // If the port is ready
    if (!isPortStateOk(port_name))
    {
        SWSS_LOG_DEBUG("The port '%s' isn't ready", port_name.c_str());
        return task_need_retry;
    }

    // Handle existing macsec profile
    auto port_itr = m_macsec_ports.find(port_name);
    if (port_itr != m_macsec_ports.end())
    {
        if (port_itr->second.profile_name == profile_name)
        {
            SWSS_LOG_NOTICE(
                "The MACsec profile '%s' on the port '%s' has been loaded",
                profile_name.c_str(),
                port_name.c_str());
            return task_success;
        }
        else
        {
            SWSS_LOG_NOTICE(
                "The MACsec profile '%s' on the port '%s' "
                "will be replaced by the MACsec profile '%s'",
                port_itr->second.profile_name.c_str(),
                port_name.c_str(),
                profile_name.c_str());
            auto result = disableMACsec(port_name, port_attr);
            if (result != task_success)
            {
                return result;
            }
        }
    }
    // Create MKA Session object
    auto port = m_macsec_ports.emplace(
        std::piecewise_construct,
        std::make_tuple(port_name),
        std::make_tuple());
    auto & session = port.first->second;
    session.profile_name = profile_name;
    ostringstream ostream;
    ostream << SOCK_DIR << port_name;
    session.sock = ostream.str();
    session.wpa_supplicant_pid = startWPASupplicant(session.sock);
    if (session.wpa_supplicant_pid < 0)
    {
        SWSS_LOG_WARN("Cannot start the wpa_supplicant of the port '%s' : %s",
            port_name.c_str(),
            strerror(errno));
        m_macsec_ports.erase(port.first);
        return task_need_retry;
    }
    else if (session.wpa_supplicant_pid == 0)
    {
        SWSS_LOG_WARN("Cannot start the wpa_supplicant of the port '%s' : %s",
        port_name.c_str(),
        strerror(errno));
        m_macsec_ports.erase(port.first);
        return task_failed;
    }

    // Enable MACsec
    if (!configureMACsec(port_name, session, profile))
    {
        SWSS_LOG_WARN("The MACsec profile '%s' on the port '%s' loading fail",
            profile_name.c_str(),
            port_name.c_str());
        return disableMACsec(port_name, port_attr);
    }
    // Remember the CKNs actually pushed to wpa_supplicant so a later profile
    // hot-update can diff against them.
    session.primary_ckn = profile.primary_ckn;
    session.fallback_ckn = profile.fallback_ckn;
    SWSS_LOG_NOTICE("The MACsec profile '%s' on the port '%s' loading success",
        profile_name.c_str(),
        port_name.c_str());
    return task_success;
}

task_process_status MACsecMgr::disableMACsec(
    const std::string & port_name,
    const TaskArgs & port_attr)
{
    SWSS_LOG_ENTER();

    auto itr = m_macsec_ports.find(port_name);
    if (itr == m_macsec_ports.end())
    {
        SWSS_LOG_NOTICE("The MACsec was not enabled on the port '%s'",
            port_name.c_str());
        return task_success;
    }
    auto & session = itr->second;
    task_process_status ret = task_success;
    if (!unconfigureMACsec(port_name, session))
    {
        SWSS_LOG_WARN(
            "Cannot stop MKA session on the port '%s'",
            port_name.c_str());
        ret = task_failed;
    }
    if (!stopWPASupplicant(session.wpa_supplicant_pid))
    {
        SWSS_LOG_WARN(
            "Cannot stop WPA_SUPPLICANT process of the port '%s'",
            port_name.c_str());
        ret = task_failed;
    }
    if (ret == task_success)
    {
        SWSS_LOG_NOTICE("The MACsec profile '%s' on the port '%s' is removed",
            itr->second.profile_name.c_str(),
            port_name.c_str());
    }
    m_macsec_ports.erase(itr);
    return ret;
}

bool MACsecMgr::isPortStateOk(const std::string & port_name)
{
    SWSS_LOG_ENTER();

    std::vector<FieldValueTuple> temp;
    std::string state;
    std::string oper_status;

    if (m_statePortTable.get(port_name, temp)
        && get_value(temp, "state", state)
        && state == "ok"
        && get_value(temp, "netdev_oper_status", oper_status)
        && oper_status == "up")
    {
        SWSS_LOG_DEBUG("Port '%s' is ready", port_name.c_str());
        return true;
    }
    SWSS_LOG_DEBUG("Port '%s' is not ready", port_name.c_str());
    return false;
}

pid_t MACsecMgr::startWPASupplicant(const std::string & sock) const
{
    SWSS_LOG_ENTER();

    pid_t wpa_supplicant_pid = fork();
    if (wpa_supplicant_pid == 0)
    {
        exit(execl(
            WPA_SUPPLICANT_CMD,
            WPA_SUPPLICANT_CMD,
            "-s",
            "-D", "macsec_sonic",
            "-g", sock.c_str(),
            NULL));
    }
    else if (wpa_supplicant_pid > 0)
    {
        // Wait wpa_supplicant ready
        bool wpa_supplicant_loading = false;
        auto retry_time = RETRY_TIME;
        while(!wpa_supplicant_loading && retry_time > 0)
        {
            try
            {
                wpa_cli_exec(sock, "", "", "status");
                wpa_supplicant_loading = true;
            }
            catch(const std::runtime_error&)
            {
                retry_time--;
                std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL));
            }
        }
        if (wpa_supplicant_loading)
        {
            SWSS_LOG_DEBUG("Start wpa_supplicant success");
        }
        else
        {
            stopWPASupplicant(wpa_supplicant_pid);
            wpa_supplicant_pid = 0;
            SWSS_LOG_WARN("Cannot connect to wpa_supplicant.");
        }
    }
    return wpa_supplicant_pid;
}

bool MACsecMgr::stopWPASupplicant(pid_t pid) const
{
    SWSS_LOG_ENTER();

    if(kill(pid, SIGINT) != 0)
    {
        SWSS_LOG_WARN("Cannot stop wpa_supplicant(%d)", pid);
        return false;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    SWSS_LOG_DEBUG(
        "Stop wpa_supplicant(%d) with return value (%d)",
        pid,
        status);
    return status == 0;
}

bool MACsecMgr::configureMACsec(
    const std::string & port_name,
    const MKASession & session,
    const MACsecProfile & profile) const
{
    SWSS_LOG_ENTER();

    try
    {
        wpa_cli_exec_and_check(
            session.sock,
            "",
            "",
            "interface_add",
            port_name,
            WPA_CONF,
            "macsec_sonic");

        const std::string res = wpa_cli_exec(
            session.sock,
            port_name,
            "",
            "add_network");
        const std::string network_id(
            res.begin(),
            std::find_if_not(
                res.begin(),
                res.end(),
                [](unsigned char c)
                {
                    return std::isdigit(c);
                }
            )
        );
        if (network_id.empty())
        {
            throw std::runtime_error("Cannot add network : " + res);
        }

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "key_mgmt",
            "NONE");

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "eapol_flags",
            0);

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "macsec_policy",
            1);

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "macsec_integ_only",
            (profile.policy == MACsecProfile::Policy::INTEGRITY_ONLY ? 1 : 0));

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "mka_cak",
            decodeKey(profile.primary_cak, profile.cipher_suite));

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "mka_ckn",
            profile.primary_ckn);

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "mka_priority",
            profile.priority);

        if (profile.rekey_period)
        {
            wpa_cli_exec_and_check(
                session.sock,
                port_name,
                network_id,
                "mka_rekey_period",
                profile.rekey_period);
        }

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "macsec_ciphersuite",
            profile.cipher_suite);

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "macsec_include_sci",
            (profile.send_sci ? 1 : 0));

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "macsec_replay_protect",
            (profile.enable_replay_protect ? 1 : 0));

        if (profile.enable_replay_protect)
        {
            wpa_cli_exec_and_check(
                session.sock,
                port_name,
                network_id,
                "macsec_replay_window",
                profile.replay_window);
        }

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            "",
            "enable_network",
            network_id);

        // The primary CA is loaded through the network block above. A fallback
        // CA (if configured) is added dynamically over the ctrl socket so it can
        // later be rotated/removed without restarting wpa_supplicant.
        if (!profile.fallback_ckn.empty())
        {
            if (!addMKA(
                    session.sock,
                    port_name,
                    profile.fallback_ckn,
                    decodeKey(profile.fallback_cak, profile.cipher_suite),
                    true))
            {
                throw std::runtime_error(
                    "Cannot add fallback MKA participant for CKN " + profile.fallback_ckn);
            }
        }
    }
    catch(const std::runtime_error & e)
    {
        SWSS_LOG_WARN("Enable MACsec fail : %s", e.what());
        return false;
    }
    return true;
}

bool MACsecMgr::unconfigureMACsec(
    const std::string & port_name,
    const MKASession & session) const
{
    SWSS_LOG_ENTER();

    // Retry interface_remove a few times in case wpa_supplicant is slow to
    // respond. This specifically targets the "command timed out" condition
    // seen in the field, to reduce spurious Task PORT - SET failures.
    static constexpr int MAX_INTERFACE_REMOVE_RETRIES = 3;

    for (int attempt = 1; attempt <= MAX_INTERFACE_REMOVE_RETRIES; ++attempt)
    {
        try
        {
            wpa_cli_exec_and_check(
                session.sock,
                "",
                "",
                "interface_remove",
                port_name);

            // Success on this attempt: no need to retry further.
            return true;
        }
        catch (const std::runtime_error &e)
        {
            const std::string error_message = e.what();
            // Best-effort cleanup semantics for interface_remove:
            //
            // 1. If wpa_cli returns "FAIL" for interface_remove, it typically means
            //    the interface is already gone from wpa_supplicant. From
            //    macsecmgr's perspective this is equivalent to a successful
            //    unconfigure, so treat it as success to avoid spurious
            //    Task PORT - SET failures.
            if (error_message.find("-> FAIL") != std::string::npos)
            {
                SWSS_LOG_NOTICE(
                    "interface_remove for port '%s' reported error '%s'; "
                    "treating MACsec unconfigure as best-effort success",
                    port_name.c_str(),
                    error_message.c_str());
                return true;
            }

            // 2. If the command times out, retry up to
            //    MAX_INTERFACE_REMOVE_RETRIES times. If all retries still time
            //    out, fall back to best-effort semantics: stopWPASupplicant()
            //    will still be invoked by the caller and will tear down the
            //    wpa_supplicant process (and its interfaces).
            if (error_message.find("command timed out") != std::string::npos)
            {
                if (attempt < MAX_INTERFACE_REMOVE_RETRIES)
                {
                    SWSS_LOG_WARN(
                        "interface_remove for port '%s' attempt %d/%d timed out: '%s'; retrying after 10 seconds",
                        port_name.c_str(),
                        attempt,
                        MAX_INTERFACE_REMOVE_RETRIES,
                        error_message.c_str());
                    std::this_thread::sleep_for(std::chrono::seconds(10));
                    continue;
                }

                SWSS_LOG_NOTICE(
                    "interface_remove for port '%s' timed out after %d attempts: '%s'; "
                    "ignoring timeouts and treating MACsec unconfigure as best-effort success",
                    port_name.c_str(),
                    MAX_INTERFACE_REMOVE_RETRIES,
                    error_message.c_str());
                return true;
            }

            // Any other error is treated as a real failure.
            SWSS_LOG_WARN("Disable MACsec fail : %s", error_message.c_str());
            return false;
        }
    }
    return true;
}

std::vector<std::map<std::string, std::string>> MACsecMgr::getMKAParticipants(
    const std::string & sock,
    const std::string & port_name) const
{
    SWSS_LOG_ENTER();

    std::vector<std::map<std::string, std::string>> participants;

    std::string output;
    try
    {
        output = wpa_cli_exec(sock, port_name, "", "macsec_mka_list");
    }
    catch(const std::runtime_error & e)
    {
        SWSS_LOG_WARN(
            "Cannot query MKA participants on port '%s' : %s",
            port_name.c_str(),
            e.what());
        return participants;
    }

    // macsec_mka_list emits top-level fields (actor_sci, key_server_sci) followed
    // by one 'key=value' block per participant. A new participant block starts at
    // the 'participant_idx' field; top-level fields before the first block are
    // ignored here.
    std::istringstream stream(output);
    std::string line;
    std::map<std::string, std::string> * current = nullptr;
    while (std::getline(stream, line))
    {
        // Trim trailing CR (wpa_cli may emit CRLF).
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        {
            line.pop_back();
        }
        if (line.empty())
        {
            continue;
        }
        auto pos = line.find('=');
        if (pos == std::string::npos)
        {
            continue;
        }
        const std::string key = line.substr(0, pos);
        const std::string value = line.substr(pos + 1);
        if (key == "participant_idx")
        {
            participants.emplace_back();
            current = &participants.back();
        }
        if (current != nullptr)
        {
            (*current)[key] = value;
        }
    }

    return participants;
}

bool MACsecMgr::addMKA(
    const std::string & sock,
    const std::string & port_name,
    const std::string & ckn,
    const std::string & cak,
    bool fallback) const
{
    SWSS_LOG_ENTER();

    // Idempotency: if the participant already exists, treat as success. This is
    // robust regardless of the exact rejection text wpa_supplicant returns for a
    // duplicate CKN.
    for (const auto & participant : getMKAParticipants(sock, port_name))
    {
        auto itr = participant.find("ckn");
        if (itr != participant.end() && boost::iequals(itr->second, ckn))
        {
            SWSS_LOG_NOTICE(
                "MKA participant CKN '%s' already present on port '%s'",
                ckn.c_str(),
                port_name.c_str());
            return true;
        }
    }

    try
    {
        if (fallback)
        {
            wpa_cli_exec_and_check(
                sock,
                port_name,
                "",
                "macsec_add_mka",
                "ckn=" + ckn,
                "cak=" + cak,
                "fallback=1");
        }
        else
        {
            wpa_cli_exec_and_check(
                sock,
                port_name,
                "",
                "macsec_add_mka",
                "ckn=" + ckn,
                "cak=" + cak);
        }
    }
    catch(const std::runtime_error & e)
    {
        SWSS_LOG_WARN(
            "Cannot add MKA participant CKN '%s' on port '%s' : %s",
            ckn.c_str(),
            port_name.c_str(),
            e.what());
        return false;
    }
    return true;
}

bool MACsecMgr::delMKA(
    const std::string & sock,
    const std::string & port_name,
    const std::string & ckn) const
{
    SWSS_LOG_ENTER();

    // Removing an absent CKN is a no-op success.
    bool present = false;
    for (const auto & participant : getMKAParticipants(sock, port_name))
    {
        auto itr = participant.find("ckn");
        if (itr != participant.end() && boost::iequals(itr->second, ckn))
        {
            present = true;
            break;
        }
    }
    if (!present)
    {
        SWSS_LOG_NOTICE(
            "MKA participant CKN '%s' not present on port '%s'; nothing to delete",
            ckn.c_str(),
            port_name.c_str());
        return true;
    }

    try
    {
        wpa_cli_exec_and_check(
            sock,
            port_name,
            "",
            "macsec_del_mka",
            "ckn=" + ckn);
    }
    catch(const std::runtime_error & e)
    {
        SWSS_LOG_WARN(
            "Cannot delete MKA participant CKN '%s' on port '%s' : %s",
            ckn.c_str(),
            port_name.c_str(),
            e.what());
        return false;
    }
    return true;
}

bool MACsecMgr::waitForCKNLive(
    const std::string & sock,
    const std::string & port_name,
    const std::string & ckn,
    std::uint64_t timeout_ms) const
{
    SWSS_LOG_ENTER();

    std::uint64_t elapsed_ms = 0;
    while (true)
    {
        for (const auto & participant : getMKAParticipants(sock, port_name))
        {
            auto ckn_itr = participant.find("ckn");
            if (ckn_itr == participant.end() || !boost::iequals(ckn_itr->second, ckn))
            {
                continue;
            }
            auto peers_itr = participant.find("live_peers");
            if (peers_itr != participant.end())
            {
                try
                {
                    if (std::stoi(peers_itr->second) >= 1)
                    {
                        return true;
                    }
                }
                catch(const std::exception &)
                {
                    // Unparseable count; keep polling until timeout.
                }
            }
        }
        if (elapsed_ms >= timeout_ms)
        {
            return false;
        }
        std::this_thread::sleep_for(
            std::chrono::milliseconds(CKN_CONVERGE_INTERVAL_MS));
        elapsed_ms += CKN_CONVERGE_INTERVAL_MS;
    }
}

bool MACsecMgr::hotUpdateProfile(
    const std::string & port_name,
    MKASession & session,
    const MACsecProfile & old_profile,
    const MACsecProfile & new_profile) const
{
    SWSS_LOG_ENTER();

    const std::string & sock = session.sock;
    bool ok = true;

    // 1. Primary CKN change -> hitless rotation, carried by the fallback CA.
    //    Hitlessness comes from the fallback key already being established, not
    //    from making-before-breaking the primary. Remove the old primary so
    //    wpa_supplicant immediately rides the live fallback CA, then add the new
    //    primary; once it converges wpa prefers it and swaps back, with the
    //    fallback protecting traffic throughout. This keeps at most two CAs on
    //    the port at once (fallback + one primary) and never stages a third.
    //    A rotation therefore requires a fallback to be established: without one
    //    there is nothing to carry traffic during the swap, so refuse it (the
    //    CLI should also reject it at command time).
    //
    //    A same-CKN, CAK-only change cannot be rotated hitlessly: the control
    //    plane keys participants by CKN (a duplicate CKN is rejected by
    //    wpa_supplicant), so there is no distinct second CA to converge and swap
    //    to. That combination takes effect on the next wpa_supplicant restart,
    //    which reloads the primary key material from CONFIG_DB. Warn rather than
    //    silently drop it, and do not tear the live CA down.
    if (old_profile.primary_ckn == new_profile.primary_ckn
        && old_profile.primary_cak != new_profile.primary_cak)
    {
        SWSS_LOG_WARN(
            "Primary MACsec CAK changed on port '%s' without a CKN change; the "
            "new key applies on the next wpa_supplicant restart",
            port_name.c_str());
    }
    else if (old_profile.primary_ckn != new_profile.primary_ckn)
    {
        SWSS_LOG_NOTICE(
            "Rotating primary MACsec CAK on port '%s' (CKN '%s' -> '%s')",
            port_name.c_str(),
            old_profile.primary_ckn.c_str(),
            new_profile.primary_ckn.c_str());

        // The new primary is already an established CA when it is the current
        // fallback being promoted (primary A->B where B was the fallback). It
        // is live, so it can take over as principal with no new negotiation.
        const bool new_primary_already_live =
            !old_profile.fallback_ckn.empty()
            && old_profile.fallback_ckn == new_profile.primary_ckn;

        // A rotation is only hitless if a second, already-established CA (the
        // fallback) is present to carry traffic while the old primary is
        // retired and the new one negotiates. Refuse to rotate without one
        // rather than black-holing traffic. This is the daemon-side guard for
        // direct CONFIG_DB writes; the CLI rejects it at command time too.
        if (!new_primary_already_live && old_profile.fallback_ckn.empty())
        {
            SWSS_LOG_ERROR(
                "Refusing to rotate primary MACsec CAK on port '%s': no fallback "
                "CA is established to carry traffic during the rotation. "
                "Configure a fallback CAK before rotating the primary.",
                port_name.c_str());
            return false;
        }

        // Retire the old primary first. wpa_supplicant carries traffic on the
        // established fallback CA across the gap (this is the hitless step, and
        // it drops the port from two CAs to one before we add the new primary).
        if (!delMKA(sock, port_name, old_profile.primary_ckn))
        {
            ok = false;
        }

        // For a fresh primary key, add it as a real primary (not in the fallback
        // slot) so the port ends with exactly the configured primary + fallback.
        // A promoted fallback is already live, so there is nothing to add. Wait
        // for the new primary to converge so the handoff is orderly before any
        // fallback reconfiguration below; the fallback keeps protecting traffic
        // during the wait, and at no point are more than two CAs established.
        if (!new_primary_already_live)
        {
            if (!addMKA(
                    sock,
                    port_name,
                    new_profile.primary_ckn,
                    decodeKey(new_profile.primary_cak, new_profile.cipher_suite),
                    false))
            {
                SWSS_LOG_ERROR(
                    "Failed to add new primary CKN '%s' on port '%s' after "
                    "retiring the old primary; the port is running on the "
                    "fallback CA only",
                    new_profile.primary_ckn.c_str(),
                    port_name.c_str());
                ok = false;
            }
            else if (!waitForCKNLive(
                        sock,
                        port_name,
                        new_profile.primary_ckn,
                        CKN_CONVERGE_TIMEOUT_MS))
            {
                SWSS_LOG_WARN(
                    "New primary CKN '%s' on port '%s' did not converge with a "
                    "peer within timeout; the port continues on the fallback CA",
                    new_profile.primary_ckn.c_str(),
                    port_name.c_str());
            }
        }
        session.primary_ckn = new_profile.primary_ckn;
    }

    // 2. Fallback CA change. Covers add, remove, CKN change and CAK-only change.
    const bool fallback_ckn_changed =
        old_profile.fallback_ckn != new_profile.fallback_ckn;
    const bool fallback_cak_changed =
        old_profile.fallback_cak != new_profile.fallback_cak;

    if (fallback_ckn_changed)
    {
        // Guard the "swap" reconfiguration where the old fallback CKN is being
        // promoted to primary (e.g. primary A->B, fallback B->C). Section 1 has
        // already made that CKN the live principal, so it must not be deleted
        // here or the datapath would drop.
        if (!old_profile.fallback_ckn.empty()
            && old_profile.fallback_ckn != new_profile.primary_ckn)
        {
            if (!delMKA(sock, port_name, old_profile.fallback_ckn))
            {
                ok = false;
            }
        }
        if (!new_profile.fallback_ckn.empty())
        {
            if (!addMKA(
                    sock,
                    port_name,
                    new_profile.fallback_ckn,
                    decodeKey(new_profile.fallback_cak, new_profile.cipher_suite),
                    true))
            {
                ok = false;
            }
        }
        session.fallback_ckn = new_profile.fallback_ckn;
    }
    else if (!new_profile.fallback_ckn.empty() && fallback_cak_changed)
    {
        // Same fallback CKN but new CAK: re-add to push the new key material.
        if (!delMKA(sock, port_name, new_profile.fallback_ckn))
        {
            ok = false;
        }
        if (!addMKA(
                sock,
                port_name,
                new_profile.fallback_ckn,
                decodeKey(new_profile.fallback_cak, new_profile.cipher_suite),
                true))
        {
            ok = false;
        }
    }

    return ok;
}
