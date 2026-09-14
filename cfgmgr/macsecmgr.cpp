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
#include <ctime>
#include <iomanip>
#include <limits>
#include <set>
#include <thread>
#include <chrono>


using namespace std;
using namespace swss;

#define WPA_SUPPLICANT_CMD "/sbin/wpa_supplicant"
#define WPA_CLI_CMD        "/sbin/wpa_cli"
#define WPA_CONF           "/etc/wpa_supplicant.conf"
#define SOCK_DIR           "/var/run/"
#define TIMEOUT_CMD        "/usr/bin/timeout"

constexpr std::uint64_t RETRY_TIME = 30;

/* retry interval, in millisecond */
constexpr std::uint64_t RETRY_INTERVAL = 100;

/*
 * MKA operational state collection.
 *
 * wpa_supplicant is single threaded and has been observed blocked for the full
 * ctrl interface timeout while it waits on something else. Collection therefore
 * never runs unbounded: every query carries its own deadline, a port is only
 * queried once per tick, one tick refreshes a slice of the ports, and a port
 * that keeps failing backs off. That bounds the worst case cost of a wedged
 * wpa_supplicant to a few seconds per tick instead of the whole port list.
 */
constexpr unsigned int MKA_QUERY_DEADLINE_SEC = 2;
constexpr unsigned int MKA_POLL_INTERVAL_SEC = 5;
constexpr unsigned int MKA_POLL_PORTS_PER_TICK = 4;
constexpr unsigned int MKA_POLL_MAX_BACKOFF = 12;
constexpr std::size_t MKA_MI_HEX_LEN = 24;
constexpr std::size_t MKA_SCI_HEX_LEN = 16;

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
            throw std::invalid_argument(
                "Invalid MACsec key length : " + std::to_string(cipher_str.length())
                + ", expected " + std::to_string(AES_LEN_128_BYTE));
    }
    else if ((cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_256) ||
             (cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_256))
    {
        if (cipher_str.length() != AES_LEN_256_BYTE)
            throw std::invalid_argument(
                "Invalid MACsec key length : " + std::to_string(cipher_str.length())
                + ", expected " + std::to_string(AES_LEN_256_BYTE));
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

// Wpa_cli failures quote the whole command line, so any CAK handed to
// wpa_supplicant has to be scrubbed out before the reason is logged.
static std::string redactSecret(std::string message, const std::string & secret)
{
    static const std::string mask = "<redacted>";

    if (secret.empty())
    {
        return message;
    }

    for (auto pos = message.find(secret);
         pos != std::string::npos;
         pos = message.find(secret, pos + mask.length()))
    {
        message.replace(pos, secret.length(), mask);
    }

    return message;
}

// wpa_cli inherits wpa_supplicant's ctrl interface timeout, which a single
// threaded wpa_supplicant blocked elsewhere will run to the end. Status
// collection therefore goes through its own deadline so one unresponsive port
// cannot hold the daemon.
template<typename...Args>
static std::string wpa_cli_exec_bounded(
    unsigned int deadline_sec,
    const std::string & sock,
    const std::string & port_name,
    const std::string & network_id,
    Args && ... args)
{
    std::ostringstream ostream;
    std::string res;
    ostream << TIMEOUT_CMD << " " << deadline_sec << " ";
    wpa_cli_commands(
        ostream,
        sock,
        port_name,
        network_id,
        std::forward<Args>(args)...);
    EXEC_WITH_ERROR_THROW(ostream.str(), res);
    return res;
}

static const char * boolText(bool value)
{
    return value ? "true" : "false";
}

// wpa_supplicant reports booleans as Yes/No. STATE_DB carries lower case
// true/false, which is what the rest of SONiC expects to read back.
static bool normalizeBool(const std::string & value, bool & result)
{
    if (boost::iequals(value, "yes") || boost::iequals(value, "true"))
    {
        result = true;
        return true;
    }
    if (boost::iequals(value, "no") || boost::iequals(value, "false"))
    {
        result = false;
        return true;
    }
    return false;
}

static bool normalizeUint(const std::string & value, std::uint32_t & result)
{
    if (value.empty())
    {
        return false;
    }
    for (const unsigned char c : value)
    {
        if (!std::isdigit(c))
        {
            return false;
        }
    }

    unsigned long parsed = 0;
    try
    {
        parsed = std::stoul(value);
    }
    catch (const std::exception &)
    {
        return false;
    }
    if (parsed > std::numeric_limits<std::uint32_t>::max())
    {
        return false;
    }
    result = static_cast<std::uint32_t>(parsed);
    return true;
}

// CKNs and MIs are hex strings whose case carries no meaning, but the CKN is the
// participant row key, so both ends have to agree on one spelling.
static bool normalizeHex(const std::string & value, std::string & result)
{
    if (value.empty() || (value.size() % 2) != 0)
    {
        return false;
    }
    result.clear();
    result.reserve(value.size());
    for (const unsigned char c : value)
    {
        if (!std::isxdigit(c))
        {
            return false;
        }
        result.push_back(static_cast<char>(std::tolower(c)));
    }
    return true;
}

// wpa_supplicant renders an SCI as 'xx:xx:xx:xx:xx:xx@port' with the port in
// decimal. STATE_DB carries the 16 hex digit wire form, so the all zero value a
// port holds before key server election normalises rather than failing.
static bool normalizeSci(const std::string & value, std::string & result)
{
    const auto separator = value.find('@');
    if (separator == std::string::npos)
    {
        return false;
    }

    std::string address;
    std::size_t colons = 0;
    for (std::size_t i = 0; i < separator; ++i)
    {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if (c == ':')
        {
            ++colons;
            continue;
        }
        if (!std::isxdigit(c))
        {
            return false;
        }
        address.push_back(static_cast<char>(std::tolower(c)));
    }
    if (colons != 5 || address.size() != MKA_SCI_HEX_LEN - 4)
    {
        return false;
    }

    std::uint32_t port = 0;
    if (!normalizeUint(value.substr(separator + 1), port) || port > 0xffff)
    {
        return false;
    }

    std::ostringstream ostream;
    ostream << address << std::hex << std::setfill('0') << std::setw(4) << port;
    result = ostream.str();
    return true;
}

static std::string utcTimestamp()
{
    const std::time_t now = std::time(nullptr);
    struct tm broken_down;
    char buffer[sizeof("1970-01-01T00:00:00Z")];

    gmtime_r(&now, &broken_down);
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &broken_down);
    return buffer;
}

static std::string participantKey(const std::string & port_name, const std::string & ckn)
{
    return port_name + "|" + ckn;
}

namespace
{

// Field names as wpa_supplicant spells them in a macsec_mka_list response. The
// top level block describes the KaY, then one block per participant, introduced
// by participant_idx, then the producer's completion marker.
const char SNAPSHOT_COMPLETE[] = "snapshot_complete";
const char PARTICIPANT_INDEX[] = "participant_idx";

// Every field the two STATE_DB rows are built from. A snapshot missing any of
// them is not something to publish a partial row from.
const std::set<std::string> REQUIRED_SESSION_FIELDS = {
    "PAE KaY status",
    "Authenticated",
    "Secured",
    "Failed",
    "Actor Priority",
    "Key Server Priority",
    "Is Key Server",
    "Number of Keys Distributed",
    "Number of Keys Received",
    "MKA Hello Time",
    "actor_sci",
    "key_server_sci",
};

const std::set<std::string> REQUIRED_PARTICIPANT_FIELDS = {
    PARTICIPANT_INDEX,
    "ckn",
    "mi",
    "mn",
    "active",
    "participant",
    "retain",
    "is_principal",
    "live_peers",
    "potential_peers",
    "is_key_server",
    "is_elected",
};

std::string missingFields(
    const std::set<std::string> & required,
    const std::set<std::string> & seen)
{
    std::ostringstream ostream;
    for (const auto & field : required)
    {
        if (seen.find(field) == seen.end())
        {
            ostream << (ostream.tellp() > 0 ? ", " : "") << field;
        }
    }
    return ostream.str();
}

}

bool MACsecMgr::parseMKAStatus(
    const std::string & output,
    MKAStatus & status,
    std::string & error)
{
    SWSS_LOG_ENTER();

    status = MKAStatus();

    std::set<std::string> session_fields;
    std::set<std::string> participant_fields;
    std::set<std::string> seen_ckns;
    MKAParticipantStatus participant;
    // The role is carried as either is_fallback or the earlier is_primary
    // spelling. Both are accepted, exactly one meaning has to come out of them.
    bool has_role = false;
    bool complete = false;
    bool in_participant = false;
    unsigned int principals = 0;

    // Close off the participant block being accumulated, if any.
    auto finishParticipant = [&]() -> bool
    {
        if (!in_participant)
        {
            return true;
        }
        const std::string missing = missingFields(REQUIRED_PARTICIPANT_FIELDS, participant_fields);
        if (!missing.empty())
        {
            error = "participant '" + participant.ckn + "' is missing " + missing;
            return false;
        }
        if (!has_role)
        {
            error = "participant '" + participant.ckn + "' has no is_fallback or is_primary";
            return false;
        }
        if (!seen_ckns.insert(participant.ckn).second)
        {
            error = "duplicate CKN '" + participant.ckn + "'";
            return false;
        }
        if (participant.is_principal && ++principals > 1)
        {
            error = "more than one principal participant";
            return false;
        }
        status.participants.push_back(participant);
        participant = MKAParticipantStatus();
        participant_fields.clear();
        has_role = false;
        in_participant = false;
        return true;
    };

    std::istringstream istream(output);
    std::string line;
    while (std::getline(istream, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
        {
            line.pop_back();
        }
        if (line.empty())
        {
            continue;
        }

        const auto separator = line.find('=');
        if (separator == std::string::npos)
        {
            error = "malformed line '" + line + "'";
            return false;
        }
        const std::string field = line.substr(0, separator);
        const std::string value = line.substr(separator + 1);

        // The marker is what tells a truncated response from a shrinking one, so
        // nothing is allowed to follow it.
        if (complete)
        {
            error = "content after " + std::string(SNAPSHOT_COMPLETE);
            return false;
        }
        if (field == SNAPSHOT_COMPLETE)
        {
            if (value != "1")
            {
                error = std::string(SNAPSHOT_COMPLETE) + " is '" + value + "'";
                return false;
            }
            if (!finishParticipant())
            {
                return false;
            }
            complete = true;
            continue;
        }

        if (field == PARTICIPANT_INDEX)
        {
            if (!finishParticipant())
            {
                return false;
            }
            in_participant = true;
        }

        std::set<std::string> & fields = in_participant ? participant_fields : session_fields;
        if (!fields.insert(field).second)
        {
            error = "duplicate field '" + field + "'";
            return false;
        }

        bool parsed = true;
        if (!in_participant)
        {
            if (field == "PAE KaY status")
            {
                if (!boost::iequals(value, "Active") && !boost::iequals(value, "Not-Active"))
                {
                    error = "unknown KaY status '" + value + "'";
                    return false;
                }
                status.kay_status = boost::iequals(value, "Active") ? "active" : "not-active";
            }
            else if (field == "Authenticated")               { parsed = normalizeBool(value, status.authenticated); }
            else if (field == "Secured")                     { parsed = normalizeBool(value, status.secured); }
            else if (field == "Failed")                      { parsed = normalizeBool(value, status.failed); }
            else if (field == "Actor Priority")              { parsed = normalizeUint(value, status.actor_priority); }
            else if (field == "Key Server Priority")         { parsed = normalizeUint(value, status.key_server_priority); }
            else if (field == "Is Key Server")               { parsed = normalizeBool(value, status.is_key_server); }
            else if (field == "Number of Keys Distributed")  { parsed = normalizeUint(value, status.keys_distributed); }
            else if (field == "Number of Keys Received")     { parsed = normalizeUint(value, status.keys_received); }
            else if (field == "MKA Hello Time")              { parsed = normalizeUint(value, status.mka_hello_time_ms); }
            else if (field == "actor_sci")                   { parsed = normalizeSci(value, status.actor_sci); }
            else if (field == "key_server_sci")              { parsed = normalizeSci(value, status.key_server_sci); }
            else
            {
                // A newer wpa_supplicant reporting more than this build knows
                // about is not a reason to drop the snapshot.
                SWSS_LOG_DEBUG("Ignoring unknown MKA status field '%s'", field.c_str());
                fields.erase(field);
            }
        }
        else if (field == PARTICIPANT_INDEX) { parsed = normalizeUint(value, participant.participant_index); }
        else if (field == "ckn")             { parsed = normalizeHex(value, participant.ckn); }
        else if (field == "mi")
        {
            parsed = normalizeHex(value, participant.mi) && participant.mi.size() == MKA_MI_HEX_LEN;
        }
        else if (field == "mn")              { parsed = normalizeUint(value, participant.mn); }
        else if (field == "active")          { parsed = normalizeBool(value, participant.active); }
        else if (field == "participant")     { parsed = normalizeBool(value, participant.participant); }
        else if (field == "retain")          { parsed = normalizeBool(value, participant.retain); }
        else if (field == "is_principal")    { parsed = normalizeBool(value, participant.is_principal); }
        else if (field == "live_peers")      { parsed = normalizeUint(value, participant.live_peers); }
        else if (field == "potential_peers") { parsed = normalizeUint(value, participant.potential_peers); }
        else if (field == "is_key_server")   { parsed = normalizeBool(value, participant.is_key_server); }
        else if (field == "is_elected")      { parsed = normalizeBool(value, participant.is_elected); }
        else if (field == "is_fallback" || field == "is_primary")
        {
            bool role = false;
            parsed = normalizeBool(value, role);
            if (parsed)
            {
                // is_primary is the inverse of is_fallback. Carrying both is only
                // acceptable while they say the same thing.
                const bool is_fallback = (field == "is_primary") ? !role : role;
                if (has_role && participant.is_fallback != is_fallback)
                {
                    error = "conflicting is_fallback and is_primary";
                    return false;
                }
                participant.is_fallback = is_fallback;
                has_role = true;
            }
        }
        else
        {
            SWSS_LOG_DEBUG("Ignoring unknown MKA participant field '%s'", field.c_str());
            fields.erase(field);
        }

        if (!parsed)
        {
            error = "cannot convert field '" + field + "' value '" + value + "'";
            return false;
        }
    }

    if (!complete)
    {
        // Truncation at a participant boundary is otherwise indistinguishable
        // from a participant having gone away, and would delete a live row.
        error = "no " + std::string(SNAPSHOT_COMPLETE) + " marker";
        return false;
    }

    const std::string missing = missingFields(REQUIRED_SESSION_FIELDS, session_fields);
    if (!missing.empty())
    {
        error = "snapshot is missing " + missing;
        return false;
    }

    return true;
}

MACsecMgr::MACsecMgr(
    DBConnector *cfgDb,
    DBConnector *stateDb,
    const vector<std::string> &tables) :
        Orch(cfgDb, tables),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME),
        m_stateMkaSessionTable(stateDb, STATE_MACSEC_MKA_SESSION_TABLE_NAME),
        m_stateMkaParticipantTable(stateDb, STATE_MACSEC_MKA_PARTICIPANT_TABLE_NAME)
{
    SWSS_LOG_ENTER();

    // Rows surviving a macsecmgrd restart describe a KaY this process has not
    // queried yet. Mark them unverified so they are not read as current; the
    // first successful refresh replaces them, and an enable clears them.
    std::vector<std::string> keys;
    m_stateMkaSessionTable.getKeys(keys);
    for (const auto & key : keys)
    {
        m_stateMkaSessionTable.hset(key, "query_status", "error");
    }

    auto interval = timespec { .tv_sec = MKA_POLL_INTERVAL_SEC, .tv_nsec = 0 };
    m_mka_poll_timer = new SelectableTimer(interval);
    Orch::addExecutor(new ExecutableTimer(m_mka_poll_timer, this, "MACSEC_MKA_POLL"));
    m_mka_poll_timer->start();
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

void MACsecMgr::doTask(SelectableTimer &)
{
    SWSS_LOG_ENTER();

    if (m_macsec_ports.empty())
    {
        return;
    }

    // Walk the ports round robin and stop once this tick has refreshed its slice
    // or spent its time budget, so a port that hangs delays the ports behind it
    // by one tick instead of holding the whole daemon.
    auto itr = m_macsec_ports.lower_bound(m_mka_poll_cursor);
    if (itr == m_macsec_ports.end())
    {
        itr = m_macsec_ports.begin();
    }

    const auto started = std::chrono::steady_clock::now();
    unsigned int refreshed = 0;
    for (std::size_t visited = 0;
         visited < m_macsec_ports.size() && refreshed < MKA_POLL_PORTS_PER_TICK;
         ++visited)
    {
        if (itr->second.poll_backoff > 0)
        {
            --itr->second.poll_backoff;
        }
        else
        {
            refreshMKAStatus(itr->first, itr->second);
            ++refreshed;
        }

        if (++itr == m_macsec_ports.end())
        {
            itr = m_macsec_ports.begin();
        }

        if (std::chrono::steady_clock::now() - started >=
            std::chrono::seconds(MKA_QUERY_DEADLINE_SEC))
        {
            break;
        }
    }

    m_mka_poll_cursor = itr->first;
}

bool MACsecMgr::queryMKAStatus(
    const MKASession & session,
    const std::string & port_name,
    MKAStatus & status) const
{
    SWSS_LOG_ENTER();

    std::string output;
    try
    {
        output = wpa_cli_exec_bounded(
            MKA_QUERY_DEADLINE_SEC,
            session.sock,
            port_name,
            "",
            "macsec_mka_list");
    }
    catch (const std::exception & e)
    {
        SWSS_LOG_WARN(
            "Cannot collect the MKA status of the port '%s' : %s",
            port_name.c_str(),
            e.what());
        return false;
    }

    std::string error;
    if (!parseMKAStatus(output, status, error))
    {
        SWSS_LOG_WARN(
            "Rejecting the MKA status snapshot of the port '%s' : %s",
            port_name.c_str(),
            error.c_str());
        return false;
    }

    return true;
}

void MACsecMgr::refreshMKAStatus(const std::string & port_name, MKASession & session)
{
    SWSS_LOG_ENTER();

    MKAStatus status;
    if (!queryMKAStatus(session, port_name, status))
    {
        publishMKAQueryFailure(port_name, session);
        if (session.query_failures < MKA_POLL_MAX_BACKOFF)
        {
            session.query_failures++;
        }
        session.poll_backoff = session.query_failures;
        return;
    }

    publishMKAStatus(port_name, session, status);
    session.query_failures = 0;
    session.poll_backoff = 0;
}

void MACsecMgr::publishMKAStatus(
    const std::string & port_name,
    MKASession & session,
    const MKAStatus & status)
{
    SWSS_LOG_ENTER();

    m_stateMkaSessionTable.set(port_name, std::vector<FieldValueTuple>(
    {
        { "profile",             session.profile_name },
        { "kay_status",          status.kay_status },
        { "authenticated",       boolText(status.authenticated) },
        { "secured",             boolText(status.secured) },
        { "failed",              boolText(status.failed) },
        { "actor_sci",           status.actor_sci },
        { "key_server_sci",      status.key_server_sci },
        { "actor_priority",      std::to_string(status.actor_priority) },
        { "key_server_priority", std::to_string(status.key_server_priority) },
        { "is_key_server",       boolText(status.is_key_server) },
        { "keys_distributed",    std::to_string(status.keys_distributed) },
        { "keys_received",       std::to_string(status.keys_received) },
        { "mka_hello_time_ms",   std::to_string(status.mka_hello_time_ms) },
        { "query_status",        "ok" },
        { "last_updated",        utcTimestamp() },
    }));

    std::set<std::string> published;
    for (const auto & participant : status.participants)
    {
        m_stateMkaParticipantTable.set(
            participantKey(port_name, participant.ckn),
            std::vector<FieldValueTuple>(
        {
            { "participant_index", std::to_string(participant.participant_index) },
            { "mi",                participant.mi },
            { "mn",                std::to_string(participant.mn) },
            { "active",            boolText(participant.active) },
            { "participant",       boolText(participant.participant) },
            { "retain",            boolText(participant.retain) },
            { "is_principal",      boolText(participant.is_principal) },
            { "is_fallback",       boolText(participant.is_fallback) },
            { "live_peers",        std::to_string(participant.live_peers) },
            { "potential_peers",   std::to_string(participant.potential_peers) },
            { "is_key_server",     boolText(participant.is_key_server) },
            { "is_elected",        boolText(participant.is_elected) },
        }));
        published.insert(participant.ckn);
    }

    // The snapshot passed every validation, so it is the whole participant list:
    // a CKN it does not carry no longer exists on the KaY.
    for (const auto & ckn : session.published_ckns)
    {
        if (published.find(ckn) == published.end())
        {
            m_stateMkaParticipantTable.del(participantKey(port_name, ckn));
        }
    }

    session.published_ckns = std::move(published);
    session.has_published_snapshot = true;
}

void MACsecMgr::publishMKAQueryFailure(const std::string & port_name, MKASession & session)
{
    SWSS_LOG_ENTER();

    if (session.has_published_snapshot)
    {
        // A failed query says nothing about the KaY, only about reaching it, so
        // the last known state is kept and only its freshness is flagged.
        // last_updated deliberately stays at the last successful collection.
        m_stateMkaSessionTable.hset(port_name, "query_status", "error");
        return;
    }

    // Nothing has ever been collected for this port. Publishing zeroes and empty
    // SCIs here would be indistinguishable from a real idle KaY, so only what is
    // actually known is published, and last_updated stays absent.
    m_stateMkaSessionTable.set(port_name, std::vector<FieldValueTuple>(
    {
        { "profile",      session.profile_name },
        { "query_status", "error" },
    }));
}

void MACsecMgr::clearMKAStatus(const std::string & port_name, MKASession & session)
{
    SWSS_LOG_ENTER();

    m_stateMkaSessionTable.del(port_name);

    // Scan rather than walk published_ckns, so rows left behind by a previous
    // macsecmgrd go with the ones this process published.
    const std::string prefix = port_name + "|";
    std::vector<std::string> keys;
    m_stateMkaParticipantTable.getKeys(keys);
    for (const auto & key : keys)
    {
        if (boost::starts_with(key, prefix))
        {
            m_stateMkaParticipantTable.del(key);
        }
    }

    session.published_ckns.clear();
    session.has_published_snapshot = false;
    session.query_failures = 0;
    session.poll_backoff = 0;
}

#define GetValue(args, name) (get_value(args, #name, name))

bool MACsecMgr::MACsecProfile::update(const TaskArgs & ta)
{
    SWSS_LOG_ENTER();

    // The following fields are optional. Clear them first: update() mutates the
    // stored profile in place, so an entry that no longer carries them (an
    // operator HDEL of fallback_cak/fallback_ckn) must not retain the old key.
    fallback_cak.clear();
    fallback_ckn.clear();
    // Both halves are read before either is judged, so that a CKN without a CAK
    // is rejected rather than quietly dropped along with the fallback.
    const bool has_fallback_cak = GetValue(ta, fallback_cak);
    const bool has_fallback_ckn = GetValue(ta, fallback_ckn);
    if (has_fallback_cak != has_fallback_ckn)
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

    // Validate into a local profile so an invalid update leaves the profile
    // currently applied to the ports untouched.
    MACsecProfile new_profile;
    try
    {
        if (!new_profile.update(profile_attr))
        {
            SWSS_LOG_WARN(
                "The MACsec profile '%s' is incomplete; rejecting the profile",
                profile_name.c_str());
            return task_invalid_entry;
        }
        SWSS_LOG_NOTICE(
            "The MACsec profile '%s' is loaded",
            profile_name.c_str());

        // The YANG model rejects this too; guard direct CONFIG_DB writes that bypass it.
        if (!new_profile.fallback_ckn.empty()
            && boost::iequals(new_profile.fallback_ckn, new_profile.primary_ckn))
        {
            SWSS_LOG_WARN(
                "The MACsec profile '%s' has a fallback CKN equal to its "
                "primary CKN; rejecting the profile",
                profile_name.c_str());
            return task_failed;
        }

        // decodeKey() is the only check on the CAK length and reports a bad key
        // by throwing. Run it here so a malformed key is rejected before the
        // profile is committed or any live MKA session is touched below.
        decodeKey(new_profile.primary_cak, new_profile.cipher_suite);
        if (!new_profile.fallback_ckn.empty())
        {
            decodeKey(new_profile.fallback_cak, new_profile.cipher_suite);
        }

        m_profiles[profile_name] = new_profile;

        // Drive the change onto every port already running this profile at run
        // time instead of restarting its MKA session.
        task_process_status status = task_success;
        for (auto & port : m_macsec_ports)
        {
            if (port.second.profile_name != profile_name)
            {
                continue;
            }
            SWSS_LOG_NOTICE(
                "Hot-updating MACsec profile '%s' on port '%s'",
                profile_name.c_str(),
                port.first.c_str());
            if (!hotUpdateProfile(port.first, port.second, new_profile))
            {
                SWSS_LOG_WARN(
                    "Hot-update of MACsec profile '%s' on port '%s' failed",
                    profile_name.c_str(),
                    port.first.c_str());
                status = task_need_retry;
            }
        }
        return status;
    }
    // The CAKs are validated above before anything is committed, so this only
    // backstops the decodeKey() calls made while applying the profile.
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
    // Drop anything a previous macsecmgrd published for this port before the new
    // KaY starts reporting, so no row outlives the session it described.
    clearMKAStatus(port_name, session);
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
        // Report the load failure, not whether the rollback succeeded.
        disableMACsec(port_name, port_attr);
        return task_failed;
    }
    SWSS_LOG_NOTICE("The MACsec profile '%s' on the port '%s' loading success",
        profile_name.c_str(),
        port_name.c_str());
    refreshMKAStatus(port_name, session);
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
    // The session is going away either way, so the rows describing it go too,
    // rather than lingering as state no refresh will ever correct.
    clearMKAStatus(port_name, session);
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
    MKASession & session,
    const MACsecProfile & profile) const
{
    SWSS_LOG_ENTER();

    const std::string primary_cak =
        decodeKey(profile.primary_cak, profile.cipher_suite);

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
            primary_cak);

        wpa_cli_exec_and_check(
            session.sock,
            port_name,
            network_id,
            "mka_ckn",
            profile.primary_ckn);

        bool fallback_configured = false;

        if (!profile.fallback_ckn.empty())
        {
            const std::string fallback_cak =
                decodeKey(profile.fallback_cak, profile.cipher_suite);

            try
            {
                wpa_cli_exec_and_check(
                    session.sock,
                    port_name,
                    network_id,
                    "mka_cak_fallback",
                    fallback_cak);

                wpa_cli_exec_and_check(
                    session.sock,
                    port_name,
                    network_id,
                    "mka_ckn_fallback",
                    profile.fallback_ckn);

                fallback_configured = true;
            }
            catch(const std::runtime_error & e)
            {
                SWSS_LOG_WARN(
                    "Cannot set the fallback CA on port '%s', the port stays "
                    "protected by the primary CA alone : %s",
                    port_name.c_str(),
                    redactSecret(e.what(), fallback_cak).c_str());
            }
        }

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

        // Record only what was actually applied to the port.
        session.network_id = network_id;
        session.primary_cak = profile.primary_cak;
        session.primary_ckn = profile.primary_ckn;

        if (fallback_configured)
        {
            session.fallback_cak = profile.fallback_cak;
            session.fallback_ckn = profile.fallback_ckn;
        }
    }
    catch(const std::runtime_error & e)
    {
        SWSS_LOG_WARN("Enable MACsec fail : %s",
            redactSecret(e.what(), primary_cak).c_str());
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

boost::optional<std::vector<MACsecMgr::MKAParticipant>> MACsecMgr::getMKAParticipants(
    const std::string & sock,
    const std::string & port_name) const
{
    SWSS_LOG_ENTER();

    std::vector<MKAParticipant> participants;

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
        return boost::none;
    }

    // A rejected command answers on the socket but carries no status, so it
    // must not be read as a port with nothing running on it.
    if (output.rfind("FAIL", 0) == 0)
    {
        SWSS_LOG_WARN(
            "Cannot query MKA participants on port '%s' : the request was rejected",
            port_name.c_str());
        return boost::none;
    }

    // macsec_mka_list emits top-level 'key=value' fields followed by one block
    // per participant, each starting at 'participant_idx'. Fields before the
    // first block belong to the KaY and are ignored here.
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line))
    {
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
        {
            line.pop_back();
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
        }
        else if (participants.empty())
        {
            continue;
        }
        else if (key == "ckn")
        {
            participants.back().ckn = value;
        }
        else if (key == "is_primary")
        {
            participants.back().fallback = !boost::iequals(value, "yes");
        }
    }

    return participants;
}

const MACsecMgr::MKAParticipant * MACsecMgr::findParticipant(
    const std::vector<MKAParticipant> & participants,
    const std::string & ckn)
{
    // wpa_supplicant reports the CKN as lower-case hex, CONFIG_DB may hold either case.
    auto itr = std::find_if(
        participants.begin(),
        participants.end(),
        [&](const MKAParticipant & participant)
        {
            return boost::iequals(participant.ckn, ckn);
        });
    return itr != participants.end() ? &(*itr) : nullptr;
}

bool MACsecMgr::addMKA(
    const std::string & sock,
    const std::string & port_name,
    const std::string & ckn,
    const std::string & cak,
    bool fallback) const
{
    SWSS_LOG_ENTER();

    // Held by value: findParticipant returns a pointer into this vector, so it
    // has to outlive the pointer.
    const auto participants = getMKAParticipants(sock, port_name);
    if (!participants)
    {
        SWSS_LOG_WARN(
            "Cannot add MKA participant CKN '%s' on port '%s' : the participants "
            "already present could not be queried",
            ckn.c_str(),
            port_name.c_str());
        return false;
    }

    const auto * present = findParticipant(*participants, ckn);
    if (present != nullptr)
    {
        // Already in the requested role, so there is nothing to do. In the other
        // role it has to be recreated, because the role is fixed at creation.
        if (present->fallback == fallback)
        {
            SWSS_LOG_NOTICE(
                "MKA participant CKN '%s' already present on port '%s'",
                ckn.c_str(),
                port_name.c_str());
            return true;
        }
        SWSS_LOG_WARN(
            "MKA participant CKN '%s' on port '%s' is being recreated to change "
            "role; the port is unprotected until it converges again",
            ckn.c_str(),
            port_name.c_str());
        if (!delMKA(sock, port_name, ckn))
        {
            return false;
        }
    }

    try
    {
        wpa_cli_exec_and_check(
            sock,
            port_name,
            "",
            "macsec_add_mka",
            "ckn=" + ckn,
            "cak=" + cak,
            std::string("fallback=") + (fallback ? "1" : "0"));
    }
    catch(const std::runtime_error & e)
    {
        SWSS_LOG_WARN(
            "Cannot add MKA participant CKN '%s' on port '%s' : %s",
            ckn.c_str(),
            port_name.c_str(),
            redactSecret(e.what(), cak).c_str());
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

    const auto participants = getMKAParticipants(sock, port_name);
    if (!participants)
    {
        // An unreachable ctrl interface says nothing about what is running
        // behind it. Reporting the delete as done here would let a rotation
        // continue over a participant that is still live.
        SWSS_LOG_WARN(
            "Cannot delete MKA participant CKN '%s' on port '%s' : the "
            "participants present could not be queried",
            ckn.c_str(),
            port_name.c_str());
        return false;
    }

    if (findParticipant(*participants, ckn) == nullptr)
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

bool MACsecMgr::hotUpdateProfile(
    const std::string & port_name,
    MKASession & session,
    const MACsecProfile & profile)
{
    SWSS_LOG_ENTER();

    const std::string & sock = session.sock;

    // Rotate the primary CA. wpa_supplicant falls back to the standby CA for as
    // long as the port has no live primary, so the old primary is retired before
    // the new one is added and no third CA is ever staged.
    if (!boost::iequals(session.primary_ckn, profile.primary_ckn))
    {
        if (session.fallback_ckn.empty())
        {
            SWSS_LOG_ERROR(
                "Refusing to rotate the primary MACsec CAK on port '%s': no "
                "fallback CA is established to carry traffic during the rotation",
                port_name.c_str());
            return false;
        }

        SWSS_LOG_NOTICE(
            "Rotating the primary MACsec CAK on port '%s' (CKN '%s' -> '%s')",
            port_name.c_str(),
            session.primary_ckn.c_str(),
            profile.primary_ckn.c_str());

        // Stop before touching the fallback below: leaving the old primary in
        // place and then retiring the standby would strand the port.
        if (!delMKA(sock, port_name, session.primary_ckn))
        {
            return false;
        }
        session.primary_ckn.clear();
        session.primary_cak.clear();
        // Republish between the two halves of the rotation: while the port is on
        // the fallback CA alone, that is the state an operator needs to see.
        refreshMKAStatus(port_name, session);

        if (!addMKA(
                sock,
                port_name,
                profile.primary_ckn,
                decodeKey(profile.primary_cak, profile.cipher_suite),
                false))
        {
            SWSS_LOG_ERROR(
                "Failed to add the new primary CKN '%s' on port '%s'; the port "
                "is running on the fallback CA only",
                profile.primary_ckn.c_str(),
                port_name.c_str());
            refreshMKAStatus(port_name, session);
            return false;
        }
        session.primary_ckn = profile.primary_ckn;
        session.primary_cak = profile.primary_cak;
        refreshMKAStatus(port_name, session);
        // The new primary may have taken over the CKN the fallback was holding,
        // in which case the port no longer has a standby CA to reconcile below.
        if (boost::iequals(session.fallback_ckn, profile.primary_ckn))
        {
            session.fallback_ckn.clear();
            session.fallback_cak.clear();
        }
    }
    else if (session.primary_cak != profile.primary_cak)
    {
        // A participant is keyed by CKN, so the same CKN cannot hold two CAs and
        // there is nothing to rotate through. Leave the live CA alone; the new
        // key is picked up from CONFIG_DB on the next wpa_supplicant restart.
        SWSS_LOG_WARN(
            "The primary MACsec CAK changed on port '%s' without a CKN change; "
            "the new key applies on the next wpa_supplicant restart",
            port_name.c_str());
    }

    // Reconcile the fallback CA.
    const bool fallback_changed =
        !boost::iequals(session.fallback_ckn, profile.fallback_ckn)
        || session.fallback_cak != profile.fallback_cak;
    if (!fallback_changed)
    {
        return true;
    }

    bool ok = true;
    // Always retire the old participant: a CAK-only change still needs it
    // recreated, because the key is fixed at creation.
    if (!session.fallback_ckn.empty()
        && !delMKA(sock, port_name, session.fallback_ckn))
    {
        ok = false;
    }
    session.fallback_ckn.clear();
    session.fallback_cak.clear();

    if (!profile.fallback_ckn.empty())
    {
        if (addMKA(
                sock,
                port_name,
                profile.fallback_ckn,
                decodeKey(profile.fallback_cak, profile.cipher_suite),
                true))
        {
            session.fallback_ckn = profile.fallback_ckn;
            session.fallback_cak = profile.fallback_cak;
        }
        else
        {
            ok = false;
        }
    }

    refreshMKAStatus(port_name, session);
    return ok;
}
