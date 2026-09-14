#include "gtest/gtest.h"
#include "../mock_table.h"
#include "macsecmgr.h"

#include <dlfcn.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <memory>
#include <string>
#include <vector>

extern int (*callback)(const std::string &cmd, std::string &stdout);

namespace macsecmgr_ut
{
    // A fake wpa_supplicant: the participants that the MKA session currently
    // holds, keyed by CKN, in the order macsec_mka_list would report them.
    struct FakeParticipant
    {
        std::string ckn;
        std::string cak;
        bool        fallback = false;
    };

    static std::vector<FakeParticipant> g_participants;
    static std::vector<std::string> g_commands;
    // Commands matching this substring fail, to exercise the error paths.
    static std::string g_failing_command;
    // When set, macsec_mka_list replies with this verbatim instead of a
    // rendered snapshot, so a test can hand the parser a specific response.
    static std::string g_mka_list_override;
    // Whether the rendered snapshot carries the producer's completion marker.
    static bool g_snapshot_complete = true;
    // Live peer count reported for every rendered participant.
    static unsigned int g_live_peers = 1;

    static const pid_t FAKE_WPA_SUPPLICANT_PID = 4242;

    static std::vector<std::string> commandsMatching(const std::string & needle)
    {
        std::vector<std::string> matches;
        for (const auto & cmd : g_commands)
        {
            if (cmd.find(needle) != std::string::npos)
            {
                matches.push_back(cmd);
            }
        }
        return matches;
    }

    static size_t countCommands(const std::string & needle)
    {
        return commandsMatching(needle).size();
    }

    // Extract the value of a space delimited 'key=value' argument. wpa_cli
    // arguments are emitted unquoted, so a value runs to the next space.
    static std::string argValue(const std::string & cmd, const std::string & key)
    {
        auto pos = cmd.find(" " + key + "=");
        if (pos == std::string::npos)
        {
            return "";
        }
        pos += key.size() + 2;
        auto end = cmd.find(' ', pos);
        return cmd.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    }

    // Extract the value that follows a 'set_network <id> <field>' keyword.
    static std::string setNetworkValue(const std::string & cmd, const std::string & field)
    {
        auto pos = cmd.find(" " + field + " ");
        if (pos == std::string::npos)
        {
            return "";
        }
        pos += field.size() + 2;
        auto end = cmd.find(' ', pos);
        return cmd.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    }

    static std::string toLower(const std::string & value)
    {
        std::string out = value;
        std::transform(
            out.begin(),
            out.end(),
            out.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    // wpa_supplicant keys a participant by the decoded CKN bytes, so the hex
    // spelling matches regardless of case.
    static std::vector<FakeParticipant>::iterator findFakeParticipantItr(
        const std::string & ckn)
    {
        return std::find_if(
            g_participants.begin(),
            g_participants.end(),
            [&](const FakeParticipant & p)
            {
                return toLower(p.ckn) == toLower(ckn);
            });
    }

    static const FakeParticipant * findFakeParticipant(const std::string & ckn)
    {
        auto itr = findFakeParticipantItr(ckn);
        return itr != g_participants.end() ? &(*itr) : nullptr;
    }

    // Render the reply of MACSEC_MKA_LIST exactly as ieee802_1x_kay_get_status
    // does: KaY level fields, then one block per participant, then the marker
    // that says the reply was not truncated. Note that the booleans are
    // reported capitalised, and sci_txt() renders an SCI as MAC@port with the
    // port in decimal.
    static std::string renderMKAList()
    {
        std::string out =
            "PAE KaY status=Active\n"
            "Authenticated=Yes\n"
            "Secured=Yes\n"
            "Failed=No\n"
            "Actor Priority=255\n"
            "Key Server Priority=255\n"
            "Is Key Server=Yes\n"
            "Number of Keys Distributed=0\n"
            "Number of Keys Received=0\n"
            "MKA Hello Time=2000\n"
            "actor_sci=52:54:00:12:34:56@1\n"
            "key_server_sci=52:54:00:ab:cd:ef@1\n";
        int idx = 0;
        for (const auto & p : g_participants)
        {
            out += "participant_idx=" + std::to_string(idx++) + "\n";
            // wpa_snprintf_hex renders the CKN in lower case, whatever case
            // CONFIG_DB used.
            out += "ckn=" + toLower(p.ckn) + "\n";
            out += "mi=0a1b2c3d4e5f60718293a4b5\n";
            out += "mn=42\n";
            out += "active=Yes\n";
            out += "participant=Yes\n";
            out += "retain=No\n";
            out += std::string("is_principal=") + (p.fallback ? "No" : "Yes") + "\n";
            out += std::string("is_primary=") + (p.fallback ? "No" : "Yes") + "\n";
            out += "live_peers=" + std::to_string(g_live_peers) + "\n";
            out += "potential_peers=0\n";
            out += "is_key_server=Yes\n";
            out += "is_elected=Yes\n";
        }
        if (g_snapshot_complete)
        {
            out += "snapshot_complete=1\n";
        }
        return out;
    }

    static int fakeWpaCli(const std::string & cmd, std::string & stdout_content)
    {
        g_commands.push_back(cmd);

        if (!g_failing_command.empty()
            && cmd.find(g_failing_command) != std::string::npos)
        {
            stdout_content = "FAIL\n";
            return 0;
        }

        if (cmd.find("add_network") != std::string::npos)
        {
            stdout_content = "0\n";
            return 0;
        }

        if (cmd.find("macsec_mka_list") != std::string::npos)
        {
            stdout_content = g_mka_list_override.empty()
                ? renderMKAList()
                : g_mka_list_override;
            return 0;
        }

        if (cmd.find("macsec_add_mka") != std::string::npos)
        {
            const std::string ckn = argValue(cmd, "ckn");
            // wpa_supplicant keys a participant by CKN and rejects a duplicate.
            if (findFakeParticipant(ckn) != nullptr)
            {
                stdout_content = "FAIL\n";
                return 0;
            }
            g_participants.push_back(
                { ckn,
                  argValue(cmd, "cak"),
                  cmd.find(" fallback=1") != std::string::npos });
            stdout_content = "OK\n";
            return 0;
        }

        if (cmd.find("macsec_del_mka") != std::string::npos)
        {
            auto itr = findFakeParticipantItr(argValue(cmd, "ckn"));
            if (itr == g_participants.end())
            {
                stdout_content = "FAIL\n";
                return 0;
            }
            g_participants.erase(itr);
            stdout_content = "OK\n";
            return 0;
        }

        // The CAs are loaded through the network block, so an enable_network
        // commits whatever mka_ckn/mka_cak and their fallback counterparts were
        // staged. A rejected set_network stages nothing.
        if (cmd.find("enable_network") != std::string::npos)
        {
            std::string ckn;
            std::string cak;
            std::string fallback_ckn;
            std::string fallback_cak;
            for (const auto & prev : g_commands)
            {
                if (!g_failing_command.empty()
                    && prev.find(g_failing_command) != std::string::npos)
                {
                    continue;
                }
                if (prev.find(" mka_ckn ") != std::string::npos)
                {
                    ckn = setNetworkValue(prev, "mka_ckn");
                }
                if (prev.find(" mka_cak ") != std::string::npos)
                {
                    cak = setNetworkValue(prev, "mka_cak");
                }
                if (prev.find(" mka_ckn_fallback ") != std::string::npos)
                {
                    fallback_ckn = setNetworkValue(prev, "mka_ckn_fallback");
                }
                if (prev.find(" mka_cak_fallback ") != std::string::npos)
                {
                    fallback_cak = setNetworkValue(prev, "mka_cak_fallback");
                }
            }
            if (!ckn.empty())
            {
                g_participants.push_back({ ckn, cak, false });
            }
            // wpa_supplicant ignores the fallback unless both halves are set.
            if (!fallback_ckn.empty() && !fallback_cak.empty())
            {
                g_participants.push_back({ fallback_ckn, fallback_cak, true });
            }
            stdout_content = "OK\n";
            return 0;
        }

        stdout_content = "OK\n";
        return 0;
    }
}

// wpa_supplicant is never really spawned: fork()/kill()/waitpid() are
// interposed so the manager sees a healthy child process.
extern "C"
{
    pid_t fork(void)
    {
        return macsecmgr_ut::FAKE_WPA_SUPPLICANT_PID;
    }

    int kill(pid_t pid, int sig)
    {
        if (pid == macsecmgr_ut::FAKE_WPA_SUPPLICANT_PID)
        {
            return 0;
        }
        static int (*real_kill)(pid_t, int) =
            (int (*)(pid_t, int))(dlsym(RTLD_NEXT, "kill"));
        return real_kill(pid, sig);
    }

    pid_t waitpid(pid_t pid, int *status, int options)
    {
        if (pid == macsecmgr_ut::FAKE_WPA_SUPPLICANT_PID)
        {
            if (status != nullptr)
            {
                *status = 0;
            }
            return pid;
        }
        static pid_t (*real_waitpid)(pid_t, int *, int) =
            (pid_t (*)(pid_t, int *, int))(dlsym(RTLD_NEXT, "waitpid"));
        return real_waitpid(pid, status, options);
    }
}

namespace macsecmgr_ut
{
    // CAKs are stored encoded in CONFIG_DB: a 2-digit salt index followed by
    // the hex of the key XORed with the magic salt. Only the length and the
    // hex alphabet matter here, the values are arbitrary.
    static const char * CAK_PRIMARY_A   = "0103140d560a14166c4d030a180e5a425a5e577e7e727f6b6c2311041206074e41";
    static const char * CAK_PRIMARY_B   = "0103140d560a14166c4e030a180e5a425a5e577e7e727f6b6c2311041206074e41";
    static const char * CAK_FALLBACK_A  = "011507085709070c2a014f441a041c5f5b5d56797f717e646d7b12051507044e41";
    static const char * CAK_FALLBACK_B  = "011507085709070c2a014c441a041c5f5b5d56797f717e646d7b12051507044e41";

    // The plaintext each of the CAKs above decodes to, which is what actually
    // reaches wpa_supplicant.
    static const char * DECODED_CAK_PRIMARY_A  = "primary-a-cak-0123456789abcdefxx";
    static const char * DECODED_CAK_PRIMARY_B  = "primary-b-cak-0123456789abcdefxx";
    static const char * DECODED_CAK_FALLBACK_A = "fallback-a-cak-0123456789abcdexx";
    static const char * DECODED_CAK_FALLBACK_B = "fallback-b-cak-0123456789abcdexx";

    static const char * CKN_PRIMARY_A  = "aaaa1111";
    static const char * CKN_PRIMARY_B  = "bbbb2222";
    static const char * CKN_FALLBACK_A = "cccc3333";
    static const char * CKN_FALLBACK_B = "dddd4444";

    static const char * PORT_NAME    = "Ethernet0";
    static const char * PROFILE_NAME = "test_profile";

    struct MACsecMgrTest : public ::testing::Test
    {
        std::shared_ptr<swss::DBConnector> m_config_db;
        std::shared_ptr<swss::DBConnector> m_state_db;
        std::vector<std::string> cfg_macsec_tables;

        virtual void SetUp() override
        {
            testing_db::reset();
            m_config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
            m_state_db = std::make_shared<swss::DBConnector>("STATE_DB", 0);

            cfg_macsec_tables = {
                CFG_MACSEC_PROFILE_TABLE_NAME,
                CFG_PORT_TABLE_NAME
            };

            g_participants.clear();
            g_commands.clear();
            g_failing_command.clear();
            g_mka_list_override.clear();
            g_snapshot_complete = true;
            g_live_peers = 1;
            callback = fakeWpaCli;
        }

        virtual void TearDown() override
        {
            callback = NULL;
        }

        // Mark the port operationally ready so enableMACsec proceeds.
        void setPortStateOk(const std::string & port_name)
        {
            swss::Table state_port_table(m_state_db.get(), STATE_PORT_TABLE_NAME);
            state_port_table.set(
                port_name,
                { { "state", "ok" }, { "netdev_oper_status", "up" } });
        }

        void setProfile(
            const std::string & primary_cak,
            const std::string & primary_ckn,
            const std::string & fallback_cak = "",
            const std::string & fallback_ckn = "")
        {
            swss::Table profile_table(
                m_config_db.get(), CFG_MACSEC_PROFILE_TABLE_NAME);
            // A table set merges fields, so drop the entry first to model a
            // profile that no longer carries the fallback fields at all.
            profile_table.del(PROFILE_NAME);
            std::vector<swss::FieldValueTuple> fvs = {
                { "priority", "255" },
                { "cipher_suite", "GCM-AES-128" },
                { "primary_cak", primary_cak },
                { "primary_ckn", primary_ckn },
                { "policy", "security" },
                { "enable_replay_protect", "false" },
                { "replay_window", "0" },
                { "send_sci", "true" },
                { "rekey_period", "0" }
            };
            if (!fallback_ckn.empty())
            {
                fvs.emplace_back("fallback_cak", fallback_cak);
                fvs.emplace_back("fallback_ckn", fallback_ckn);
            }
            profile_table.set(PROFILE_NAME, fvs);
        }

        void bindPort(const std::string & port_name)
        {
            swss::Table port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
            port_table.set(port_name, { { "macsec", PROFILE_NAME } });
        }

        // Bring a port up on the given profile and clear the command log, so a
        // test only sees the commands driven by the update under test.
        void enablePort(swss::MACsecMgr & macsecmgr)
        {
            swss::Table profile_table(
                m_config_db.get(), CFG_MACSEC_PROFILE_TABLE_NAME);
            swss::Table port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
            macsecmgr.addExistingData(&profile_table);
            macsecmgr.addExistingData(&port_table);
            macsecmgr.doTask();
            g_commands.clear();
        }

        // Push a profile change through CONFIG_DB and let the manager apply it.
        void updateProfile(swss::MACsecMgr & macsecmgr)
        {
            swss::Table profile_table(
                m_config_db.get(), CFG_MACSEC_PROFILE_TABLE_NAME);
            macsecmgr.addExistingData(&profile_table);
            macsecmgr.doTask();
        }

        // Orch::doTask() only drains consumers, so the periodic collector has to
        // be driven through its executor.
        void firePollTimer(swss::MACsecMgr & macsecmgr)
        {
            for (auto * selectable : macsecmgr.getSelectables())
            {
                auto * executor = dynamic_cast<Executor *>(selectable);
                if (executor != nullptr && executor->getName() == "MACSEC_MKA_POLL")
                {
                    executor->execute();
                    return;
                }
            }
            FAIL() << "The MACsec MKA poll timer is not registered";
        }

        std::string sessionField(
            const std::string & port_name,
            const std::string & field)
        {
            swss::Table table(m_state_db.get(), STATE_MACSEC_MKA_SESSION_TABLE_NAME);
            std::string value;
            table.hget(port_name, field, value);
            return value;
        }

        bool hasSessionField(const std::string & port_name, const std::string & field)
        {
            swss::Table table(m_state_db.get(), STATE_MACSEC_MKA_SESSION_TABLE_NAME);
            std::string value;
            return table.hget(port_name, field, value);
        }

        std::string participantField(
            const std::string & port_name,
            const std::string & ckn,
            const std::string & field)
        {
            swss::Table table(
                m_state_db.get(), STATE_MACSEC_MKA_PARTICIPANT_TABLE_NAME);
            std::string value;
            table.hget(port_name + "|" + ckn, field, value);
            return value;
        }

        std::vector<std::string> participantKeys()
        {
            swss::Table table(
                m_state_db.get(), STATE_MACSEC_MKA_PARTICIPANT_TABLE_NAME);
            std::vector<std::string> keys;
            table.getKeys(keys);
            return keys;
        }
    };

    // The fields the parser has to see before it will accept a snapshot, so a
    // test can build a valid reply and then take exactly one thing away.
    static std::string mkaSessionHeader()
    {
        return
            "PAE KaY status=Active\n"
            "Authenticated=Yes\n"
            "Secured=No\n"
            "Failed=No\n"
            "Actor Priority=16\n"
            "Key Server Priority=16\n"
            "Is Key Server=Yes\n"
            "Number of Keys Distributed=3\n"
            "Number of Keys Received=4\n"
            "MKA Hello Time=2000\n"
            "actor_sci=52:54:00:12:34:56@1\n"
            "key_server_sci=00:00:00:00:00:00@0\n";
    }

    static std::string mkaParticipantBlock(
        const std::string & ckn,
        const std::string & role_field = "is_primary=Yes")
    {
        return
            "participant_idx=0\n"
            "ckn=" + ckn + "\n"
            "mi=0a1b2c3d4e5f60718293a4b5\n"
            "mn=7\n"
            "active=Yes\n"
            "participant=Yes\n"
            "retain=No\n"
            "is_principal=Yes\n"
            + role_field + "\n"
            "live_peers=2\n"
            "potential_peers=1\n"
            "is_key_server=No\n"
            "is_elected=No\n";
    }

    // Enabling MACsec on a port with a fallback configured must add the
    // fallback CA over the control socket, since only the primary is carried by
    // the wpa_supplicant network block.
    TEST_F(MACsecMgrTest, enableMACsecAddsFallbackParticipant)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        ASSERT_EQ(g_participants.size(), 2);
        const auto * fallback = findFakeParticipant(CKN_FALLBACK_A);
        ASSERT_NE(fallback, nullptr);
        EXPECT_TRUE(fallback->fallback);
        EXPECT_EQ(fallback->cak, DECODED_CAK_FALLBACK_A);

        // The primary is loaded through the network block, decoded the same way.
        const auto * primary = findFakeParticipant(CKN_PRIMARY_A);
        ASSERT_NE(primary, nullptr);
        EXPECT_FALSE(primary->fallback);
        EXPECT_EQ(primary->cak, DECODED_CAK_PRIMARY_A);
    }

    // A profile with no fallback must not issue any macsec_add_mka.
    TEST_F(MACsecMgrTest, enableMACsecWithoutFallbackAddsNoParticipant)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);

        swss::Table profile_table(
            m_config_db.get(), CFG_MACSEC_PROFILE_TABLE_NAME);
        swss::Table port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
        macsecmgr.addExistingData(&profile_table);
        macsecmgr.addExistingData(&port_table);
        macsecmgr.doTask();

        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        ASSERT_EQ(g_participants.size(), 1);
        EXPECT_FALSE(g_participants.front().fallback);
        EXPECT_EQ(g_participants.front().ckn, CKN_PRIMARY_A);
    }

    // Rotating the primary CKN retires the old primary before adding the new
    // one, so the port is never holding a third CA, and rides the fallback in
    // between.
    TEST_F(MACsecMgrTest, rotatePrimaryRetiresOldPrimaryBeforeAddingNew)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_B, CKN_PRIMARY_B, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        auto dels = commandsMatching("macsec_del_mka");
        auto adds = commandsMatching("macsec_add_mka");
        ASSERT_EQ(dels.size(), 1);
        ASSERT_EQ(adds.size(), 1);
        EXPECT_EQ(argValue(dels.front(), "ckn"), CKN_PRIMARY_A);
        EXPECT_EQ(argValue(adds.front(), "ckn"), CKN_PRIMARY_B);
        EXPECT_EQ(argValue(adds.front(), "cak"), DECODED_CAK_PRIMARY_B);
        // The new primary is added as a primary, not into the fallback slot.
        EXPECT_NE(adds.front().find(" fallback=0"), std::string::npos);

        // The delete of the old primary must be ordered before the add.
        auto del_pos = std::find(g_commands.begin(), g_commands.end(), dels.front());
        auto add_pos = std::find(g_commands.begin(), g_commands.end(), adds.front());
        EXPECT_LT(del_pos, add_pos);

        // The fallback is untouched and the port converges on the new primary.
        ASSERT_EQ(g_participants.size(), 2);
        const auto * fallback = findFakeParticipant(CKN_FALLBACK_A);
        ASSERT_NE(fallback, nullptr);
        EXPECT_TRUE(fallback->fallback);
        const auto * primary = findFakeParticipant(CKN_PRIMARY_B);
        ASSERT_NE(primary, nullptr);
        EXPECT_FALSE(primary->fallback);
    }

    // Without an established fallback there is nothing to carry traffic during
    // the swap, so the rotation must be refused before anything is torn down.
    TEST_F(MACsecMgrTest, rotatePrimaryWithoutFallbackIsRefused)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_B, CKN_PRIMARY_B);
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        ASSERT_EQ(g_participants.size(), 1);
        EXPECT_EQ(g_participants.front().ckn, CKN_PRIMARY_A);
    }

    // The primary CAK is fixed on the participant at creation and a participant
    // is keyed by CKN, so a CAK-only change cannot be rotated at run time. The
    // live CA must be left alone rather than torn down.
    TEST_F(MACsecMgrTest, primaryCakOnlyChangeLeavesSessionUntouched)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_B, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        ASSERT_EQ(g_participants.size(), 2);
        EXPECT_NE(findFakeParticipant(CKN_PRIMARY_A), nullptr);
    }

    // Adding a fallback to a port that had none must add exactly one standby CA.
    TEST_F(MACsecMgrTest, addFallbackToRunningPort)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        auto adds = commandsMatching("macsec_add_mka");
        ASSERT_EQ(adds.size(), 1);
        EXPECT_EQ(argValue(adds.front(), "ckn"), CKN_FALLBACK_A);
        EXPECT_EQ(argValue(adds.front(), "cak"), DECODED_CAK_FALLBACK_A);
        EXPECT_NE(adds.front().find(" fallback=1"), std::string::npos);
        EXPECT_EQ(countCommands("macsec_del_mka"), 0);

        const auto * fallback = findFakeParticipant(CKN_FALLBACK_A);
        ASSERT_NE(fallback, nullptr);
        EXPECT_TRUE(fallback->fallback);
    }

    // Removing fallback_cak/fallback_ckn from CONFIG_DB must retire the standby
    // CA rather than leave stale key material on the port.
    TEST_F(MACsecMgrTest, removeFallbackRetiresParticipant)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        updateProfile(macsecmgr);

        auto dels = commandsMatching("macsec_del_mka");
        ASSERT_EQ(dels.size(), 1);
        EXPECT_EQ(argValue(dels.front(), "ckn"), CKN_FALLBACK_A);
        EXPECT_EQ(countCommands("macsec_add_mka"), 0);

        ASSERT_EQ(g_participants.size(), 1);
        EXPECT_EQ(g_participants.front().ckn, CKN_PRIMARY_A);
    }

    // Changing the fallback CKN swaps the standby CA.
    TEST_F(MACsecMgrTest, changeFallbackCknReplacesParticipant)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_B, CKN_FALLBACK_B);
        updateProfile(macsecmgr);

        auto dels = commandsMatching("macsec_del_mka");
        auto adds = commandsMatching("macsec_add_mka");
        ASSERT_EQ(dels.size(), 1);
        ASSERT_EQ(adds.size(), 1);
        EXPECT_EQ(argValue(dels.front(), "ckn"), CKN_FALLBACK_A);
        EXPECT_EQ(argValue(adds.front(), "ckn"), CKN_FALLBACK_B);
        EXPECT_NE(adds.front().find(" fallback=1"), std::string::npos);

        EXPECT_EQ(findFakeParticipant(CKN_FALLBACK_A), nullptr);
        EXPECT_NE(findFakeParticipant(CKN_FALLBACK_B), nullptr);
    }

    // The CAK is fixed on the participant at creation, so a fallback CAK-only
    // change still has to recreate it for the new key to take effect.
    TEST_F(MACsecMgrTest, fallbackCakOnlyChangeRecreatesParticipant)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        const std::string old_cak = [&]
        {
            enablePort(macsecmgr);
            const auto * p = findFakeParticipant(CKN_FALLBACK_A);
            return p != nullptr ? p->cak : "";
        }();
        ASSERT_FALSE(old_cak.empty());

        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_B, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        auto dels = commandsMatching("macsec_del_mka");
        auto adds = commandsMatching("macsec_add_mka");
        ASSERT_EQ(dels.size(), 1);
        ASSERT_EQ(adds.size(), 1);
        EXPECT_EQ(argValue(dels.front(), "ckn"), CKN_FALLBACK_A);
        EXPECT_EQ(argValue(adds.front(), "ckn"), CKN_FALLBACK_A);
        EXPECT_EQ(argValue(adds.front(), "cak"), DECODED_CAK_FALLBACK_B);

        const auto * fallback = findFakeParticipant(CKN_FALLBACK_A);
        ASSERT_NE(fallback, nullptr);
        EXPECT_TRUE(fallback->fallback);
        EXPECT_NE(fallback->cak, old_cak);
        EXPECT_EQ(fallback->cak, DECODED_CAK_FALLBACK_B);
    }

    // Re-applying an unchanged profile must not disturb the live session.
    TEST_F(MACsecMgrTest, unchangedProfileIssuesNoRuntimeCommands)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        EXPECT_EQ(g_participants.size(), 2);
    }

    // wpa_supplicant reports the CKN as lower-case hex while CONFIG_DB may hold
    // either case, so a case-only difference is not a key change.
    TEST_F(MACsecMgrTest, cknComparisonIsCaseInsensitive)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, "aabbccdd", CAK_FALLBACK_A, "11223344");
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_A, "AABBCCDD", CAK_FALLBACK_A, "11223344");
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
    }

    // A fallback CKN colliding with the primary CKN is rejected, and the
    // profile already applied to the port is left untouched.
    TEST_F(MACsecMgrTest, fallbackCknCollidingWithPrimaryIsRejected)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_PRIMARY_A);
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        ASSERT_EQ(g_participants.size(), 2);
        EXPECT_NE(findFakeParticipant(CKN_FALLBACK_A), nullptr);
    }

    // A malformed CAK is reported by decodeKey throwing, which must be caught
    // and reported as a failed task rather than escaping the manager.
    TEST_F(MACsecMgrTest, malformedCakIsRejected)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        // Too short for GCM-AES-128, which expects 66 characters.
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, "01abcdef", CKN_FALLBACK_B);
        EXPECT_NO_THROW(updateProfile(macsecmgr));

        // The key is validated before the session is touched, so the live
        // fallback must still be in place rather than torn down part way.
        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        ASSERT_EQ(g_participants.size(), 2);
        EXPECT_NE(findFakeParticipant(CKN_FALLBACK_A), nullptr);
    }

    // wpa_supplicant reports the CKN in lower case, so a profile that spells it
    // in upper case must still resolve to the live participant.
    TEST_F(MACsecMgrTest, cknLookupMatchesLowerCaseReportedByWpaSupplicant)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, "aabbccdd", CAK_FALLBACK_A, "EEFF0011");
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        // A fallback CAK-only change has to find, and retire, the participant
        // that macsec_mka_list reports as 'eeff0011'.
        setProfile(CAK_PRIMARY_A, "aabbccdd", CAK_FALLBACK_B, "EEFF0011");
        updateProfile(macsecmgr);

        auto dels = commandsMatching("macsec_del_mka");
        auto adds = commandsMatching("macsec_add_mka");
        ASSERT_EQ(dels.size(), 1);
        ASSERT_EQ(adds.size(), 1);
        EXPECT_EQ(argValue(dels.front(), "ckn"), "EEFF0011");
        EXPECT_EQ(argValue(adds.front(), "cak"), DECODED_CAK_FALLBACK_B);
        EXPECT_EQ(g_participants.size(), 2);
    }

    // A profile carrying a fallback CAK but no fallback CKN is incomplete, and
    // must be rejected outright rather than committed and driven onto the port.
    TEST_F(MACsecMgrTest, incompleteProfileIsRejected)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        swss::Table profile_table(
            m_config_db.get(), CFG_MACSEC_PROFILE_TABLE_NAME);
        profile_table.del(PROFILE_NAME);
        profile_table.set(
            PROFILE_NAME,
            { { "cipher_suite", "GCM-AES-128" },
              { "primary_cak", CAK_PRIMARY_A },
              { "primary_ckn", CKN_PRIMARY_A },
              { "fallback_cak", CAK_FALLBACK_B } });
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        ASSERT_EQ(g_participants.size(), 2);
        EXPECT_NE(findFakeParticipant(CKN_FALLBACK_A), nullptr);
    }

    // If the old primary cannot be retired the rotation must stop, rather than
    // going on to retire the fallback and strand the port with no live CA.
    TEST_F(MACsecMgrTest, failedPrimaryDeleteDoesNotRetireFallback)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        g_failing_command = "macsec_del_mka";
        setProfile(CAK_PRIMARY_B, CKN_PRIMARY_B, CAK_FALLBACK_B, CKN_FALLBACK_B);
        updateProfile(macsecmgr);

        // Only the primary delete is attempted, and the fallback survives.
        auto dels = commandsMatching("macsec_del_mka");
        ASSERT_EQ(dels.size(), 1);
        EXPECT_EQ(argValue(dels.front(), "ckn"), CKN_PRIMARY_A);
        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        EXPECT_NE(findFakeParticipant(CKN_FALLBACK_A), nullptr);
    }

    // Promoting the standby by hand (primary A->B where B was the fallback)
    // must converge with B as the primary, not delete it as a stale fallback.
    TEST_F(MACsecMgrTest, promotingFallbackToPrimaryKeepsPortProtected)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        // The old fallback becomes the primary and a new fallback takes over.
        setProfile(CAK_FALLBACK_A, CKN_FALLBACK_A, CAK_FALLBACK_B, CKN_FALLBACK_B);
        updateProfile(macsecmgr);

        ASSERT_EQ(g_participants.size(), 2);
        const auto * primary = findFakeParticipant(CKN_FALLBACK_A);
        ASSERT_NE(primary, nullptr);
        EXPECT_FALSE(primary->fallback);
        const auto * fallback = findFakeParticipant(CKN_FALLBACK_B);
        ASSERT_NE(fallback, nullptr);
        EXPECT_TRUE(fallback->fallback);
        EXPECT_EQ(findFakeParticipant(CKN_PRIMARY_A), nullptr);
    }

    // A rejected macsec_add_mka must not be retried or leave a half configured
    // CA behind, and must leave the live primary alone.
    TEST_F(MACsecMgrTest, failedAddDoesNotLeaveParticipantBehind)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        g_failing_command = "macsec_add_mka";
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_add_mka"), 1);
        EXPECT_EQ(findFakeParticipant(CKN_FALLBACK_A), nullptr);
        ASSERT_EQ(g_participants.size(), 1);
        EXPECT_EQ(g_participants.front().ckn, CKN_PRIMARY_A);
    }

    // A fallback CA is only a standby, so failing to install it at enable time
    // must leave the port protected by the primary rather than rolling MACsec
    // back and leaving the port unprotected.
    TEST_F(MACsecMgrTest, fallbackSetFailureKeepsPrimaryProtected)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);

        g_failing_command = "mka_cak_fallback";
        swss::Table profile_table(
            m_config_db.get(), CFG_MACSEC_PROFILE_TABLE_NAME);
        swss::Table port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
        macsecmgr.addExistingData(&profile_table);
        macsecmgr.addExistingData(&port_table);
        macsecmgr.doTask();

        // The primary is live and the session was not torn back down.
        ASSERT_EQ(g_participants.size(), 1);
        EXPECT_EQ(g_participants.front().ckn, CKN_PRIMARY_A);
        EXPECT_FALSE(g_participants.front().fallback);
        EXPECT_EQ(countCommands("interface_remove"), 0);
    }

    // The fallback that failed to install must not be recorded as applied, so a
    // later profile update reconciles it instead of diffing it away.
    TEST_F(MACsecMgrTest, fallbackSetFailureIsRepairedByProfileUpdate)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);

        g_failing_command = "mka_cak_fallback";
        enablePort(macsecmgr);
        ASSERT_EQ(findFakeParticipant(CKN_FALLBACK_A), nullptr);

        // Re-applying the same profile is enough to install the missing standby.
        g_failing_command.clear();
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        const auto * fallback = findFakeParticipant(CKN_FALLBACK_A);
        ASSERT_NE(fallback, nullptr);
        EXPECT_TRUE(fallback->fallback);
        EXPECT_NE(findFakeParticipant(CKN_PRIMARY_A), nullptr);
    }

    // Because the failed fallback is not recorded, the rotation guard still sees
    // a port with no standby and refuses, rather than retiring the live primary
    // in favour of a CA that was never installed.
    TEST_F(MACsecMgrTest, fallbackSetFailureRefusesPrimaryRotation)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);

        g_failing_command = "mka_cak_fallback";
        enablePort(macsecmgr);

        g_failing_command.clear();
        setProfile(CAK_PRIMARY_B, CKN_PRIMARY_B, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        ASSERT_EQ(g_participants.size(), 1);
        EXPECT_EQ(g_participants.front().ckn, CKN_PRIMARY_A);
    }

    // A control socket that cannot be read says nothing about what is running
    // behind it. A rotation that cannot see the participants must leave the live
    // primary in place rather than assume it has already gone.
    TEST_F(MACsecMgrTest, mkaListFailureRefusesPrimaryRotation)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);
        ASSERT_EQ(g_participants.size(), 2);

        g_failing_command = "macsec_mka_list";
        setProfile(CAK_PRIMARY_B, CKN_PRIMARY_B, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        // Nothing was retired, and nothing was staged on top of what is running.
        EXPECT_EQ(countCommands("macsec_del_mka"), 0);
        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        ASSERT_EQ(g_participants.size(), 2);
        EXPECT_NE(findFakeParticipant(CKN_PRIMARY_A), nullptr);
        EXPECT_EQ(findFakeParticipant(CKN_PRIMARY_B), nullptr);
    }

    // The fallback CAK and CKN are a pair. A profile carrying one half is a
    // misconfiguration, and must be refused rather than applied as a profile
    // that silently has no standby at all.
    TEST_F(MACsecMgrTest, halfConfiguredFallbackIsRejected)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        // A table set merges fields, so this leaves the CKN without its CAK.
        swss::Table profile_table(
            m_config_db.get(), CFG_MACSEC_PROFILE_TABLE_NAME);
        profile_table.set(PROFILE_NAME, { { "fallback_ckn", CKN_FALLBACK_A } });
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        // The profile was never loaded, so no port came up on it.
        EXPECT_EQ(countCommands("macsec_add_mka"), 0);
        EXPECT_TRUE(g_participants.empty());
    }

    // macsec_mka_list carries KaY-level 'key=value' lines before the first
    // participant block, which must not be mistaken for participant fields.
    TEST_F(MACsecMgrTest, mkaListHeaderLinesAreNotParsedAsParticipants)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        // Removing the fallback requires the manager to have found exactly the
        // fallback participant in a reply that also carries KaY header fields.
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        updateProfile(macsecmgr);

        ASSERT_EQ(countCommands("macsec_del_mka"), 1);
        EXPECT_EQ(g_participants.size(), 1);
    }

    // --- macsec_mka_list parsing -------------------------------------------

    using MKAStatus = swss::MACsecMgr::MKAStatus;

    TEST(MACsecMkaParser, parsesACompleteSnapshot)
    {
        MKAStatus status;
        std::string error;
        ASSERT_TRUE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("aabb") + "snapshot_complete=1\n",
            status,
            error)) << error;

        EXPECT_EQ(status.kay_status, "active");
        EXPECT_TRUE(status.authenticated);
        EXPECT_FALSE(status.secured);
        EXPECT_FALSE(status.failed);
        EXPECT_EQ(status.actor_priority, 16u);
        EXPECT_EQ(status.key_server_priority, 16u);
        EXPECT_TRUE(status.is_key_server);
        EXPECT_EQ(status.keys_distributed, 3u);
        EXPECT_EQ(status.keys_received, 4u);
        EXPECT_EQ(status.mka_hello_time_ms, 2000u);

        ASSERT_EQ(status.participants.size(), 1u);
        const auto & participant = status.participants.front();
        EXPECT_EQ(participant.ckn, "aabb");
        EXPECT_EQ(participant.participant_index, 0u);
        EXPECT_EQ(participant.mn, 7u);
        EXPECT_TRUE(participant.active);
        EXPECT_TRUE(participant.participant);
        EXPECT_FALSE(participant.retain);
        EXPECT_TRUE(participant.is_principal);
        EXPECT_EQ(participant.live_peers, 2u);
        EXPECT_EQ(participant.potential_peers, 1u);
        EXPECT_FALSE(participant.is_key_server);
        EXPECT_FALSE(participant.is_elected);
    }

    // sci_txt() renders MAC@port with the port in decimal; STATE_DB carries the
    // 16 hex digit wire form. An unelected key server has an all zero SCI, which
    // is a real value rather than a parse failure.
    TEST(MACsecMkaParser, normalizesSci)
    {
        MKAStatus status;
        std::string error;
        ASSERT_TRUE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + "snapshot_complete=1\n", status, error)) << error;

        EXPECT_EQ(status.actor_sci, "5254001234560001");
        EXPECT_EQ(status.key_server_sci, "0000000000000000");
    }

    TEST(MACsecMkaParser, rejectsAMalformedSci)
    {
        MKAStatus status;
        std::string error;
        std::string output = mkaSessionHeader() + "snapshot_complete=1\n";
        output.replace(
            output.find("52:54:00:12:34:56@1"),
            sizeof("52:54:00:12:34:56@1") - 1,
            "525400123456#0001");
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(output, status, error));
    }

    // The CKN keys the participant row, so it is normalised to one spelling.
    TEST(MACsecMkaParser, normalizesCknCase)
    {
        MKAStatus status;
        std::string error;
        ASSERT_TRUE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("AABBCCDD")
                + "snapshot_complete=1\n",
            status,
            error)) << error;

        ASSERT_EQ(status.participants.size(), 1u);
        EXPECT_EQ(status.participants.front().ckn, "aabbccdd");
    }

    // is_primary is what wpa_supplicant reports today. It means the inverse of
    // the is_fallback the schema publishes.
    TEST(MACsecMkaParser, acceptsIsPrimaryAsTheInverseOfIsFallback)
    {
        MKAStatus status;
        std::string error;
        ASSERT_TRUE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("aabb", "is_primary=No")
                + "snapshot_complete=1\n",
            status,
            error)) << error;
        ASSERT_EQ(status.participants.size(), 1u);
        EXPECT_TRUE(status.participants.front().is_fallback);

        ASSERT_TRUE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("aabb", "is_fallback=Yes")
                + "snapshot_complete=1\n",
            status,
            error)) << error;
        ASSERT_EQ(status.participants.size(), 1u);
        EXPECT_TRUE(status.participants.front().is_fallback);
    }

    TEST(MACsecMkaParser, rejectsConflictingRoleFields)
    {
        MKAStatus status;
        std::string error;
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader()
                + mkaParticipantBlock("aabb", "is_primary=Yes\nis_fallback=Yes")
                + "snapshot_complete=1\n",
            status,
            error));

        ASSERT_TRUE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader()
                + mkaParticipantBlock("aabb", "is_primary=Yes\nis_fallback=No")
                + "snapshot_complete=1\n",
            status,
            error)) << error;
    }

    TEST(MACsecMkaParser, rejectsASnapshotWithoutTheCompletionMarker)
    {
        MKAStatus status;
        std::string error;
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("aabb"), status, error));
    }

    // Truncation in the middle of a block is obvious. Truncation at a block
    // boundary is not: without the marker it reads as a participant that has
    // gone away, which would delete a live row.
    TEST(MACsecMkaParser, rejectsTruncationAtACleanParticipantBoundary)
    {
        MKAStatus status;
        std::string error;
        const std::string complete =
            mkaSessionHeader() + mkaParticipantBlock("aabb") + "snapshot_complete=1\n";

        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            complete.substr(0, complete.find("snapshot_complete")), status, error));
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + "participant_idx=0\nckn=aabb\n", status, error));
    }

    TEST(MACsecMkaParser, rejectsAnIncompleteSnapshot)
    {
        MKAStatus status;
        std::string error;
        std::string output = mkaSessionHeader() + "snapshot_complete=1\n";
        const std::string dropped = "Secured=No\n";
        output.erase(output.find(dropped), dropped.size());
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(output, status, error));

        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + "participant_idx=0\nckn=aabb\nsnapshot_complete=1\n",
            status,
            error));
    }

    TEST(MACsecMkaParser, rejectsDuplicatesAndMultiplePrincipals)
    {
        MKAStatus status;
        std::string error;

        // The same field twice, so a concatenation of two replies cannot pass.
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + "Secured=No\nsnapshot_complete=1\n", status, error));

        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("aabb")
                + mkaParticipantBlock("AABB") + "snapshot_complete=1\n",
            status,
            error));

        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("aabb")
                + mkaParticipantBlock("ccdd") + "snapshot_complete=1\n",
            status,
            error));
    }

    TEST(MACsecMkaParser, rejectsMalformedValues)
    {
        MKAStatus status;
        std::string error;

        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + "snapshot_complete=0\n", status, error));

        std::string output = mkaSessionHeader() + "snapshot_complete=1\n";
        output.replace(output.find("Authenticated=Yes"), sizeof("Authenticated=Yes") - 1,
            "Authenticated=Maybe");
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(output, status, error));

        // An odd length or non hex CKN is not a participant key.
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("aab") + "snapshot_complete=1\n",
            status,
            error));
        EXPECT_FALSE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + mkaParticipantBlock("zzzz") + "snapshot_complete=1\n",
            status,
            error));
    }

    // A wpa_supplicant reporting more than this build knows about is not a
    // reason to drop the whole snapshot.
    TEST(MACsecMkaParser, ignoresUnknownFields)
    {
        MKAStatus status;
        std::string error;
        EXPECT_TRUE(swss::MACsecMgr::parseMKAStatus(
            mkaSessionHeader() + "Some Future Field=7\n"
                + mkaParticipantBlock("aabb") + "future_participant_field=7\n"
                + "snapshot_complete=1\n",
            status,
            error)) << error;
    }

    // --- MKA operational state publication ---------------------------------

    TEST_F(MACsecMgrTest, enablePublishesTheMkaSessionAndParticipants)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        EXPECT_EQ(sessionField(PORT_NAME, "profile"), PROFILE_NAME);
        EXPECT_EQ(sessionField(PORT_NAME, "query_status"), "ok");
        EXPECT_EQ(sessionField(PORT_NAME, "kay_status"), "active");
        // Yes/No is normalised the way the rest of STATE_DB spells a boolean.
        EXPECT_EQ(sessionField(PORT_NAME, "authenticated"), "true");
        EXPECT_EQ(sessionField(PORT_NAME, "failed"), "false");
        EXPECT_EQ(sessionField(PORT_NAME, "actor_sci"), "5254001234560001");
        EXPECT_EQ(sessionField(PORT_NAME, "mka_hello_time_ms"), "2000");
        EXPECT_FALSE(sessionField(PORT_NAME, "last_updated").empty());

        EXPECT_EQ(participantKeys().size(), 2u);
        EXPECT_EQ(participantField(PORT_NAME, CKN_PRIMARY_A, "is_fallback"), "false");
        EXPECT_EQ(participantField(PORT_NAME, CKN_FALLBACK_A, "is_fallback"), "true");
        EXPECT_EQ(participantField(PORT_NAME, CKN_PRIMARY_A, "live_peers"), "1");
        EXPECT_EQ(participantField(PORT_NAME, CKN_PRIMARY_A, "mi"),
            "0a1b2c3d4e5f60718293a4b5");
    }

    // A validated snapshot is the whole participant list, so what it omits is
    // deleted. That only happens once the snapshot has passed validation.
    TEST_F(MACsecMgrTest, staleParticipantRowsGoOnlyAfterAGoodSnapshot)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);
        ASSERT_EQ(participantKeys().size(), 2u);

        // The fallback goes away, but the reply describing that is truncated.
        g_participants.erase(findFakeParticipantItr(CKN_FALLBACK_A));
        g_snapshot_complete = false;
        firePollTimer(macsecmgr);

        EXPECT_EQ(participantKeys().size(), 2u);
        EXPECT_EQ(sessionField(PORT_NAME, "query_status"), "error");

        g_snapshot_complete = true;
        // A port whose query failed backs off one tick before it is retried.
        firePollTimer(macsecmgr);
        firePollTimer(macsecmgr);

        EXPECT_EQ(participantKeys().size(), 1u);
        EXPECT_EQ(sessionField(PORT_NAME, "query_status"), "ok");
    }

    // A wedged wpa_supplicant must not be retried every tick: the port backs off
    // so the tick budget goes to the ports that are still answering.
    TEST_F(MACsecMgrTest, aFailingPortBacksOff)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        g_failing_command = "macsec_mka_list";
        firePollTimer(macsecmgr);
        ASSERT_EQ(countCommands("macsec_mka_list"), 1u);

        // Skipped, because the previous tick failed.
        firePollTimer(macsecmgr);
        EXPECT_EQ(countCommands("macsec_mka_list"), 1u);

        firePollTimer(macsecmgr);
        EXPECT_EQ(countCommands("macsec_mka_list"), 2u);
    }

    // A failed query says nothing about the KaY, only about reaching it.
    TEST_F(MACsecMgrTest, queryFailureRetainsTheLastKnownState)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        const std::string last_updated = sessionField(PORT_NAME, "last_updated");
        ASSERT_FALSE(last_updated.empty());

        g_failing_command = "macsec_mka_list";
        firePollTimer(macsecmgr);

        EXPECT_EQ(sessionField(PORT_NAME, "query_status"), "error");
        EXPECT_EQ(sessionField(PORT_NAME, "kay_status"), "active");
        EXPECT_EQ(sessionField(PORT_NAME, "actor_sci"), "5254001234560001");
        // Freshness must not advance across a failure.
        EXPECT_EQ(sessionField(PORT_NAME, "last_updated"), last_updated);
        EXPECT_EQ(participantKeys().size(), 1u);
    }

    // With nothing ever collected, success shaped defaults would be read as a
    // real idle KaY. Only what is actually known is published.
    TEST_F(MACsecMgrTest, firstQueryFailurePublishesOnlyKnownMetadata)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);
        g_failing_command = "macsec_mka_list";
        enablePort(macsecmgr);

        EXPECT_EQ(sessionField(PORT_NAME, "profile"), PROFILE_NAME);
        EXPECT_EQ(sessionField(PORT_NAME, "query_status"), "error");
        EXPECT_FALSE(hasSessionField(PORT_NAME, "kay_status"));
        EXPECT_FALSE(hasSessionField(PORT_NAME, "last_updated"));
        EXPECT_TRUE(participantKeys().empty());
    }

    // Collection has to stay bounded: a wpa_supplicant blocked elsewhere holds
    // the ctrl interface for its whole timeout, and there is one query per port.
    TEST_F(MACsecMgrTest, statusQueriesCarryADeadline)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);
        firePollTimer(macsecmgr);

        const auto queries = commandsMatching("macsec_mka_list");
        ASSERT_EQ(queries.size(), 1u);
        EXPECT_EQ(queries.front().find("/usr/bin/timeout "), 0u);
    }

    // Disable is authoritative: no refresh will ever correct these rows.
    TEST_F(MACsecMgrTest, disableRemovesTheMkaState)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);
        ASSERT_EQ(participantKeys().size(), 2u);

        swss::Table port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
        port_table.del(PORT_NAME);
        port_table.set(PORT_NAME, { { "macsec", "" } });
        macsecmgr.addExistingData(&port_table);
        macsecmgr.doTask();

        EXPECT_FALSE(hasSessionField(PORT_NAME, "query_status"));
        EXPECT_TRUE(participantKeys().empty());
    }

    // Rotation republishes between the two halves, so the window where the port
    // runs on the fallback CA alone is visible rather than inferred.
    TEST_F(MACsecMgrTest, rotationRepublishesAfterEachParticipantChange)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        setProfile(CAK_PRIMARY_B, CKN_PRIMARY_B, CAK_FALLBACK_A, CKN_FALLBACK_A);
        updateProfile(macsecmgr);

        // One query after the delete and one after the add.
        EXPECT_GE(countCommands("macsec_mka_list"), 2u);
        EXPECT_EQ(participantKeys().size(), 2u);
        EXPECT_EQ(participantField(PORT_NAME, CKN_PRIMARY_B, "is_fallback"), "false");
        // The rotated out CKN is gone rather than left behind as a live CA.
        EXPECT_EQ(participantField(PORT_NAME, CKN_PRIMARY_A, "is_fallback"), "");
    }

    // State is keyed by interface, so nothing a port publishes can be read as
    // another port's, and no row is written for an interface that has none.
    TEST_F(MACsecMgrTest, stateIsKeyedPerInterface)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        const std::vector<std::string> keys = participantKeys();
        ASSERT_EQ(keys.size(), 2u);
        for (const auto & key : keys)
        {
            EXPECT_EQ(key.find(std::string(PORT_NAME) + "|"), 0u);
        }
        EXPECT_FALSE(hasSessionField("Ethernet4", "query_status"));
    }

    // The CKN is publishable, the CAK never is. Nothing in either table may
    // carry key material.
    TEST_F(MACsecMgrTest, noSecretMaterialReachesTheStateDb)
    {
        swss::MACsecMgr macsecmgr(
            m_config_db.get(), m_state_db.get(), cfg_macsec_tables);
        setPortStateOk(PORT_NAME);
        setProfile(CAK_PRIMARY_A, CKN_PRIMARY_A, CAK_FALLBACK_A, CKN_FALLBACK_A);
        bindPort(PORT_NAME);
        enablePort(macsecmgr);

        swss::Table session_table(
            m_state_db.get(), STATE_MACSEC_MKA_SESSION_TABLE_NAME);
        swss::Table participant_table(
            m_state_db.get(), STATE_MACSEC_MKA_PARTICIPANT_TABLE_NAME);

        std::vector<swss::FieldValueTuple> published;
        session_table.get(PORT_NAME, published);
        ASSERT_FALSE(published.empty());
        for (const auto & key : participantKeys())
        {
            std::vector<swss::FieldValueTuple> fvs;
            participant_table.get(key, fvs);
            published.insert(published.end(), fvs.begin(), fvs.end());
        }

        for (const auto & fv : published)
        {
            EXPECT_EQ(fvValue(fv).find(DECODED_CAK_PRIMARY_A), std::string::npos);
            EXPECT_EQ(fvValue(fv).find(DECODED_CAK_FALLBACK_A), std::string::npos);
            EXPECT_EQ(fvValue(fv).find(CAK_PRIMARY_A), std::string::npos);
            EXPECT_EQ(fvValue(fv).find(CAK_FALLBACK_A), std::string::npos);
        }
    }
}
