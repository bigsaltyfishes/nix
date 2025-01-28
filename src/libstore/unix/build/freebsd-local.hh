#include <db.h>
#include <net/if.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <unistd.h>

namespace nix {

struct PasswordEntry
{
    std::string name;
    uid_t uid;
    gid_t gid;
    std::string description;
    Path home;
    Path shell;
};


static void free_db(DB * db)
{
    if (db != nullptr) {
        (db->close)(db);
    }
}

// Database open flags from FreeBSD, in case they're necessary for compatibility
static const HASHINFO db_flags = {
    .bsize = 4096,
    .ffactor = 32,
    .nelem = 256,
    .cachesize = 2 * 1024 * 1024,
    .hash = nullptr,
    .lorder = BIG_ENDIAN,
};

// Password database version
// Version 4 has been current since 2003
static const uint8_t dbVersion = 4;

static void serializeString(std::vector<uint8_t> & buf, std::string const & str)
{
    buf.reserve(buf.size() + str.size() + 1);
    buf.insert(buf.end(), str.begin(), str.end());
    buf.push_back(0);
}

static void serializeInt(std::vector<uint8_t> & buf, uint32_t num)
{
    buf.reserve(buf.size() + sizeof(num));
    // Always big endian
    buf.push_back((num >> 24) & 0xff);
    buf.push_back((num >> 16) & 0xff);
    buf.push_back((num >> 8) & 0xff);
    buf.push_back((num >> 0) & 0xff);
}

static std::vector<uint8_t> byNameKey(std::string const & name)
{
    std::vector<uint8_t> buf{_PW_VERSIONED(_PW_KEYBYNAME, dbVersion)};
    buf.reserve(1 + name.size());
    // We can't use serializeString since that's null terimated
    buf.insert(buf.end(), name.begin(), name.end());

    return buf;
}

static std::vector<uint8_t> byNumKey(uint32_t num)
{
    std::vector<uint8_t> buf{_PW_VERSIONED(_PW_KEYBYNUM, dbVersion)};
    serializeInt(buf, num);

    return buf;
}

static std::vector<uint8_t> byUidKey(uid_t uid)
{
    std::vector<uint8_t> buf{_PW_VERSIONED(_PW_KEYBYUID, dbVersion)};
    serializeInt(buf, uid);

    return buf;
}

static void createPasswordFiles(Path & chrootRootDir, std::vector<PasswordEntry> & users)
{
    std::unique_ptr<DB, decltype(&free_db)> db(
        dbopen(
            (chrootRootDir + "/etc/pwd.db").c_str(),
            O_CREAT | O_RDWR | O_EXCL,
            0644,
            DB_HASH,
            &db_flags
        ),
        &free_db
    );

    if (db == nullptr) {
        throw SysError("Could not create password database");
    }

    auto dbInsert = [&db](std::vector<uint8_t> key_buf, std::vector<uint8_t> & value_buf) {
        DBT key = {key_buf.data(), key_buf.size()};
        DBT value = {value_buf.data(), value_buf.size()};

        if ((db->put)(db.get(), &key, &value, R_NOOVERWRITE) == -1) {
            throw SysError("Could not write to password database");
        }
    };

    // Annoyingly DBT doesn't have const pointers so we need this whole shuffle
    std::string versionKeyStr(_PWD_VERSION_KEY);
    std::vector<uint8_t> versionKey(versionKeyStr.begin(), versionKeyStr.end());
    std::vector<uint8_t> versionValue{dbVersion};
    dbInsert(versionKey, versionValue);

    for (size_t i = 0; i < users.size(); i++) {
        auto user = users[i];

        // flags for non-empty fields
        uint32_t fields =
            _PWF_NAME | _PWF_PASSWD | _PWF_UID | _PWF_GID | _PWF_GECOS | _PWF_DIR | _PWF_SHELL;

        std::vector<uint8_t> buf;
        serializeString(buf, user.name);
        // pw_password is always "*" in the insecure database
        serializeString(buf, std::string("*"));
        serializeInt(buf, user.uid);
        serializeInt(buf, user.gid);
        // pw_change = 0 means no requirement to change password
        serializeInt(buf, 0);
        // pw_class is empty since we don't make a class database
        serializeString(buf, std::string(""));
        serializeString(buf, user.description);
        serializeString(buf, user.home);
        serializeString(buf, user.shell);
        // pw_expire = 0 means password does not expire
        serializeInt(buf, 0);
        serializeInt(buf, fields);

        dbInsert(byNameKey(user.name), buf);
        // _PW_KEYBYNUM is 1-indexed
        dbInsert(byNumKey(i + 1), buf);
        dbInsert(byUidKey(user.uid), buf);
    }

    // FreeBSD libc doesn't use /etc/passwd, but some software might
    std::string passwdContent = "";
    for (auto user : users) {
        passwdContent.append(
            fmt("%s:*:%d:%d:%s:%s:%s\n",
                user.name,
                user.uid,
                user.gid,
                user.description,
                user.home,
                user.shell)
        );
    }

    writeFile(chrootRootDir + "/etc/passwd", passwdContent);

    // No need to make /etc/master.passwd or /etc/spwd.db,
    // our build user wouldn't be able to read them anyway
}

}