#include <xtl.h>
#include <string>
#include <cstdint>
#include <iostream>
#include <cstddef>
#include <cassert>

// Get the address of a function from a module by its ordinal
void *ResolveFunction(const std::string &moduleName, uint32_t ordinal)
{
    HMODULE moduleHandle = GetModuleHandle(moduleName.c_str());
    if (moduleHandle == nullptr)
        return nullptr;

    return GetProcAddress(moduleHandle, reinterpret_cast<const char *>(ordinal));
}

typedef void (*XNOTIFYQUEUEUI)(uint32_t type, uint32_t userIndex, uint64_t areas, const wchar_t *displayText, void *pContextData);
XNOTIFYQUEUEUI XNotifyQueueUI = static_cast<XNOTIFYQUEUEUI>(ResolveFunction("xam.xex", 656));

enum Games
{
    GAME_DASHBOARD = 0xFFFE07D1,
    GAME_IW3 = 0x415607E6,
};

// Imports from the Xbox libraries
extern "C"
{
    uint32_t XamGetCurrentTitleId();

    uint32_t ExCreateThread(
        HANDLE *pHandle,
        uint32_t stackSize,
        uint32_t *pThreadId,
        void *pApiThreadStartup,
        PTHREAD_START_ROUTINE pStartAddress,
        void *pParameter,
        uint32_t creationFlags
    );

    bool MmIsAddressValid(void *pAddress);
}

void InitIW3();

bool g_Running = true;

// Infinitely check the current game running
uint32_t MonitorTitleId(void *pThreadParameter)
{
    uint32_t currentTitleId = 0;

    while (g_Running)
    {
        uint32_t newTitleId = XamGetCurrentTitleId();

        if (newTitleId == currentTitleId)
            continue;

        currentTitleId = newTitleId;

        switch (newTitleId)
        {
        case GAME_DASHBOARD:
            XNotifyQueueUI(0, 0, XNOTIFY_SYSTEM, L"Dashboard", nullptr);
            break;
        case GAME_IW3:
            InitIW3();
            break;
        }
    }

    return 0;
}

#define MAX_HOOK_COUNT 100
#define NUM_INSTRUCTIONS_IN_JUMP 4
#define POWERPC_B 0x48
#define POWERPC_BL 0x4B

class Detour
{
public:
    Detour(void *pSource, const void *pDestination)
        : m_pSource(pSource), m_pDestination(pDestination), m_HookIndex(static_cast<size_t>(-1))
    {
    }

    Detour(uintptr_t sourceAddress, const void *pDestination)
        : m_pSource(reinterpret_cast<void *>(sourceAddress)), m_pDestination(pDestination), m_HookIndex(static_cast<size_t>(-1))
    {
    }

    ~Detour()
    {
        Remove();
    }

    HRESULT Install()
    {
        if (s_HookCount >= MAX_HOOK_COUNT || m_pSource == nullptr || m_pDestination == nullptr)
            return E_FAIL;

        if (s_CriticalSection.Synchronization.RawEvent[0] == 0)
            InitializeCriticalSection(&s_CriticalSection);

        EnterCriticalSection(&s_CriticalSection);

        // Keep track of where the stub of the current instance is in s_StubSection
        m_HookIndex = s_HookCount;

        // Copy the original instructions at m_pSource before hooking to be able to
        // restore them later
        memcpy(&m_Original, m_pSource, sizeof(m_Original));

        DetourFunctionStart();

        s_HookCount++;

        LeaveCriticalSection(&s_CriticalSection);

        return S_OK;
    }

    void Remove()
    {
        // Restore the original instructions if needed
        if (m_HookIndex != -1 && m_pSource != nullptr && MmIsAddressValid(m_pSource))
            memcpy(m_pSource, &m_Original, sizeof(m_Original));

        m_pSource = nullptr;
        m_pDestination = nullptr;
        m_HookIndex = 0;
        m_Original = Jump();
    }

    template<typename T>
    inline T GetOriginal() const
    {
        return reinterpret_cast<T>(&s_StubSection[m_HookIndex]);
    }

private:
    typedef uint32_t POWERPC_INSTRUCTION;
    typedef uint8_t POWERPC_INSTRUCTION_TYPE;

    struct Stub
    {
        POWERPC_INSTRUCTION Instructions[20]; // DetourFunctionStart can copy up to 20 instructions

        Stub() { ZeroMemory(&Instructions, sizeof(Instructions)); }
    };

    struct Jump
    {
        POWERPC_INSTRUCTION Instructions[NUM_INSTRUCTIONS_IN_JUMP];

        Jump() { ZeroMemory(&Instructions, sizeof(Instructions)); }
    };

    void *m_pSource;
    const void *m_pDestination;
    size_t m_HookIndex;
    Jump m_Original;

    static Stub s_StubSection[MAX_HOOK_COUNT];
    static size_t s_HookCount;
    static CRITICAL_SECTION s_CriticalSection;

    void DetourFunctionStart()
    {
        POWERPC_INSTRUCTION *pSource = static_cast<POWERPC_INSTRUCTION *>(m_pSource);
        POWERPC_INSTRUCTION *pStub = reinterpret_cast<POWERPC_INSTRUCTION *>(&s_StubSection[m_HookIndex]);
        size_t instructionCount = 0;

        for (size_t i = 0; i < NUM_INSTRUCTIONS_IN_JUMP; i++)
        {
            POWERPC_INSTRUCTION instruction = pSource[i];
            POWERPC_INSTRUCTION_TYPE instructionType = *reinterpret_cast<POWERPC_INSTRUCTION_TYPE *>(&pSource[i]);

            // If the function op code is null, it's invalid
            if (instruction == 0)
                break;

            // If the instruction is a branch
            if (instructionType == POWERPC_B || instructionType == POWERPC_BL)
            {
                // Get a pointer to where the branch goes
                void *pBranchDestination = ResolveBranch(instruction, &pSource[i]);
                bool linked = (instruction & 1) != 0;

                // Jump from the stub to where the branch goes
                PatchInJump(&pStub[instructionCount], pBranchDestination, linked);
                instructionCount += NUM_INSTRUCTIONS_IN_JUMP;

                // If it was a branch to a different section of the same function (b loc_),
                // we won't need to add anything else to the stub
                if (!linked)
                {
                    PatchInJump(pSource, m_pDestination, false);
                    return;
                }
            }
            // Otherwise, just copy the instruction to the stub
            else
            {
                pStub[instructionCount] = instruction;
                instructionCount++;
            }
        }

        // Make the stub call the original function
        PatchInJump(&pStub[instructionCount], &pSource[NUM_INSTRUCTIONS_IN_JUMP], false);

        // Make the original function call the stub
        PatchInJump(pSource, m_pDestination, false);
    }

    void PatchInJump(void *pSource, const void *pDestination, bool linked)
    {
        Jump jump;
        uintptr_t destinationAddress = reinterpret_cast<uintptr_t>(pDestination);

        jump.Instructions[0] = 0x3C000000 + (destinationAddress >> 16);    // lis    %r0, dest>>16
        jump.Instructions[1] = 0x60000000 + (destinationAddress & 0xFFFF); // ori    %r0, %r0, dest&0xFFFF
        jump.Instructions[2] = 0x7C0903A6;                                 // mtctr  %r0
        jump.Instructions[3] = 0x4E800420 + (linked ? 1 : 0);              // bctr/bctrl

        memcpy(pSource, &jump, sizeof(jump));

        __dcbst(0, pSource);
        __sync();
        __emit(0x4C00012C);
    }

    void *ResolveBranch(POWERPC_INSTRUCTION instruction, const void *pBranch)
    {
        // Taken from here
        // https://github.com/skiff/libpsutil/blob/master/libpsutil/system/memory.cpp#L90

        uintptr_t offset = instruction & 0x3FFFFFC;

        if (offset & (1 << 25))
            offset |= 0xFC000000;

        return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(pBranch) + offset);
    }
};

// This will hold all the instructions for all hooks. This needs to be a static buffer because,
// if it was a class member, it would be allocated on the stack and stack memory isn't executable
Detour::Stub Detour::s_StubSection[MAX_HOOK_COUNT];
size_t Detour::s_HookCount = 0;
CRITICAL_SECTION Detour::s_CriticalSection = { 0 };

#define KEY_MASK_FIRE 1
#define KEY_MASK_SPRINT 2
#define KEY_MASK_MELEE 4
#define KEY_MASK_RELOAD 16
#define KEY_MASK_LEANLEFT 64
#define KEY_MASK_LEANRIGHT 128
#define KEY_MASK_PRONE 256
#define KEY_MASK_CROUCH 512
#define KEY_MASK_JUMP 1024
#define KEY_MASK_ADS_MODE 2048
#define KEY_MASK_TEMP_ACTION 4096
#define KEY_MASK_HOLDBREATH 8192
#define KEY_MASK_FRAG 16384
#define KEY_MASK_SMOKE 32768
#define KEY_MASK_NIGHTVISION 262144
#define KEY_MASK_ADS 524288
#define KEY_MASK_USE 8
#define KEY_MASK_USERELOAD 0x20

/* 9096 */
struct EntHandle

{
    unsigned __int16 number;
    unsigned __int16 infoIndex;
};

/* 9097 */
struct entityShared_t
{
    unsigned __int8 linked;
    unsigned __int8 bmodel;
    unsigned __int8 svFlags;
    int clientMask[2];
    unsigned __int8 inuse;
    int broadcastTime;
    float mins[3];
    float maxs[3];
    int contents;
    float absmin[3];
    float absmax[3];
    float currentOrigin[3];
    float currentAngles[3];
    EntHandle ownerNum;
    int eventTime;
};

static_assert(sizeof(entityShared_t) == 0x0068, "size of entityShared_t is not 0x0068");

/* 662 */
enum OffhandSecondaryClass : __int32
{
    PLAYER_OFFHAND_SECONDARY_SMOKE = 0x0,
    PLAYER_OFFHAND_SECONDARY_FLASH = 0x1,
    PLAYER_OFFHAND_SECONDARIES_TOTAL = 0x2,
};

/* 663 */
enum ViewLockTypes : __int32
{
    PLAYERVIEWLOCK_NONE = 0x0,
    PLAYERVIEWLOCK_FULL = 0x1,
    PLAYERVIEWLOCK_WEAPONJITTER = 0x2,
    PLAYERVIEWLOCKCOUNT = 0x3,
};

/* 665 */
enum team_t : __int32
{
    TEAM_FREE = 0x0,
    TEAM_AXIS = 0x1,
    TEAM_ALLIES = 0x2,
    TEAM_SPECTATOR = 0x3,
    TEAM_NUM_TEAMS = 0x4,
};

/* 8733 */
struct SprintState
{
    int sprintButtonUpRequired;
    int sprintDelay;
    int lastSprintStart;
    int lastSprintEnd;
    int sprintStartMaxLength;
};

/* 8734 */
struct MantleState
{
    float yaw;
    int timer;
    int transIndex;
    int flags;
};

/* 664 */
enum ActionSlotType : __int32
{
    ACTIONSLOTTYPE_DONOTHING = 0x0,
    ACTIONSLOTTYPE_SPECIFYWEAPON = 0x1,
    ACTIONSLOTTYPE_ALTWEAPONTOGGLE = 0x2,
    ACTIONSLOTTYPE_NIGHTVISION = 0x3,
    ACTIONSLOTTYPECOUNT = 0x4,
};

/* 8721 */
struct ActionSlotParam_SpecifyWeapon
{
    unsigned int index;
};

/* 8735 */
struct ActionSlotParam
{
    ActionSlotParam_SpecifyWeapon specifyWeapon;
};

/* 660 */
enum objectiveState_t : __int32
{
    OBJST_EMPTY = 0x0,
    OBJST_ACTIVE = 0x1,
    OBJST_INVISIBLE = 0x2,
    OBJST_DONE = 0x3,
    OBJST_CURRENT = 0x4,
    OBJST_FAILED = 0x5,
    OBJST_NUMSTATES = 0x6,
};

/* 8736 */
struct objective_t
{
    objectiveState_t state;
    float origin[3];
    int entNum;
    int teamNum;
    int icon;
};

/* 667 */
enum he_type_t : __int32
{
    HE_TYPE_FREE = 0x0,
    HE_TYPE_TEXT = 0x1,
    HE_TYPE_VALUE = 0x2,
    HE_TYPE_PLAYERNAME = 0x3,
    HE_TYPE_MAPNAME = 0x4,
    HE_TYPE_GAMETYPE = 0x5,
    HE_TYPE_MATERIAL = 0x6,
    HE_TYPE_TIMER_DOWN = 0x7,
    HE_TYPE_TIMER_UP = 0x8,
    HE_TYPE_TENTHS_TIMER_DOWN = 0x9,
    HE_TYPE_TENTHS_TIMER_UP = 0xA,
    HE_TYPE_CLOCK_DOWN = 0xB,
    HE_TYPE_CLOCK_UP = 0xC,
    HE_TYPE_WAYPOINT = 0xD,
    HE_TYPE_COUNT = 0xE,
};

/* 8713 */
struct $0D0CB43DF22755AD856C77DD3F304010
{
    unsigned __int8 r;
    unsigned __int8 g;
    unsigned __int8 b;
    unsigned __int8 a;
};

/* 8714 */
union hudelem_color_t {
    $0D0CB43DF22755AD856C77DD3F304010 __s0;
    int rgba;
};

/* 8737 */
struct hudelem_s
{
    he_type_t type;
    float x;
    float y;
    float z;
    int targetEntNum;
    float fontScale;
    int font;
    int alignOrg;
    int alignScreen;
    hudelem_color_t color;
    hudelem_color_t fromColor;
    int fadeStartTime;
    int fadeTime;
    int label;
    int width;
    int height;
    int materialIndex;
    int offscreenMaterialIdx;
    int fromWidth;
    int fromHeight;
    int scaleStartTime;
    int scaleTime;
    float fromX;
    float fromY;
    int fromAlignOrg;
    int fromAlignScreen;
    int moveStartTime;
    int moveTime;
    int time;
    int duration;
    float value;
    int text;
    float sort;
    hudelem_color_t glowColor;
    int fxBirthTime;
    int fxLetterTime;
    int fxDecayStartTime;
    int fxDecayDuration;
    int soundID;
    int flags;
};

typedef struct hudElemState_t
{
    hudelem_s current[31];
    hudelem_s archival[31];
};

struct playerState_s
{
    int commandTime;
    int pm_type;
    int bobCycle;
    int pm_flags;
    int weapFlags;
    int otherFlags;
    int pm_time;
    float origin[3];
    float velocity[3];
    float oldVelocity[2];
    int weaponTime;
    int weaponDelay;
    int grenadeTimeLeft;
    int throwBackGrenadeOwner;
    int throwBackGrenadeTimeLeft;
    int weaponRestrictKickTime;
    int foliageSoundTime;
    int gravity;
    float leanf;
    int speed;
    float delta_angles[3];
    int groundEntityNum;
    float vLadderVec[3];
    int jumpTime;
    float jumpOriginZ;
    int legsTimer;
    int legsAnim;
    int torsoTimer;
    int torsoAnim;
    int legsAnimDuration;
    int torsoAnimDuration;
    int damageTimer;
    int damageDuration;
    int flinchYawAnim;
    int movementDir;
    int eFlags;
    int eventSequence;
    int events[4];
    unsigned int eventParms[4];
    int oldEventSequence;
    int clientNum;
    int offHandIndex;
    OffhandSecondaryClass offhandSecondary;
    unsigned int weapon;
    int weaponstate;
    unsigned int weaponShotCount;
    float fWeaponPosFrac;
    int adsDelayTime;
    int spreadOverride;
    int spreadOverrideState;
    int viewmodelIndex;
    float viewangles[3];
    int viewHeightTarget;
    float viewHeightCurrent;
    int viewHeightLerpTime;
    int viewHeightLerpTarget;
    int viewHeightLerpDown;
    float viewAngleClampBase[2];
    float viewAngleClampRange[2];
    int damageEvent;
    int damageYaw;
    int damagePitch;
    int damageCount;
    int stats[5];
    int ammo[128];
    int ammoclip[128];
    unsigned int weapons[4];
    unsigned int weaponold[4];
    unsigned int weaponrechamber[4];
    float proneDirection;
    float proneDirectionPitch;
    float proneTorsoPitch;
    ViewLockTypes viewlocked;
    int viewlocked_entNum;
    int cursorHint;
    int cursorHintString;
    int cursorHintEntIndex;
    int iCompassPlayerInfo;
    int radarEnabled;
    int locationSelectionInfo;
    SprintState sprintState;
    float fTorsoPitch;
    float fWaistPitch;
    float holdBreathScale;
    int holdBreathTimer;
    float moveSpeedScaleMultiplier;
    MantleState mantleState;
    float meleeChargeYaw;
    int meleeChargeDist;
    int meleeChargeTime;
    int perks;
    ActionSlotType actionSlotType[4];
    ActionSlotParam actionSlotParam[4];
    int entityEventSequence;
    int weapAnim;
    float aimSpreadScale;
    int shellshockIndex;
    int shellshockTime;
    int shellshockDuration;
    float dofNearStart;
    float dofNearEnd;
    float dofFarStart;
    float dofFarEnd;
    float dofNearBlur;
    float dofFarBlur;
    float dofViewmodelStart;
    float dofViewmodelEnd;
    int hudElemLastAssignedSoundID;
    objective_t objective[16];
    unsigned __int8 weaponmodels[128];
    int deltaTime;
    int killCamEntity;
    hudElemState_t hud;
};

/* 770 */
enum clientConnected_t : __int32
{
    CON_DISCONNECTED = 0x0,
    CON_CONNECTING = 0x1,
    CON_CONNECTED = 0x2,
};

/* 771 */
enum sessionState_t : __int32
{
    SESS_STATE_PLAYING = 0x0,
    SESS_STATE_DEAD = 0x1,
    SESS_STATE_SPECTATOR = 0x2,
    SESS_STATE_INTERMISSION = 0x3,
};

/* 8748 */
struct __declspec(align(2)) usercmd_s
{
    int serverTime;
    int buttons;
    int angles[3];
    unsigned __int8 weapon;
    unsigned __int8 offHandIndex;
    char forwardmove;
    char rightmove;
    float meleeChargeYaw;
    unsigned __int8 meleeChargeDist;
    char selectedLocation[2];
};

static_assert(sizeof(usercmd_s) == 0x0020, "Size of usercmd_s must be 0x0020 (32 bytes).");

/* 9099 */
struct playerTeamState_t
{
    int location;
};

/* 8741 */
struct clientState_s
{
    int clientIndex;
    team_t team;
    int modelindex;
    int attachModelIndex[6];
    int attachTagIndex[6];
    char name[32];
    float maxSprintTimeMultiplier;
    int rank;
    int prestige;
    int perks;
    int voiceConnectivityBits;
    char clanAbbrev[8];
    int attachedVehEntNum;
    int attachedVehSlotIndex;
};

/* 9100 */
struct clientSession_t
{
    sessionState_t sessionState; // correct
    int forceSpectatorClient;
    int killCamEntity;
    int status_icon;
    int archiveTime;
    int score;
    int deaths;
    int kills;
    int assists;
    unsigned __int16 scriptPersId;
    clientConnected_t connected;
    usercmd_s cmd;
    usercmd_s oldcmd;
    int localClient;
    int predictItemPickup;
    char newnetname[32];
    int maxHealth;
    int enterTime;
    playerTeamState_t teamState;
    int voteCount;
    int teamVoteCount;
    float moveSpeedScaleMultiplier;
    int viewmodelIndex;
    int noSpectate;
    int teamInfo;
    clientState_s cs;
    int psOffsetTime;
};

struct gentity_s;

struct gclient_s
{
    playerState_s ps;
    char _pad[0x04]; // not sure in correct position but retail TU4 size is 4 bytes larger
    clientSession_t sess;
    int spectatorClient;
    int noclip; // 0x30a8
    int ufo;    // 0x30ac
    int bFrozen;
    int lastCmdTime;
    int buttons;
    int oldbuttons;
    int latched_buttons;
    int buttonsSinceLastFrame;
    float oldOrigin[3];
    float fGunPitch;
    float fGunYaw;
    int damage_blood;
    float damage_from[3];
    int damage_fromWorld;
    int accurateCount;
    int accuracy_shots;
    int accuracy_hits;
    int inactivityTime;
    int inactivityWarning;
    int lastVoiceTime;
    int switchTeamTime;
    float currentAimSpreadScale;
    gentity_s *persistantPowerup;
    int portalID;
    int dropWeaponTime;
    int sniperRifleFiredTime;
    float sniperRifleMuzzleYaw;
    int PCSpecialPickedUpCount;
    EntHandle useHoldEntity;
    int useHoldTime;
    int useButtonDone;
    int iLastCompassPlayerInfoEnt;
    int compassPingTime;
    int damageTime;
    float v_dmg_roll;
    float v_dmg_pitch;
    float swayViewAngles[3];
    float swayOffset[3];
    float swayAngles[3];
    float vLastMoveAng[3];
    float fLastIdleFactor;
    float vGunOffset[3];
    float vGunSpeed[3];
    int weapIdleTime;
    int lastServerTime;
    int lastSpawnTime;
    unsigned int lastWeapon;
    bool previouslyFiring;
    bool previouslyUsingNightVision;
    bool previouslySprinting;
    int hasRadar;
    int lastStand;
    int lastStandTime;
};

static_assert(offsetof(gclient_s, noclip) == 0x30a8, "");
static_assert(offsetof(gclient_s, ufo) == 0x30ac, "");
static_assert(sizeof(gclient_s) == 12724, "Size of gclient_s must be 12724.");

static_assert(offsetof(gclient_s, sess) + offsetof(clientSession_t, cmd) == 12180, "sess.cmd is not at offset 12180");
static_assert(offsetof(gclient_s, sess) + offsetof(clientSession_t, archiveTime) == 12152, "sess.cmd is not at offset 12152");

struct gentity_s
{
    // entityState_s s;
    char _pad[0x00F4]; // 0x0000, 0x00F4
    entityShared_t r;  // 0x00F4, 0x0068
    gclient_s *client; // 0x015c, 0x0004
};

static_assert(offsetof(gentity_s, client) == 0x0015C, "client is not at the correct offset 0x0015C");

/* 671 */
enum netsrc_t : __int32
{
    NS_CLIENT1 = 0x0,
    NS_CLIENT2 = 0x1,
    NS_CLIENT3 = 0x2,
    NS_CLIENT4 = 0x3,
    NS_SERVER = 0x4,
    NS_MAXCLIENTS = 0x4,
    NS_PACKET = 0x5,
};

/* 659 */
enum netadrtype_t : __int32
{
    NA_BOT = 0x0,
    NA_BAD = 0x1,
    NA_LOOPBACK = 0x2,
    NA_BROADCAST = 0x3,
    NA_IP = 0x4,
};

/* 8757 */
struct __declspec(align(4)) netadr_t
{
    netadrtype_t type;
    unsigned __int8 ip[4];
    unsigned __int16 port;
};

/* 8723 */
struct netProfilePacket_t
{
    int iTime;
    int iSize;
    int bFragment;
};

/* 8724 */
struct netProfileStream_t
{
    netProfilePacket_t packets[60];
    int iCurrPacket;
    int iBytesPerSecond;
    int iLastBPSCalcTime;
    int iCountedPackets;
    int iCountedFragments;
    int iFragmentPercentage;
    int iLargestPacket;
    int iSmallestPacket;
};

/* 8755 */
struct netProfileInfo_t
{
    netProfileStream_t send;
    netProfileStream_t recieve;
};

/* 8758 */
struct netchan_t
{
    int outgoingSequence;
    netsrc_t sock;
    int dropped;
    int incomingSequence;
    netadr_t remoteAddress;
    int fragmentSequence;
    int fragmentLength;
    unsigned __int8 *fragmentBuffer;
    int fragmentBufferSize;
    int unsentFragments;
    int unsentFragmentStart;
    int unsentLength;
    unsigned __int8 *unsentBuffer;
    int unsentBufferSize;
    netProfileInfo_t prof;
};

/* 9758 */
const struct clientHeader_t
{
    int state;
    int sendAsActive;
    int deltaMessage;
    int rateDelayed;
    netchan_t netchan;
    float predictedOrigin[3];
    int predictedOriginServerTime;
};

static_assert(offsetof(clientHeader_t, deltaMessage) == 0x8, "");

/* 9760 */
struct svscmd_info_t
{
    char cmd[1024];
    int time;
    int type;
};

struct __declspec(align(4)) client_t
{
    // char _pad[0x20E5C];
    clientHeader_t header;
    const char *dropReason;
    char userinfo[1024];
    svscmd_info_t reliableCommandInfo[128];
    int reliableSequence;
    int reliableAcknowledge;
    int reliableSent;
    int messageAcknowledge;
    int gamestateMessageNum;
    int challenge;
    usercmd_s lastUsercmd;              // 0x20E5C, 0x0020
    int lastClientCommand;              // 0x20E7C, 0x0004
    char lastClientCommandString[1024]; // 0x20E80, 0x0004
    gentity_s *gentity;                 // 0x21280, 0x0004
    char name[32];                      // 0x21284, 0x0020
    char _padding[0x819e4];             // Padding to reach 666760 bytes
};

static_assert(sizeof(client_t) == 666760, "Size of client_t must be 666760.");
static_assert(offsetof(client_t, gentity) == 0x21280, "");

/* 9124 */
struct level_locals_t
{
    gclient_s *clients;
    gentity_s *gentities;
    int gentitySize;
    int num_entities;
    gentity_s *firstFreeEnt;
    gentity_s *lastFreeEnt;
};

struct entityState_s;
struct clientState_s;
struct svEntity_s;
struct archivedEntity_s;
struct cachedClient_s;
struct cachedSnapshot_t;

/* 9766 */
struct serverStaticHeader_t
{
    client_t *clients;
    int time;
    int snapFlagServerBit;
    int numSnapshotEntities;
    int numSnapshotClients;
    int nextSnapshotEntities;
    entityState_s *snapshotEntities;
    clientState_s *snapshotClients;
    svEntity_s *svEntities;
    float mapCenter[3];
    archivedEntity_s *cachedSnapshotEntities;
    cachedClient_s *cachedSnapshotClients;
    unsigned __int8 *archivedSnapshotBuffer;
    cachedSnapshot_t *cachedSnapshotFrames;
    int nextCachedSnapshotFrames;
    int nextArchivedSnapshotFrames;
    int nextCachedSnapshotEntities;
    int nextCachedSnapshotClients;
    int num_entities;
    int maxclients;
    int fps;
    int clientArchive;
    gentity_s *gentities;
    int gentitySize;
    clientState_s *firstClientState;
    playerState_s *firstPlayerState;
    int clientSize;
    unsigned int pad[3];
};

static_assert(sizeof(serverStaticHeader_t) == 0x0080, "Size of serverStaticHeader_t must be 0x0080.");

struct scr_entref_t
{
    unsigned __int16 entnum;
    unsigned __int16 classnum;
};

typedef void (*xfunction_t)(scr_entref_t);

enum svscmd_type
{
    SV_CMD_CAN_IGNORE = 0x0,
    SV_CMD_RELIABLE = 0x1,
};

struct cmd_function_s
{
    cmd_function_s *next;
    const char *name;
    const char *autoCompleteDir;
    const char *autoCompleteExt;
    void(__cdecl *function)();
};

gentity_s *(*GetEntity)(scr_entref_t *entref) = reinterpret_cast<gentity_s *(*)(scr_entref_t *)>(0x82257F30);
void (*CG_GameMessage)(int localClientNum, const char *msg) = reinterpret_cast<void (*)(int localClientNum, const char *msg)>(0x8230AAF0);
void (*SV_ExecuteClientCommand)(client_t *cl, const char *s, int clientOK) = reinterpret_cast<void (*)(client_t *cl, const char *s, int clientOK)>(0x82208088);
void (*SV_GameSendServerCommand)(int clientNum, svscmd_type type, const char *text) = reinterpret_cast<void (*)(int clientNum, svscmd_type type, const char *text)>(0x82204BB8);
void (*Cbuf_AddText)(int localClientNum, const char *text) = reinterpret_cast<void (*)(int localClientNum, const char *text)>(0x82239FD0);
char *(*Scr_GetString)(unsigned int index) = reinterpret_cast<char *(*)(unsigned int index)>(0x82211390);
void (*Scr_ObjectError)(const char *error) = reinterpret_cast<void (*)(const char *error)>(0x8220FDD0);
// void (*ClientCommand)(int clientNum) = reinterpret_cast<void (*)(int clientNum)>(0x8227DCF0);
void (*SV_Cmd_ArgvBuffer)(int arg, char *buffer, int bufferLength) = reinterpret_cast<void (*)(int arg, char *buffer, int bufferLength)>(0x82239F48);
int (*I_strnicmp)(const char *s0, const char *s1, int n) = reinterpret_cast<int (*)(const char *s0, const char *s1, int n)>(0x821CDA98);
void (*Scr_AddBool)(int value) = reinterpret_cast<void (*)(int value)>(0x82211238);
void (*SV_ClientThink)(client_t *cl, usercmd_s *cmd) = reinterpret_cast<void (*)(client_t *cl, usercmd_s *cmd)>(0x82208448);

cmd_function_s *cmd_functions = reinterpret_cast<cmd_function_s *>(0x82A2335C);
gentity_s *g_entities = reinterpret_cast<gentity_s *>(0x8287CD08);
serverStaticHeader_t *svsHeader = reinterpret_cast<serverStaticHeader_t *>(0x849F1580);
level_locals_t *level = reinterpret_cast<level_locals_t *>(0x82A07650);

client_t *GetClientAtIndex(int index)
{
    size_t clientSize = 666760;
    client_t *baseClient = svsHeader->clients;
    client_t *clientAtIndex = (client_t *)((unsigned char *)baseClient + (index * clientSize));
    return clientAtIndex;
}

gclient_s *GetGclientAtIndex(int index)
{
    size_t clientSize = 12724;
    gclient_s *baseClient = level->clients;
    gclient_s *clientAtIndex = (gclient_s *)((unsigned char *)baseClient + (index * clientSize));
    return clientAtIndex;
}

void GScr_ExecuteClientCommand(scr_entref_t entref)
{
    gentity_s *ent = GetEntity(0);

    // todo: find address for Scr_GetNumParam
    // if (Scr_GetNumParam() != 1)
    // {
    //     Scr_ObjectError("Usage: SendCommand( string )");
    //     return;
    // }

    char *cmd = Scr_GetString(0);

    // CG_GameMessage(0, cmd);

    // TODO: this works but it needs special formatting for a client command?
    // SV_ExecuteClientCommand(reinterpret_cast<client_t*>(0xB112AD68), cmd, 1);
    int clientNum = ent - g_entities;
    Cbuf_AddText(clientNum, cmd);
}

void Cmd_AddCommand(const char *name)
{
    cmd_function_s *cmd = new cmd_function_s;
    cmd->name = name;
    cmd->autoCompleteDir = nullptr;
    cmd->autoCompleteExt = nullptr;
    cmd->function = 0;   // Handled in ClientCommandHook since we need to pass gentity_s
    cmd->next = nullptr; // Since it's the last item, next should be null

    // Traverse the list to find the last element
    cmd_function_s *current = cmd_functions;
    while (current->next != nullptr)
        current = current->next;

    current->next = cmd;
}

void Cmd_Noclip_f(gentity_s *ent)
{
    int current = ent->client->noclip;
    ent->client->noclip = current == 0;
    int clientNum = ent - g_entities;
    if (current)
        SV_GameSendServerCommand(clientNum, SV_CMD_CAN_IGNORE, "e \"GAME_NOCLIPOFF\"");
    else
        SV_GameSendServerCommand(clientNum, SV_CMD_CAN_IGNORE, "e \"GAME_NOCLIPON\"");
}

void Cmd_UFO_f(gentity_s *ent)
{
    int current = ent->client->ufo;
    ent->client->ufo = current == 0;
    int clientNum = ent - g_entities;
    if (current)
        SV_GameSendServerCommand(clientNum, SV_CMD_CAN_IGNORE, "e \"GAME_UFOOFF\"");
    else
        SV_GameSendServerCommand(clientNum, SV_CMD_CAN_IGNORE, "e \"GAME_UFOON\"");
}

void GScr_testfunction(scr_entref_t entref)
{
    // client_t *cl = GetClientAtIndex(entref.entnum);
    // std::cout << "scr_entref_t address: " << entref << std::endl;
    // gentity_s *gent = GetEntity(entref);

    std::cout << "Size of playerState_s: " << sizeof(playerState_s) << " bytes" << std::endl;
    std::cout << "Size of clientSession_t: " << sizeof(clientSession_t) << " bytes" << std::endl;
    std::cout << "Size of client_t: " << sizeof(client_t) << " bytes" << std::endl;
}

void PlayerCmd_JumpButtonPressed(scr_entref_t entref)
{
    // if (Scr_GetNumParam())
    //     Scr_Error("Usage: <client> JumpButtonPressed()\n");

    client_t *cl = GetClientAtIndex(entref.entnum);

    if (!cl)
        Scr_ObjectError("not a client\n");

    Scr_AddBool(cl->lastUsercmd.buttons & KEY_MASK_JUMP);
}

void PlayerCmd_HoldBreathButtonPressed(scr_entref_t entref)
{
    // if (Scr_GetNumParam())
    //     Scr_Error("Usage: <client> HoldBreathButtonPressed()\n");

    client_t *cl = GetClientAtIndex(entref.entnum);

    if (!cl)
        Scr_ObjectError("not a client\n");

    Scr_AddBool(cl->lastUsercmd.buttons & KEY_MASK_HOLDBREATH);
}

void PlayerCmd_LeanLeftButtonPressed(scr_entref_t entref)
{
    // if (Scr_GetNumParam())
    //     Scr_Error("Usage: <client> LeanLeftButtonPressed()\n");

    client_t *cl = GetClientAtIndex(entref.entnum);

    if (!cl)
        Scr_ObjectError("not a client\n");

    Scr_AddBool(cl->lastUsercmd.buttons & KEY_MASK_LEANLEFT);
}

void PlayerCmd_LeanRightButtonPressed(scr_entref_t entref)
{
    // if (Scr_GetNumParam())
    //     Scr_Error("Usage: <client> LeanRightButtonPressed()\n");

    client_t *cl = GetClientAtIndex(entref.entnum);

    if (!cl)
        Scr_ObjectError("not a client\n");

    Scr_AddBool(cl->lastUsercmd.buttons & KEY_MASK_LEANRIGHT);
}

Detour *pScr_GetMethodDetour = nullptr;

xfunction_t Scr_GetMethodHook(const char **pName, int *type)
{
    xfunction_t ret = pScr_GetMethodDetour->GetOriginal<decltype(&Scr_GetMethodHook)>()(pName, type);

    if (ret)
        return ret;

    if (std::strcmp(*pName, "executeclientcommand") == 0)
        return &GScr_ExecuteClientCommand;

    if (std::strcmp(*pName, "testfunction") == 0)
        return &GScr_testfunction;

    if (std::strcmp(*pName, "jumpbuttonpressed") == 0)
        return &PlayerCmd_JumpButtonPressed;

    if (std::strcmp(*pName, "holdbreathbuttonpressed") == 0)
        return &PlayerCmd_HoldBreathButtonPressed;

    if (std::strcmp(*pName, "leanleftbuttonpressed") == 0)
        return &PlayerCmd_LeanLeftButtonPressed;

    if (std::strcmp(*pName, "leanrightbuttonpressed") == 0)
        return &PlayerCmd_LeanRightButtonPressed;

    return ret;
}

Detour *pClientCommandDetour = nullptr;

void ClientCommandHook(int clientNum)
{
    gentity_s *ent = &g_entities[clientNum];
    // std::cout << "ClientCommandHook clientNum: " << clientNum << std::endl;
    // std::cout << "ClientCommandHook ent: " << ent << std::endl;

    char cmd[1032];
    SV_Cmd_ArgvBuffer(0, cmd, 1024);

    // std::cout << "ClientCommand: " << cmd << std::endl;

    if (I_strnicmp(cmd, "noclip", 6) == 0)
        Cmd_Noclip_f(ent);

    else if (I_strnicmp(cmd, "ufo", 3) == 0)
        Cmd_UFO_f(ent);

    else
        pClientCommandDetour->GetOriginal<decltype(&ClientCommandHook)>()(clientNum);
}

void printUserCmd(const usercmd_s *cmd)
{
    std::cout << "cmd->serverTime: " << cmd->serverTime << std::endl;
    std::cout << "cmd->buttons: " << cmd->buttons << std::endl;
    std::cout << "cmd->angles: [" << cmd->angles[0] << ", " << cmd->angles[1] << ", " << cmd->angles[2] << "]" << std::endl;
    std::cout << "cmd->weapon: " << static_cast<int>(cmd->weapon) << std::endl;
    std::cout << "cmd->offHandIndex: " << static_cast<int>(cmd->offHandIndex) << std::endl;
    std::cout << "cmd->forwardmove: " << static_cast<int>(cmd->forwardmove) << std::endl;
    std::cout << "cmd->rightmove: " << static_cast<int>(cmd->rightmove) << std::endl;
    std::cout << "cmd->meleeChargeYaw: " << cmd->meleeChargeYaw << std::endl;
    std::cout << "cmd->meleeChargeDist: " << static_cast<int>(cmd->meleeChargeDist) << std::endl;
    std::cout << "cmd->selectedLocation: [" << static_cast<int>(cmd->selectedLocation[0]) << ", " << static_cast<int>(cmd->selectedLocation[1]) << "]" << std::endl;
}

Detour *pSV_BotUserMoveDetour = nullptr;

bool doneOnce = false;

void SV_BotUserMoveHook(client_t *cl)
{
    // if (!doneOnce)
    // {
    //     pSV_BotUserMoveDetour->GetOriginal<decltype(&SV_BotUserMoveHook)>()(cl);
    //     doneOnce = true;
    //     printUserCmd(&cl->lastUsercmd);
    //     std::cout << std::endl;
    //     std::cout << std::endl;
    // };

    // printUserCmd(&cl->lastUsercmd);

    if (!cl->gentity)
        return;

    gclient_s *gclient = GetGclientAtIndex(1);
    std::cout << gclient << std::endl;

    if (gclient->sess.archiveTime == 0)
    {
        usercmd_s cmd = {
            0,               // serverTime
            0,               // buttons
            { 0, -27, 260 }, // angles
            0,               // weapon
            0,               // offHandIndex
            0,               // forwardmove
            0,               // rightmove
            0.0f,            // meleeChargeYaw
            0,               // meleeChargeDist
            { 0, 0 }         // selectedLocation
        };
        cmd.buttons |= KEY_MASK_JUMP;
        printUserCmd(&cmd);
        std::cout << std::endl;
        cl->header.deltaMessage = cl->header.netchan.outgoingSequence - 1;
        SV_ClientThink(cl, &cmd);
    }
}

// if(level.clients)

// usercmd_s cmd = {
//     0,              // serverTime
//     KEY_MASK_JUMP,  // buttons
//     { 0, -145, 0 }, // angles
//     15,             // weapon
//     0,              // offHandIndex
//     127,            // forwardmove
//     0,              // rightmove
//     0.0f,           // meleeChargeYaw
//     0,              // meleeChargeDist
//     { 0, 0 }        // selectedLocation
// };
// cl->header.deltaMessage = cl->header.netchan.outgoingSequence - 1;
// SV_ClientThink(cl, &cmd);

// usercmd_s cmd = cl->lastUsercmd;
// cmd.serverTime = svsHeader->time;
// cmd.buttons = 1024;

// cl->header.deltaMessage = cl->header.netchan.outgoingSequence - 1;

// cl->header.deltaMessage = cl->header.netchan.outgoingSequence - 1;

// usercmd_s cmd = { 0 };
// cmd.serverTime = svsHeader->time;
// cmd.buttons = 1024;
// cmd.angles = cl->lastUsercmd->angles;
// cmd.weapon = cl->lastUsercmd->weapon;
// cmd.offHandIndex = cl->lastUsercmd->offHandIndex;
// cmd.forwardmove = cl->lastUsercmd->forwardmove;
// cmd.rightmove = cl->lastUsercmd->rightmove;
// cmd.meleeChargeYaw = cl->lastUsercmd->meleeChargeYaw;
// cmd.meleeChargeDist = cl->lastUsercmd->meleeChargeDist;
// cmd.selectedLocation = cl->lastUsercmd->selectedLocation;

// usercmd_s cmd = cl->lastUsercmd;
// cmd.buttons = 1024;               // New buttons value
// cmd.serverTime = svsHeader->time; // New server time value

// printUserCmd(&cl->lastUsercmd);
// std::cout << std::endl;

// long *deltaMessage = (long *)((char *)cl + 0x08);
// long *outgoingSequence = (long *)((char *)cl + 0x10);

// *deltaMessage = *outgoingSequence - 1;

// // client -> deltaMessage = 00000008
// // client->netchan.outgoingSequence = 00000010
// // client->deltaMessage = client->netchan.outgoingSequence - 1;

// SV_ClientThink(cl, &cmd);

// noop to prevent bots random movement
// pSV_BotUserMoveDetour->GetOriginal<decltype(&SV_BotUserMoveHook)>()(cl);

// Sets up the hook
void InitIW3()
{
    // Waiting a little bit for the game to be fully loaded in memory
    Sleep(1000);
    XNotifyQueueUI(0, 0, XNOTIFY_SYSTEM, L"iw3xenon loaded - by mo", nullptr);

    pScr_GetMethodDetour = new Detour(0x822570E0, Scr_GetMethodHook);
    pScr_GetMethodDetour->Install();

    pClientCommandDetour = new Detour(0x8227DCF0, ClientCommandHook);
    pClientCommandDetour->Install();

    pSV_BotUserMoveDetour = new Detour(0x822009A8, SV_BotUserMoveHook);
    pSV_BotUserMoveDetour->Install();

    Cmd_AddCommand("noclip");
    Cmd_AddCommand("ufo");
}

int DllMain(HANDLE hModule, DWORD reason, void *pReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        // Runs MonitorTitleId in separate thread
        ExCreateThread(nullptr, 0, nullptr, nullptr, reinterpret_cast<PTHREAD_START_ROUTINE>(MonitorTitleId), nullptr, 2);
        break;
    case DLL_PROCESS_DETACH:
        g_Running = false;

        if (pScr_GetMethodDetour)
            delete pScr_GetMethodDetour;

        if (pClientCommandDetour)
            delete pClientCommandDetour;

        if (pSV_BotUserMoveDetour)
            delete pSV_BotUserMoveDetour;

        // We give the system some time to clean up the thread before exiting
        Sleep(250);
        break;
    }

    return TRUE;
}
