// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Copyright (c) 2021-2022 The DECENOMY Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "chainparamsseeds.h"
#include "consensus/merkle.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>

#include <assert.h>

#define DISABLED 0x7FFFFFFE;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of the genesis coinbase cannot
 * be spent as it did not originally exist in the database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
	// pszTimestamp = Headline: https://cointelegraph.com/news/another-defi-exit-scam-just-made-off-with-20m-in-investor-funds
    const char* pszTimestamp = "COINTELEGRAPH 10/Sep/2020 Another DeFi exit scam just made off with $20M in investor funds";
    const CScript genesisOutputScript = CScript() << ParseHex("0448790ec8f49697a1b0089fd998e932231ba4728c8c3edc2b50b65821e58b441117036ff66337ea5021baf94e29ea83117e885d67018654d0869bbe2eb1d74dd6") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256S("00000551e93eb0749d40dfafd54b092e78d6612b47bd40de8d099818f65f53c1"))
    (17431, uint256S("756fc5a48231f0a7422de24f5801e0c4ca8a14b428789b9e196c35fa7864eef5"))
    (34863, uint256S("e41a7cd96e0a0bf01781243fc0ee7297d18891deacd0c4442ef39c7a3fe80332"))
    (52295, uint256S("498140ca2fdce8a437e604019492469cf09e875ed11afbbfbe58b6d2dec5f3bc"))
    (69727, uint256S("3b263bc8a912f5ee84eb0875aab5b982bf8c9c221d05e808a47ea2b25dc0b2b6"))
    (87159, uint256S("bb0447caa8ef1f279b15a7bd8538095161563d073dfed79977de9bee0aa8947d"))
    (104591, uint256S("2d25725c9be9e0dfdb003ceabda41b017e427a732260ed203fb7a83b2a798860"))
    (122023, uint256S("5200c64ca58efdabfa15bc97b496347b0cbb1aa65924dd29c2823ac1668736ac"))
    (139455, uint256S("5cd4a4025cae96dd4dd852a95b2ca132ff765204b762dacf01824ad7205b5c41"))
    (156887, uint256S("ed0e2ec69bcf4b6387601e48a68ccf987a71bd745081013d1f2a257e11fcce0d"))
    (174319, uint256S("1b61207ab3b14960cbe33b7148b65a8e88b62b44392fc7f2192a55322e3f43aa"))
    (191751, uint256S("a0df3dd4450523bfb96133bb18d3dcf751cfcc315fe7eb3ec9ba6fddfffaae9d"))
    (209183, uint256S("a646267e876ce897593af5353ac8e3fbb72435ae0a16a39199fc9487e18f30fc"))
    (226615, uint256S("cc1056afa29a97510b4f695067a31a7af6f0cd5e2b33ac1cb38abf69575af79a"))
    (244047, uint256S("6cbc0b06cac64a8e853c12286012437ac1a8aa5c126f3b23ca7a07943d76c3e0"))
    (261479, uint256S("ed9ca144a4376812cf135fe4e258e78019bb5269f35fe1615d883e9861b02f68"))
    (278911, uint256S("512b3e0ca8cee19b9b19c464895defb00d774e72827ef84c8bcf08a5b152a09d"))
    (296343, uint256S("e22e78a53ad2821f9c5f1e5a96144a9eb34941b12cf1eaefb1ce3389a765036f"))
    (313775, uint256S("fe356746a37acdb63ba46bb4848b8830f172b300a91bb7fa25786a00dafc22fd"))
    (331207, uint256S("da8a0d76d5d1c7d1584964e2bde0273b52ba253803cf633a88e73268a5058c9e"))
    (348639, uint256S("97781bbf4e323570269a170f7ae599a93f0fb6cab19cf62874df94f97145a5f5"))
    (366071, uint256S("338114582c6af513f1d25618ff5ec4e9324b178cebe86f0cf250288855cc62e3"))
    (383503, uint256S("169e9f134643c5cbe1df1a0a0e2c2981558c7ac39444927317eb37e999353a56"))
    (400935, uint256S("5fe19a9634efbce37049804bb90dae8b1e95ccb084593419c5d67175873610f4"))
    (418367, uint256S("daa8ac9ad02f47e4f2e2a5a278f67a528c10773ffb6c09fab0f3005305db9f15"))
    (435799, uint256S("62f3cf203ab93313503ed8aae11176168df2d63e8716afb0f9f6b3e8af2f11d5"))
    (453231, uint256S("5031139828d7aaec0fc0c27dd63b0d0e98d40e592e16546f4e9b77b1ca73ee71"))
    (470663, uint256S("d5bc2a291b6c6564dbe80e67e2e150ffd2fe94657b99358f29d311d940001ac1"))
    (488095, uint256S("eb9af35f8a4247cf2afd5dd30aeb941e245ad686543b7cc5a2a5422619653e50"))
    (505527, uint256S("5fe30ace97370b5bf896d9f8dde9aee86c53db6420d2cc7229fded87c77875a0"))
    (522959, uint256S("4e55ebd7b189f116d5431d6e554049d9d43a0d7ffc78cef72ff8fbf546965db2"))
    (540391, uint256S("2a94be0b1b6c4f208fd05e001cb30cbfb5cf07213c1a90fce664b08c5e3b8f89"))
    (557823, uint256S("daa3a0a887b8d54e51836398a5cf4d37ecbe0eea2a9d24468e1477ca7afa8348"))
    (575255, uint256S("0d95e0183469bd2e9a6297975a2e5bcb91f568d165b02abdda9f4654cbffdce8"))
    (592687, uint256S("9a5ef0a5efd31b4c02dabef51696d55815bfafa604d435b80880e8e814a6358e"))
    (610119, uint256S("0394ec5a00450fd003f8c4f88ed1088e97ee5dff6ddbfbc16f01e510f582cdec"))
    (627551, uint256S("ae1850fae1587085f11e0fef7957255daf22456e9df57a0edcb34d407cb7d9ab"))
    (644983, uint256S("a4d989c067b929ac56b065a16a37cbb9d78d6447626696544c278b8602da435c"))
    (662415, uint256S("3338f0e7bc6f7326d2360be21ccf5944bead898162f63ed6a2fd281be06dc5fa"))
    (679847, uint256S("594a62eb358d0061b1b29174ec456f87eb7fe17001b2cdd2f725c565d7356c16"))
    (697279, uint256S("c11c23a1fae5582ba0e8fc780b773d7c4924d93ffff110ac6262d1b6ca243f92"))
    (714711, uint256S("07fde01496985fd13ebd9c809d576ba179c8828222b1d373acc06b72613b9957"))
    (732143, uint256S("195e8fdc5a8b7f7c8ca66c75d2db32ffec6f575701c22d663b687a123f24e755"))
    (749575, uint256S("e8217fac9a8df59f7748a891c5ec99261ddc6c48ae21c4f0965cc99dac826cd3"))
    (767007, uint256S("f3312329aab732b1d29fcb5885bb7bc07d5bf557b7ed6a16b723a44c665e9696"))
    (784439, uint256S("45d1be68043f13a59e8e65a5d8754402da2f9429466f211ae604a802268f7f42"))
    (801871, uint256S("ae1df919fae83fe5ea0c905af02d07c902e1c7daf565f944b54087b9f963d1a5"))
    (819303, uint256S("f4f16af660313ae3fc9d3a92a950a05b87d597c19d5d646804391bd7429730ba"))
    (836735, uint256S("dd8e1163e606183b8face59b7c699b263b1b357a54ac28e569b86e9a60ac954d"))
    (854167, uint256S("2f15f5d3ce263d88b770578bccd328eb6e7218451892b17eae0256c027317058"))
    (871599, uint256S("b68a15d84f758cb06dff5ad29e2e0827a101da68d51608a0137dd4aa6027b31d"))
    (889031, uint256S("5c0fa7e456238bbfe3ff47a48386baca9e3e1db19e52a440681ba1a38acfa546"))
    (906463, uint256S("3f138e3659ee678bc4c14609d5a72ebdf55621bca140448e7a73aff8b83d4d5b"))
    (923895, uint256S("172c5d90359a8ec818536b10efda507585485fe9399c9f88166ae2f803b1f037"))
    (941327, uint256S("21df23010e639ad1b43183632d381bf684fa5c131ec640093734ba4cd1aa9df5"))
    (958759, uint256S("08e584a345fe725f706066cd37a5ac494b0c5625521bdd596ef8466ce9e139f7"))
    (976191, uint256S("4553f387efda60fc49ddc47e50f9adae81b81c5e0030d7a62509eab9392403e2"))
    (993623, uint256S("80a2a1488ba2a874c078b351b106af3d343df9ec892dce56f145693d33851c1c"))
    (1011055, uint256S("71ab49555acab62274a650134666fbe26915c220a5213f50bd8c5a3a9ee2880a"))
    (1028487, uint256S("0e16dfcbc765112791ba1e3f580db284c2c627b66b1af06323ccda7ce0c1aeca"))
    (1045919, uint256S("9575b2a1be653b87a8c2fa26a675adb4c7123cf4b0e63ca760db6dcb964f5792"))
    (1063351, uint256S("4e3bd4d210997f145c6273e75a284633791f2c66352a78c26d4afab1b5057197"))
    (1080783, uint256S("37127bbe788576243a629a4135f0bb46cfea90101a0b7f4debdae5fc44f8de9f"))
    (1098215, uint256S("6dbbe155eb2a8bc5df5f961befaa98930a916023f038d5f672f07bd56ff48490"))
    (1115647, uint256S("266b1470d2d966e7e24bbfefb7698d4106839b41635c3c7aa979ad337065f38b"))
    (1133079, uint256S("b3533ebeb2176cb90ac20bc835b99b1830c0a5b003eeeeaf0f402c95229372a9"))
    (1150511, uint256S("9d638915dfbf0a29a828e85bb041494ede9a918c1193cc8f8348cf4811c833ac"))
    (1167943, uint256S("95161cc020a15fc1b70eb631ae733c4d225ddcdfad85ceb505dac3ace3b6ebdc"))
    (1185375, uint256S("d1f4603f8ce29f14800b12fa96f86c5849ba0138f87c0d56a1a912cdb2161725"))
    (1202807, uint256S("ae8136602f082fab203873b9f3a03a1dd3accc335ec51e033b8b8d08f7e19183"))
    (1220329, uint256S("6496d3bf8732be53932b18e9d9ec0d4ab6d32b340b6f2b9a45f871a2b2c2ffbf"))
    (1238010, uint256S("ac8062dcb632d697e098adcae4c389692b1ff9485daff1d0440812ab5a196fb2"))
    (1255596, uint256S("5902e3b09a831112d3de2fb63a2f098309caca0fb4b3770d3dcdf5ae0b0a5d05"))
    (1273262, uint256S("35ae6df0451fda29a77905d68fdbc81601ee5bc144bce0c79740d75861ca9347"))
    (1290999, uint256S("5f05eea97876e36bd561b95124502a159dc301040735dd7a658ecf1431d96db3"))
    (1308767, uint256S("5bfce49294053d4c1b8c5c1352cc7a25e925a880bd9c0ab259fa955b1b8f46ca"))
    (1326430, uint256S("66a1bb8752c31822bcb24fe6d14277ad58c4eb7eac514cf544bec27dfabe5e8c"))
    (1344290, uint256S("ae5b48605b3e3d85887c0de3e224c624d53e590b0942eb58f13d405d83222e34"))
    (1362088, uint256S("7b1fc39808be08824230ec044b0c1a45c0c09c03c48fe2273898207b4c9b05d7"))
    (1379749, uint256S("1da1779af8e2dfbfa2c2238b301cd9410d5b3ca1a9daf0dbe61b35c1cde0c815"))
    (1397474, uint256S("4c35578cbb7992e47886ea8b70cf279614fc5c278faccec623f55eb8fc7d4fe5"))
    (1415134, uint256S("3dfea97bace449be7b8428b02be382441c5f5c8099679ef390afe4090426bfca"))
    (1432804, uint256S("ab07a549799c17d0ca7af2ee72ba90b2f5b29ecd4ca4fd9de6f47bc5f85067be"))
    (1450531, uint256S("05674e36c4b5b8c550d12c96903350e5438b30bd809f57be1cce25405befced3"))
    (1468213, uint256S("89720c153a7340307fb3d89e65440a7c0c0a5dea019df9a17ab81a8f64aa4761"))
    (1485875, uint256S("45509c96f4bd58050bbc6f3a085ba4387fe5339c7cc63f1eee0069691b9ffc4a"))
    (1503603, uint256S("812d659d80a959d13c627942dc2100fa36db216c611abdfadd2379952981d31c"))
    (1523160, uint256S("880432f6423dff57e6d2601cfc0fd8dbf755933912991b1577b621330f1a597e"))
    (1543801, uint256S("54dd193918b2054e3d4898e9cee1678cff406096a02c67fa5089faa21bf7664c"))
    (1562794, uint256S("442489e61f88789e035daf652382937ddf7256a1ebb4c2fe6ebaecbdfa062df6"))
    (1581648, uint256S("4f743f3685d416d01762006383929f700b511bde331bcdec86cef1d616780eca"))
    (1600190, uint256S("94b5fc227c5a826967cc9fb2f14f8cda8c2ade60488e95b5fa96ea6277cde1e3"))
    (1618979, uint256S("e2c97d0a21599d46e167165dcd3c619a74c5c48479e0e5b2991c12bcefb96e1c"))
    (1637876, uint256S("6141d62052d23a1668f77c2386b7483244e25e9493e7d60983db44527016b5d8"))
    (1657688, uint256S("1c318090bbf5d777ec1525bcc03de940fc594cb066ba5954cd4daa2b745f80bb"))
    (1677186, uint256S("b5e2a4d63eecd596dd8efa74c56f8c7f4f2e5c1a89f1ae2ed58cc4b9944108d5"))
    (1696465, uint256S("0a5d75cd9193e0d4e61e9acf23b4649926b5b33e1c7275c234be53e0b60e810f"))
 ;

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1731999990, // * UNIX timestamp of last checkpoint block
    3583075,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the UpdateTip debug.log lines)
    2814        // * estimated number of transactions per day after checkpoint. 2000 for 10 minutes of bitcoin blockchain (1M block size). With 2M of block size and 1 minute of block time, this field should be around 4000 * 10 * 6 * 24 = 5760000
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    (0, uint256S("0x000000313693c8b25165dbdc8498b8c0084fa24ffea6a02765733700fbcf7467"))
;

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1599766365,
    0,
    2000};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of
    (0, uint256S("0x430fbdf677d8bd836bc104377a7ab86d62051d927c80315d30e2df6b09df8e7b"))
;

static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1625312841,
    0,
    2000};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        /**
         * Salute to old Kyanite code based on DASH code base.
         * Original chain launch was made on 10th of September, 2020 as the pszTimestamp headline.
         * Genesis block creation timestamp (1599766364) is reflecting that day.
         * Original chain consensus.hashGenesisBlock: 0x00000551e93eb0749d40dfafd54b092e78d6612b47bd40de8d099818f65f53c1
         * Original chain genesis.hashMerkleRoot: 0x17c6d46ee4758572534f6dec116f61268fe883caa99062c1efd764bbbc975d71
         * We keep both consensus.hashGenesisBlock and genesis.hashMerkleRoot of the original chain in the new DSW code base.
         */
        genesis = CreateGenesisBlock(1599766364, 112122, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000551e93eb0749d40dfafd54b092e78d6612b47bd40de8d099818f65f53c1"));
        assert(genesis.hashMerkleRoot == uint256S("0x17c6d46ee4758572534f6dec116f61268fe883caa99062c1efd764bbbc975d71"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = 9999999999 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nStakeMinAge = 60 * 60; // 1h
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 600;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.nRewardAdjustmentInterval = 7 * 1440;

        // spork keys
        consensus.strSporkPubKey = "035d8e6fdf6e463bc59d4efe4339de96b8274a911526348de46963511f5e6d6170";
        consensus.strSporkPubKeyOld = "035d8e6fdf6e463bc59d4efe4339de96b8274a911526348de46963511f5e6d6170";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // burn addresses
        consensus.mBurnAddresses = {
           { "KXBURNXXXXXXXXXXXXXXXXXXXXXXWJmF2X", 0 }
        };

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                   = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight              = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                    = 1001;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                 = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                  = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight      = 1541;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight       = 1641;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight = 1741;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight     = 5001;
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].nActivationHeight     = 3001;
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_REWARDS].nActivationHeight        = 1475000;
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_COLLATERALS].nActivationHeight    = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V3].nActivationHeight                 = 1750000;

        consensus.vUpgrades[Consensus::UPGRADE_POS].hashActivationBlock                    = uint256S("a68286b8dd2d7730ab2025201b38020fa68592010ac3e4bcbeaf066b40533802");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].hashActivationBlock                 = uint256S("09daf9665ae60b0dbcef4d60ac4af43bf83837e3d8a89198d82e53fac00010fc");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock                  = uint256S("09daf9665ae60b0dbcef4d60ac4af43bf83837e3d8a89198d82e53fac00010fc");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock      = uint256S("6b369beb95e63b6dab9c5f52e26339aaf5bfdccce0bad968c21267464829c904");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock       = uint256S("4278660ffb8d8d12cc070eea2f8390aa84132fef799675a865717e444d5722e1");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock = uint256S("2123647f29f91a35aa429913db96e666d7de476f1fc109a8298bf6f291b36584");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock     = uint256S("04721c90cd55aa14dbf5cf0b24de60311b37b2deb0e98004b01b2e90c4d3b031");
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].hashActivationBlock     = uint256S("8f7c1d65300983dbf2d99c70051d20470f0088275d6bca9a69fbb2b8597585b7");
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_REWARDS].hashActivationBlock        = uint256S("fb34d4dac7794c616b7894b06499d175ccecfbff7809a706842c5c7b3f41fc1b");
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_COLLATERALS].hashActivationBlock    = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V3].hashActivationBlock                 = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xa6;
        pchMessageStart[1] = 0xf6;
        pchMessageStart[2] = 0xa9;
        pchMessageStart[3] = 0xf9;
        nDefaultPort = 7757;

        vSeeds.push_back(CDNSSeedData("seeder", "seeder.kyancoin.net"));
	    vSeeds.push_back(CDNSSeedData("seed1", "seed1.kyancoin.net"));
        vSeeds.push_back(CDNSSeedData("seed2", "seed2.kyancoin.net"));
        vSeeds.push_back(CDNSSeedData("seed3", "seed3.kyancoin.net"));
        vSeeds.push_back(CDNSSeedData("seed4", "seed4.kyancoin.net"));
	    vSeeds.push_back(CDNSSeedData("seed5", "seed5.kyancoin.net"));
	    vSeeds.push_back(CDNSSeedData("seed6", "seed6.kyancoin.net"));
	    vSeeds.push_back(CDNSSeedData("seed7", "seed7.kyancoin.net"));
	    vSeeds.push_back(CDNSSeedData("seed8", "seed8.kyancoin.net"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 46); // K
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 16); // 7
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 43);  // 7 or X
        // Kyan BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Kyan BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x03)(0x42).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main)); // added
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;

/**
 * Testnet (v1)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

        // // This is used inorder to mine the genesis block. Once found, we can use the nonce and block hash found to create a valid genesis block
        // /////////////////////////////////////////////////////////////////

        // uint32_t nGenesisTime = 1599766365; // 2021-02-03T13:51:41+00:00

        // arith_uint256 test;
        // bool fNegative;
        // bool fOverflow;
        // test.SetCompact(0x1e0ffff0, &fNegative, &fOverflow);
        // std::cout << "Test threshold: " << test.GetHex() << "\n\n";

        // int genesisNonce = 0;
        // uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        // uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // for (int i=0;i<40000000;i++) {
        //     genesis = CreateGenesisBlock(nGenesisTime, i, 0x1e0ffff0, 1, 0 * COIN);
        //     //genesis.hashPrevBlock = TempHashHolding;
        //     consensus.hashGenesisBlock = genesis.GetHash();

        //     arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
        //     if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
        //         BestBlockHash = consensus.hashGenesisBlock;
        //         std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
        //         std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
        //     }

        //     TempHashHolding = consensus.hashGenesisBlock;

        //     if (BestBlockHashArith < test) {
        //         genesisNonce = i - 1;
        //         break;
        //     }
        //     //std::cout << consensus.hashGenesisBlock.GetHex() << "\n";
        // }
        // std::cout << "\n";
        // std::cout << "\n";
        // std::cout << "\n";

        // std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
        // std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
        // std::cout << "Genesis Merkle 0x" << genesis.hashMerkleRoot.GetHex() << std::endl;

        // exit(0);

        // /////////////////////////////////////////////////////////////////

        genesis = CreateGenesisBlock(1599766364, 112122, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000551e93eb0749d40dfafd54b092e78d6612b47bd40de8d099818f65f53c1"));
        assert(genesis.hashMerkleRoot == uint256S("0x17c6d46ee4758572534f6dec116f61268fe883caa99062c1efd764bbbc975d71"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = 1000000000 * COIN; // 1000M KYAN
        consensus.nPoolMaxTransactions = 3;
        consensus.nStakeMinAge = 60 * 60; // 1h
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 10;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.nRewardAdjustmentInterval = 60;

        // spork keys
        consensus.strSporkPubKey = "037c650e8f2e175727a69c50d5fb459f09891e8f6d113105033dfa7af472a229e2";
        consensus.strSporkPubKeyOld = "037c650e8f2e175727a69c50d5fb459f09891e8f6d113105033dfa7af472a229e2";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // burn addresses
        consensus.mBurnAddresses = {
           { "kBURNXXXXXXXXXXXXXXXXXXXXXXXUwNvtS", 0 }
        };

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                   = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight              = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                    = 1001;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                 = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                  = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight      = 1541;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight       = 1641;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight = 1741;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight     = 5001;
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].nActivationHeight     = 3001;
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_REWARDS].nActivationHeight        = 1234440;
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_COLLATERALS].nActivationHeight    = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_POS].hashActivationBlock                    = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].hashActivationBlock                 = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock                  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock      = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock       = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock     = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].hashActivationBlock     = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_REWARDS].hashActivationBlock        = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_DYNAMIC_COLLATERALS].hashActivationBlock    = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0x6a;
        pchMessageStart[1] = 0x9a;
        pchMessageStart[2] = 0x6f;
        pchMessageStart[3] = 0x9f;
        nDefaultPort = 8757;

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("tseeder", "tseeder.kyancoin.net", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 107); // Testnet kyanite addresses start with 'k'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet kyanite script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet kyanite BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Kyaninte BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet Kyaninte BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";

        // // This is used inorder to mine the genesis block. Once found, we can use the nonce and block hash found to create a valid genesis block
        // /////////////////////////////////////////////////////////////////

        // uint32_t nGenesisTime = 1625312841; // 2021-02-03T13:51:41+00:00

        // arith_uint256 test;
        // bool fNegative;
        // bool fOverflow;
        // test.SetCompact(0x207fffff, &fNegative, &fOverflow);
        // std::cout << "Test threshold: " << test.GetHex() << "\n\n";

        // int genesisNonce = 0;
        // uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        // uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // for (int i=0;i<40000000;i++) {
        //     genesis = CreateGenesisBlock(nGenesisTime, i, 0x207fffff, 1, 1000 * COIN);
        //     //genesis.hashPrevBlock = TempHashHolding;
        //     consensus.hashGenesisBlock = genesis.GetHash();

        //     arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
        //     if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
        //         BestBlockHash = consensus.hashGenesisBlock;
        //         std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
        //         std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
        //     }

        //     TempHashHolding = consensus.hashGenesisBlock;

        //     if (BestBlockHashArith < test) {
        //         genesisNonce = i - 1;
        //         break;
        //     }
        //     //std::cout << consensus.hashGenesisBlock.GetHex() << "\n";
        // }
        // std::cout << "\n";
        // std::cout << "\n";
        // std::cout << "\n";

        // std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
        // std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
        // std::cout << "Genesis Merkle 0x" << genesis.hashMerkleRoot.GetHex() << std::endl;

        // exit(0);

        // /////////////////////////////////////////////////////////////////

        genesis = CreateGenesisBlock(1625312841, 1, 0x207fffff, 1, 1000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x430fbdf677d8bd836bc104377a7ab86d62051d927c80315d30e2df6b09df8e7b"));
        assert(genesis.hashMerkleRoot == uint256S("0xa50c4f55f3df2d2ecf33f0248f631ca20935c49dccad9bf2107911d94c5ab0fe"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // kyanite starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 1000000000 * COIN; // 1 billion KYAN
        consensus.nPoolMaxTransactions = 2;
        consensus.nStakeMinAge = 0;
        consensus.nStakeMinDepth = 2;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        /* Spork Key for RegTest:
        WIF private key: 932HEevBSujW2ud7RfB1YF91AFygbBRQj3de3LyaCRqNzKKgWXi
        private key hex: bd4960dcbd9e7f2223f24e7164ecb6f1fe96fc3a416f5d3a830ba5720c84b8ca
        Address: yCvUVd72w7xpimf981m114FSFbmAmne7j9
        */
        consensus.strSporkPubKey = "043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7";
        consensus.strSporkPubKeyOld = "043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight           = 251;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight        = 251;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight          = 251;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight       = 300;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xd6;
        pchMessageStart[1] = 0xd9;
        pchMessageStart[2] = 0x6d;
        pchMessageStart[3] = 0x9d;
        nDefaultPort = 9757;

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 140); // Regtest kyanite addresses start with 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Regtest kyanite script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        // Regtest kyanite BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest Kyaninte BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Regtest Kyaninte BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Regtest mode doesn't have any DNS seeds.
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
