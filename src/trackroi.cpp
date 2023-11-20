// trackroi.cpp
#define CTRACK_ROI_CPP
#include "trackroi.h"

#include "base58.h"
#include "chainparams.h"
#include "clientversion.h"
#include "fs.h"
#include "hash.h"
#include "masternode.h"
#include "masternodeman.h"
#include "net.h"
#include "masternode-sync.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/standard.h"
#include "streams.h"
#include "tinyformat.h"
#include "util.h"

/*	Design Notes
    The ROI calculation works by analyzing current and past related transactions starting
    with "back", the transaction with the highest blocktime, then analyzing each "prev"
    transaction until either a terminal transaction is encountered or the transaction
    sequence becomes to old.

    Conventions used are the same as when dealing with vectors:

    std::vector<> vect -- where data is entered using vect.push_back(data),
    "vect" has 	vect.back(),  the most recently entered data
    	   and	vect.front(), the oldest data

    Similarly, coinstake transactions form a chain from the most recent in an ADDRESS, back
    in time to the origin transaction that placed the stake amount at the ADDRESS.
    
        The most recent transaction labeled as	"back"	snynonomous with newest
        Oldest transaction labeled as		"front" snynonomous with oldest
        A transaction starting with "back"	"cur"	somewhere in the middle
        and moving one by one towards "front"
        A transaction immediately toward 	"prev"
        "front" from "cur"

    Terms used:

        stake:	the amount of coin in the transaction that was
                responsible for the coinstake event.
        spiff:	the reward added to the stake for the coinstake event.
        mnPay:	the masternode payment amount
        bkVal:	the reward block value, same as mnPay + Spiff

        prefixes:

        back:	the most recent transaction in a transaction sequence
                has the highest block time.
        cur:	the transaction under analysis
        prev:	the previous transaction from "cur"

    A transaction sequence can be represent like this

        back    transaction with highest blocktime, begins analysis
         -
         -      zero or more transactions analyzed
         -
        cur	    "back" (first pass) or transaction with a lower blocktime, under analysis
        prev    previous transaction from current
         -
         -	    remaining transactions to analyze
         -
        front   transaction with the lowest blocktime

    Analyzed transactions fall int 4 catagories:

        regular:	coinstake with 3 vout items
            one vout.nValue = 0
            one vout.nValue = staked  + spiff
            one vout.nValue = mnPay

        split:		coinstake with N > 3 vout items
            one vout.nValue = 0
            one vout.nValue = mnPay
            --- a group of N -2 vout's ----
            Sum(N -2 vout's) = stake

        origin:		non-coinstake transaction vout
                        that placed the stake at the ADDRESS

        terminal:	either an "origin" tx or invalid "split" tx

    -------------------------------------------------------------------------------

    typical coinstake transaction

{
  "txid": "0751ded0fc2c74b7be2287edc3095b7263640990bff26579450677808b4b399a",
  "version": 1,
  "size": 234,
  "locktime": 0,
  "vin": [
    {
      "txid": "fa1e80d038ee738bbe69d9238cb8092ff7c80771d4ed221b02cb86ac0b93e287",
      "vout": 2,
      "scriptSig": { 			// not used by these methods
      },
      "sequence":			// not used by these meghods
    }
  ],
  "vout": [
    {
      "value": 0.00,
      "n": 0,
      "scriptPubKey": {
        "asm": "",
        "hex": "",
        "type": "nonstandard"
      }
    },
    {
      "value": 1342.90759077,		// the stake amount
      "n": 1,
      "scriptPubKey": {			// decoded to get public key address
        "asm": "OP_DUP OP_HASH160 aa7ac2f08f3a3488c6caa123f2b697ed221c7cf6 OP_EQUALVERIFY OP_CHECKSIG",
        "hex": "76a914aa7ac2f08f3a3488c6caa123f2b697ed221c7cf688ac",
        "reqSigs": 1,
        "type": "pubkeyhash",
        "addresses": [
          "Kn6AEDy7QNFZCggHSAb9WWQbE6stG4sKwu"
        ]
      }
    },
    {
      "value": 520.00,
      "n": 2,
      "scriptPubKey": {			// not used by these methods
      }
    }
  ],
  "hex":				// not used by these methods
  "blockhash":				// not directly used by these methods
  "confirmations": 939,
  "time": 1699678875,
  "blocktime": 1699678875
}


A coinstake transaction has

    One (1) input
	txid:	ID of previous transaction
	vout:	index of previous transaction

   Three (3) or more outputs
	The first output has a value of zero, index 0

	The SUM of the outputs is the VALUE of the
	input transaction plus the BLOCK_REWARD
	i.e. prevTransaction input value = SUM - BLOCK_REWARD

	One of the outputs equals the MASTERNODE_REWARD

	The scriptPubKey is decoded to get the publicKeyAddress
*/

// Conventions used throughout:
// "front" is the oldest, smallest height, earliest time
// "back"  is the newest, largest height,  latest time

// enters with LOCK(cs_wallet) from wallet.cpp, and LOCK(cs_main) from main.cpp
void CTrackRoi::saveStake(CTransaction& tx, const CBlockIndex* pIndex)
{
    if (!pwalletMain) return;

    if (!fTxIndex) return;

    if (!masternodeSync.IsSynced()) return;

    if (!tx.IsCoinStake()) return;

    CMasternode cmn;

/*
class CStakeSamples
{
public:
    int64_t      nTime;         // transaction time
    unsigned int nHeight;       // block height of this event
    uint256      hTxid;         // transaction ID
*/

    unsigned int nBackHeight = pIndex->nHeight;

    CAmount nBlkReward	 = cmn.GetBlockValue(nBackHeight);
    CAmount nMNpayment	 = cmn.GetMasternodePayment(nBackHeight);

    if (nBlkReward == 0 || nBlkReward == nMNpayment) return;     // no staking

    int64_t nBackBlkTime = pIndex->GetBlockTime();
    uint256 nBackTxid	 = tx.GetHash();

    {
        LOCK(cs_track);

        if (sampleInterval == 0) {	// first time thru, initialize stuff
            sampleInterval = samDays * 86400 / Params().GetConsensus().nTargetSpacing;
            if (vROI.capacity() < 10 + sampleInterval) vROI.reserve(10 + sampleInterval);	// reserve a few days + pad
            nOldMNpayment = nMNpayment;
            nOldBlkReward = nBlkReward;
        }
// check if there has been a reward structure change
        else if (nMNpayment != nOldMNpayment || nBlkReward != nOldBlkReward) {		// start fresh
            nOldMNpayment = nMNpayment;
            nOldBlkReward = nBlkReward;
            vROI.resize(0);
            nLastRoilistSave = 0;		// force erase
        }
// check for old or out of sequence entry
        int nROIsize = vROI.size();
        if (nROIsize > 0 && nBackHeight <= vROI.back().nHeight) return;
// check for duplicate entries, should not happen
        for (auto item: vROI) {
            if (item.nHeight == nBackHeight) {
                LogPrintf("ERROR: CTrackRoi::saveStake found duplicate transaction block");
                return;
            }
        }

        CStakeSamples ss;
        ss.nHeight	= nBackHeight;
        ss.nTime	= nBackBlkTime;
        ss.hTxid	= tx.GetHash();

        vROI.emplace_back(ss);

        LogPrint(BCLog::TRACKROI, "CTrackRoi::saveStake tx, %s, hgt, %" PRId64 ", time, %" PRId64 ", sz, %d \n",ss.hTxid.GetHex(), nBackHeight, nBackBlkTime, nROIsize + 1);

// clean up samples that are to old
        while (vROI.size() > sampleInterval) {	// prune data set
            vROI.erase(vROI.begin());
        }
    } // end LOCK(cs_track);
// periodically update roicache.dat	...  every hour
    if (nLastRoilistSave + 3600 < nBackBlkTime) {
        nLastRoilistSave = nBackBlkTime;
        dumpVroi();
    }
}

/*  Method description:
    generateROI()

1) Data about the first (most recent) sample in vROI is  collected as follows:

        nBackHeight		the chain block height at analysis start
        nMNpayment		the masternode payment value at analysis start block height
        nBlkReward		the block reward value at analysis start block height
        nBackBlkTime		the block time of at analysis start blockheight

    These data come from vROI.back(), the first available sample.
    The values remain immutable during the analysis of a stake transaction chain.

1a) Data about the last (oldest) sample in vROI is collected accurately determine
    blocks / day as follows:

        nLowestHeight		the earliest known height
        nEarliestTime		blocktime for earliest known height

2)  Processes std::vector<CStakesSamples> vROI from back (most recent) to front (oldest).
    Skip transactions in blocks already seen by traceprevious()
    Trace back the previous stakes that are the parents of the current transaction
    Each sample contains the following data:

class CStakeSamples
{
public:
    int64_t      nTime;         // transaction time
    unsigned int nHeight;       // block height of this event
    uint256      hTxid;         // transaction ID
-------------------------
    First collect known data about current transaction.

    CurHash		= Txid from current sample
    CurHeight		= block height from current sample

3)  Get the transaction
    tx			= from GetTransaction(CurHash, ...

4)  Get the stake value and pubKeyScript
    Stake		= calculate from tx.vout
    pubKeyScript	= find in tx.vout

    Get the publicKeyAddress from ExtractDestination
    and temporarily save it "addr"

5)  Create an ROI stake analysis sample "sa"

class CStakeAnalyze	-- hereinafter known as SA data
{
public:
    CAmount       nStake;       // current stake value
    unsigned int  nCurHeight;   // from vROI
    unsigned int  nPrevHeight;  // set by traceprevious()
    int           nDepth;       // set by caller
};

6)  Get the current transaction status and trace back through
    previous transactions to build a stake chain for further analysis.

    sa inputs = current transaction

    See the description for traceprevious().

    Transaction status is one of three types
    1) > 0,  valid and has parent stake transaction
    2) == 0, valid and has terminating transaction, either split tx or non-coinstake
    3) < 0,  invalid, multiple possible reasons. See traceprevious() description

7)  If the tx is valid:
    Save the SA data in mapPubAddrs by ADDRESS fro further ROI analysis
    Save the block height in StakeSeen

    If the tx has chainstake parent, set up the previous tx for analysis
    ...else continue

8)  The Txid provides a linked list back in time for the current transaction.
    Trace back through these transactions to extract ROI data
    See description for traceprevious()

    While subsequent tx status remain true, repeat the equivalent of steps 6) thru 9)
    for each subsequent satemp transaction related to the current stake.

9) Terminate analysis if there are insufficient data sammples for accurate ROI calculations

10) Calculate the number of masternode rewards per day (blocks per day) and the masternode ROI

   Masternode reward ROI calculation

            rewards/day * 365 * block reward
    mnROI = --------------------------------
                numberMN's * collateral

11) Calculate the staking ROI using two similar methods

Known:
      A stake reward will be known as a "spiff"

    There are 1440 spiff's per day, but not really. This will vary slightly depending on how
    often a new block is created. For the purpose of this analysis, 1440 will be used throughout.
    The code uses the actual number of blocks per day.

    Incoming transaction data. For each coinstake transaction:

    stake		value of the staked coinage
    current height	block height of this coinstake
    previous height	height of this stake's previous tx

Because of the psuedo-random variability in the Age for each stake event, any individual staking
event will produce un-reliable ROI, however the average over a large number of samples will converge
to the true ROI over time.

                ----- the ROI calculation -----

First, all transaction samples are agregated into bins represented by their respective public addresses.
    This isolates those transactions to a particular wallet.

Second, transactions are validated by looking back in time at the previous transaction to make sure that
    a change in collateral structure has not occured during the time a transaction was first added to the
    block chain and the time of the staking event.

Additionally, the trace back of previous transactions continues in order to provide additional valid data
    points to the extent that previous transactions:
        1) are not split transactions
        2) are not coinstake transactions
        3) the staking timestamp is within the allowed lookback window

Third, transaction sets which aggregate to a particular address are selected for ROI analysis when the
    number of aggregants exceed a predetermined threshold. (example threshold, 10 data points). The
    weight of each sample is calculated using the stake amount and the elapsed block count.

    elapsed block count = block height of staking event - block height when tx was first added to the blockchain
    stake amount	= value of the staking amount just prior to the staking event

        weight - stakeAmount * elapsedBlockCount

    The weights for each sample in the address data set are then averaged and saved
    Eack "validated" address data set is processed in the same manner.

ROI method. The mean value (average) of all the address data sets is used to calculate ROI as follows:

            Spiff * BlocksPerDay * 365
      ROI = --------------------------
                   MeanWeight

 ----------------------------------------------------------------------------
 
The second ROI calculation method.

First, calculate the average of all data sample weights. 

Second, create a weighted upper and lower bound based on the number of samples vs the maximum number of samples

                     size of sample set
    adjustment = --------------------------
                 maximum size of sample set		// vROI.size()

Third, set the upper and lower bound

    LOWER = adjustment * average weight  / 100		~ 1%
    UPPER = adjustment * average weeight * 10		~ 1000%

Forth, trim the smallest and largest weights from the sample set that exceed the bounds

Fifth, average the remaining samples and use this value to calculate ROI

*/

bool CTrackRoi::generateROI(UniValue& roi, std::string& sGerror, bool fVerbose)
{
    if (!fTxIndex) {
        sGerror = "getroi: -txindex REQUIRED to enable ROI calculation";
        return false;
    }
// BEGIN ROI calculation setup. Find all the useable stake sample and map them by publicKeyAddress

    int nROIsize;
    std::vector<CStakeSamples> vROIcopy;
    {
        LOCK(cs_track);

        nROIsize = vROI.size();
        if (sampleInterval == 0) {
            sGerror = strprintf("Not enough data, waiting for confirmations");
            return false;
        }
        if (nROIsize < nMinVroiSamples) {
            sGerror = strprintf("Not enough data, need %d confirmations, have %d", nMinVroiSamples, nROIsize);
            return false;
        }
// deep copy vROI
        std::vector<CStakeSamples> vROItemp(vROI);
        std::swap(vROItemp,vROIcopy);		// move to outer scope

    }   // end LOCK(cs_track);

// a map of public address contain a list  stake sample chains
    std::unordered_map<std::string, std::vector<CStakeAnalyze>> mapPubAddrs;
    mapPubAddrs.reserve(2 * nROIsize);
    std::vector<unsigned int> vStakeSeen;
    vStakeSeen.reserve(nROIsize);
/*
    address	=> [		samples are not in any particular order
            sample00	=> [
                tx_chain00.back,
                X.. tx_chains00's....
                txchain00.terminal
            ],
            sample01	=> [
                tx_chain01.back,
                Y tx_chain01's....
                txchain01.terminal
            ],
            ...
    ];
*/
//	step 1)
    CMasternode cmn;
    unsigned int nBackHeight	= vROIcopy.back().nHeight;
    CAmount nMNpayment		= cmn.GetMasternodePayment(nBackHeight);
    CAmount nBlkReward		= cmn.GetBlockValue(nBackHeight);
    int64_t nBackBlkTime	= vROIcopy.back().nTime;
//	step 1a)
    unsigned int nLowestHeight	= vROIcopy.front().nHeight;
    int64_t nEarliestTime	= vROIcopy.front().nTime;
    int64_t nCollectionTime	= vROIcopy.back().nTime - nEarliestTime;	// elapsed collection used in ROI screen presentation

/*	BEGIN setup analysis
	Process each sample to see if it is valid and get public key address's

        each sample contains:

class CStakeSamples
{
public:
    int64_t      nTime;         // transaction time
    unsigned int nHeight;       // block height of this event
    uint256      hTxid;         // transaction ID
};
*/
//	step 2)
    for (auto itr = vROIcopy.rbegin(); itr != vROIcopy.rend(); itr++ ) {
        unsigned nCurrentHeight	= itr->nHeight;

        auto stakeBlkFound = std::find(vStakeSeen.rbegin(), vStakeSeen.rend(), nCurrentHeight);
        if (stakeBlkFound != vStakeSeen.rend()) continue;	// already seen

        uint256 nCurHash	= itr->hTxid;
        CTransaction tx;		// set below
        CAmount nStake		= 0;	// set below
        int nTxIndx		= 0;	// set below

        CBlockIndex* blockindex = nullptr;
        uint256 hash_block;
        int	nDepth	= 0;

//	step 3)
//		locks cs_main
        if (!GetTransaction(nCurHash, tx, hash_block, true, blockindex) || hash_block.IsNull()) {
        // should never happen
            LogPrintf("ERROR: CTrackRoi::generateROI no such mempool or blockchain tx %s\n", nCurHash.GetHex());
            continue;
        }

//	step 4)
// if nMNpayment == 1, we have unconditionally found an index from which we can get the publicKeyAddress
        int nMNpaymentFound = 0;
        int nTxEnd = tx.vout.size();
        for (int i = 0; i < nTxEnd; i++) {
            CAmount nVoVal = tx.vout[i].nValue;
            if (nVoVal == 0) continue;
            if (nVoVal == nMNpayment) {
                nMNpaymentFound++;
            } else {
                nTxIndx = i;
            }
            nStake += nVoVal;
        }

        if (nMNpaymentFound == 0) {			// should never happen
            LogPrintf("ERROR: CTrackRoi::generateROI masternode reward not found for tx %s\n", nCurHash.GetHex());
            continue;
        }
        if (nMNpaymentFound > 1) continue;	// ambigious corner condition, reject

        nStake -= nBlkReward;		       // value of stake before coinstake

        CScript myPubKey = tx.vout[nTxIndx].scriptPubKey;

        CTxDestination addressRet;
        ExtractDestination(myPubKey,addressRet);
        std::string addr = EncodeDestination(addressRet);

//	step 5)
        CStakeAnalyze sa;
/*
public:
    CAmount       nStake;       // current stake value
    unsigned int  nCurHeight;   // from vROI
    unsigned int  nPrevHeight;  // set by traceprevious()
    int           nDepth;       // set by caller
};
*/
        sa.nStake     = nStake;
        sa.nDepth     = nDepth;
        sa.nCurHeight = nCurrentHeight;
//	step 6)
// updates tx to prevTx, updates sa.nDepth, sets nPrevHeight
//	     returns prevStakeValue before stake event
// sa inputs = current transaction
        CAmount nStakeStatusValue = traceprevious(tx, sa, nMNpayment, nBlkReward, &nLowestHeight, &nEarliestTime, nBackHeight);
        if (nStakeStatusValue < 0) continue;	// invalid stake

//	step 7)
        saveToMap(mapPubAddrs, sa, addr);
        vStakeSeen.push_back(nCurrentHeight);

        if (nStakeStatusValue == 0) continue;	// this was a terminating transaction, maybe useful later

        nCurrentHeight = sa.nPrevHeight;	// update for next tx in chain if there is one
        nDepth         = sa.nDepth;		// for subsequent previous transaction

//	step 8)
// look back at previous transactions
        while (nStakeStatusValue > 0) {
            CStakeAnalyze satemp;			// temporary
            satemp.nStake     = nStakeStatusValue;	// from previous traceprevious()
            satemp.nDepth     = nDepth;
            satemp.nCurHeight = nCurrentHeight;
// returns previous stake value
            nStakeStatusValue = traceprevious(tx, satemp, nMNpayment, nBlkReward, &nLowestHeight, &nEarliestTime, nBackHeight);
            if (nStakeStatusValue < 0) break;		// invalid transaction, chain ended on previous tx

// save trave transaction record
            saveToMap(mapPubAddrs, satemp, addr);
            vStakeSeen.push_back(nCurrentHeight);

            if (nStakeStatusValue == 0) break;		// this tx is the last in the tx chain

            nCurrentHeight = satemp.nPrevHeight;	// update for next tx in chain if there is one
            nDepth   	   = satemp.nDepth;		// for subsequent previous transaction
        }
    } // END ROI setup analysis
//	step 9)
    if (mapPubAddrs.size() < nMinAddrsBuckets) {
        sGerror = strprintf("Not enough valid data, have %d addresses, need more than %d. Please wait.", mapPubAddrs.size(), nMinAddrsBuckets);
        return false;
    }
//	step 10)
// calculate number of rewards per day and masternode reward ROI
    int nBlksSeen	    = nBackHeight - nLowestHeight;		// total number of blocks seen during analyais
    float nMNrewardsPerDay  =(float) 86400 * (float)nBlksSeen;
    nMNrewardsPerDay	   /= (float)(nBackBlkTime - nEarliestTime);	// number of blocks per day

/*	Reward ROI calculation

            rewards/day * 365 * block reward
    mnROI = --------------------------------
                numberMN's * collateral
*/

// really want GetNextMasternodeInQueueCount but that is
// much more CPU intensive and CountEnabled is very close
    int nEnabled     = mnodeman.CountEnabled();
    if (nEnabled     < 1) nEnabled = 1;			// no divide by zero

    int nStkMinDepth = (Params().GetConsensus().NetworkUpgradeActive(nBackHeight, Consensus::UPGRADE_STAKE_MIN_DEPTH_V2) ?
                    Params().GetConsensus().nStakeMinDepthV2 : Params().GetConsensus().nStakeMinDepth);

    CAmount nCollateral = cmn.GetMasternodeNodeCollateral(nBackHeight);
    float nMN_ROI    = nMNrewardsPerDay * (float)nMNpayment * (float)36500;	// * 100 for nn.nn% result presentation
    nMN_ROI	     /= (float)nEnabled;
    nMN_ROI	     /= (float)nCollateral;

//	step 11)
// calculate staking ROI
    CAmount nSpiff   = nBlkReward - nMNpayment;
// qualified weight
    float nQweight   = 0;		// qualified weight
    int nQwcount     = 0;		// group count
    int nMwcount     = 0;		// group sample count
// average weight
    float nAweight   = 0;
    int nAwcount     = 0;		// total sample count
// qualified ROI
    float nROI       = nMNrewardsPerDay * (float)36500;	// 1440 * 365 * 100     -       blksPerDay * yearOfDays * 100 for presentation of nn.nn% result
    nROI	     *= (float)nSpiff;
// average
    float nAROI      = nROI;
    float nSetWeight = 0;
    int nSort 	     = 0;

    std::vector<float> vAverage;
    vAverage.reserve(2 * vROIcopy.size());

    bool fBCLogROI = fEnableCSV2Log && g_logger->WillLogCategory(BCLog::TRACKROI);

    for (auto& pAddress: mapPubAddrs) {     // generate csv style output to debug.log
        int nSize = (pAddress.second).size();
        if (fBCLogROI) {
// generate csv formated text to debug.log for easy import into excel for analysis
            std::string addout = strprintf("CTrackRoi::CSV, %d, %d,   , pubadd, %s,,,,,,\n",nSize, nSort, pAddress.first);
            LogPrintf("%s", addout);
            nSort++;
        }
        nSetWeight = 0;			// current public address average
        for (auto sa: (pAddress.second)) {
            if (fBCLogROI) {
                std::string stkout= strprintf("CTrackRoi::CSV, %d, %d, dp%02d, stake, %" PRId64 ", curhgt, %" PRId64 ", prvhgt, %" PRId64 " \n",
                    nSize,
                    nSort,
                    sa.nDepth,
                    sa.nStake,
                    sa.nCurHeight,
                    sa.nPrevHeight
                );
                LogPrintf("%s", stkout);
                nSort++;
            }
            float(nSampleWeight) = ((float)sa.nStake * (float)(sa.nCurHeight - sa.nPrevHeight + nStkMinDepth));	// this sample weight
            vAverage.push_back(nSampleWeight);
            nSetWeight += nSampleWeight;									// total address data set weight
        }
        nAweight += nSetWeight;
        nAwcount += nSize;
// for qualified weight, sum the average weight for a public address data set and later divide by the number of sets nQcount
//
//	average Weights by qualified Address
//      ------------------------------------
//         number of qualified Addresses

        if (nSize > nMinBucketSize) {
            nQweight += (nSetWeight / (float)nSize);	// qualified address weight
            nQwcount++;					// number of qualified data sets

            nMwcount += nSize;				// total number of set data points
        }
    }
    if (nQweight < (float)nSpiff) {
        nROI     = 0;
    } else {
// qualified ROI
        nQweight /= (float)nQwcount;	// average weight
        nROI	 /= (float)nQweight;
    }
    int nAvgCount = 0;
    if (nAwcount  < 1) {		// do not divide by zero
        nAROI     = 0;
    } else {
// remove outliers
// calculate the average weight then remove the individual samples that are less than 1% and exceed 1000% of the average
// re-calculate the average with the pruned sample set
        float nLowerBound = (float)sampleInterval;
        nLowerBound	 /= (float)vROIcopy.size();
        float nUpperBound = nLowerBound;
        nAweight     /= (float)nAwcount;
        nLowerBound  *= nAweight / 100;
        nUpperBound  *= nAweight * 10;
        nAweight      = 0;
        for (auto nAw: vAverage) {
            if (nAw < nLowerBound) continue;
            if (nAw > nUpperBound) continue;
            nAweight += nAw;
            nAvgCount++;
        }
        nAweight /= (float)nAvgCount;
        nAROI    /= nAweight;
    }

    LogPrint(BCLog::TRACKROI, "CTrackRoi::generateROI qual staking ROI %3.2f%%, addrs %d, samps %d, cnt %d, weight %8.0f\n", nROI, nQwcount, nMwcount, nAwcount, nQweight);
    LogPrint(BCLog::TRACKROI, "CTrackRoi::generateROI adjavg stake ROI %3.2f%%, adjtd %d, averg %d  adj weight %8.0f\n", nAROI, nAvgCount, nAwcount, nAweight);
    LogPrint(BCLog::TRACKROI, "CTrackRoi::generateROI masternode ROI %3.2f%%\n",nMN_ROI);
/*
        staking    ROI : nnnn.n%
        network  stake : nnnnnnnn
        best addrs nnn : nnnn / nnnn samples		only with fVerbose
	data    window : nnn.n hours			only with fVerbose
                 ---or---
        no staking ROI: insufficient data
        data     cache: nnn.n hours

        masternode ROI: nnnn.n%
        tot collateral: nnnnnnnn
        enabled  nodes: nnnnn
        blocks per day: nnnn.n
        data    window: nnn.n hours			only with fVerbose
*/
    bool fnoROI = nROI < 1 || nAROI < 1 || nQwcount < nMinAddrsBuckets || nMwcount < nMinWeightPoints;

// print staking ROI info
    if (fnoROI) {
        roi.push_back(Pair("no staking  ROI", "insufficient data"));
    } else {
        nQweight /= (float)COIN;
        roi.push_back(Pair("staking    ROI", strprintf("%4.1f%%", nROI)));
        if (fTroiUseRange) {
            roi.push_back(Pair(" range     ROI", strprintf("%4.1f%%", nAROI)));
            nAweight /= (float)COIN;
            nQweight += nAweight;
            nQweight /= (float)2;
        }
        roi.push_back(Pair("network  stake", CAmount2Kwithcommas((CAmount)nQweight)));
        if (fVerbose) roi.push_back(Pair(strprintf("best addrs %3d", nQwcount), strprintf("%d of %d samples", nMwcount, nAwcount)));
    }
    float nDisplayHours = (float)nCollectionTime;
    nDisplayHours /= 3600;
    nDisplayHours += 0.05;	//round

    std::string sTimeComment1 = "capture window";
    std::string sTimeComment2 = "hours";

    if (fnoROI) {
        sTimeComment1 = "data     cache";
        sTimeComment2 = "hours, please wait";
    }
    if (fVerbose) roi.push_back(Pair(sTimeComment1, strprintf("%3.1f %s", nDisplayHours, sTimeComment2)));
    roi.push_back(Pair("--------------","--------------"));

// print masternode ROI info
    float nHours = (float)(nBackBlkTime - nEarliestTime);
    nHours /= (float)3600;
    nHours += 0.05;	// round
    roi.push_back(Pair("masternode ROI", strprintf("%4.1f%%", nMN_ROI)));
    CAmount nTotalCollateral = (nCollateral / COIN) * nEnabled;
    roi.push_back(Pair("tot collateral", CAmount2Kwithcommas(nTotalCollateral)));
    roi.push_back(Pair("enabled  nodes", strprintf("%d", nEnabled)));
    roi.push_back(Pair("blocks per day", strprintf("%4.1f", nMNrewardsPerDay)));
    if (fVerbose) roi.push_back(Pair("capture window", strprintf("%3.1f hours", nHours)));
    return true;
}

/*  Method description:
    CAmount nStakeStatusValue = traceprevious(tx, SA, nMNpayment, nBlkReward, nBackBlkTime);

    sa inputs = current transaction under analysis

    Return previous stake value, or 0 if terminating tx, or -1 if invalid tx

    Transaction status is one of three types
    1) = -1,	invalid, multiple possible reasons.
    2) = 0,	valid and has terminating transaction, either split tx or non-coinstake
    3) = stake, valid and has parent stake transaction

    Reasons for -1	invalid transaction
        1) transaction not found in mempool or blockchain
        2) stake value not found in previous tx
        3) previous block index not found
        4) reward structure changed from current tx to previous tx
    ----------- only for first tx in a chain
        5) first tx in a chain is a split tx
        6) masternode payment not found in current tx
        7) multiple masternode payment values found in first tx in a chain, ambiguious condition, reject


    Reasons for 0	terminating transaction
        1) previous tx is not a coinstake, however stake value is present and there has been no collateral change
        2) previous tx is a split transaction, further traceprevious would allow split
           stakes to converge on a single tx chain and duplicate datapoints
        3) starting timestamp of previous tx is beyond the data sample window
        4) previous tx is not a coinstake, current tx terminates chain
        5) current transaction stake value == masternode payment value, no previous transaction

    inputs:
        tx		current tx
        SA		class object, described below
        nMNpayment      vROI.back() masternode payment value
        nBlkReward      vROI.back() block reward value
        nBackBlkTime	vROI.back() block time

class CStakeAnalyze	-- hereinafter known as SA
{
public:
    CAmount       nStake;       // current stake value for the input tx
    int64_t       nCurTime;     // from vROIcopy
    int64_t       nPrevTime;    // set by this method
    int           nDepth;       // set by caller, modified by this method

traceprevious() performs multiple validation steps and provides previous transaction
data points for the subsequent step in the tx chain traceprevious. Specfically:

    tx		updates tx to point to previous transaction
    nPrevTime	sets value for record of current transaction, use as CurTime for subsequent prevTx
    nStake	returns the stake value if the current transaction is valid and the chain continues

1)  Get the previous transaction and block hash
    if not valid, abandon current tx, last one processed is end of tx chain, return -1, or...

2)  Get the previous tx vout stake value and verify against current tx stake value
    prevTx		temp is set
    prevStake		temp is set

3)  Update OldestTime, OldestHeight as needed

4) Get previous tx block height and verify that there has not been a reward structure change
    if changed, return -1

5)  Set return values

    sa.nPrevHeight	is set
    sa.nDepth		is set += 1 to indicate the depth of this TX

6)  check that current stake value is NOT == masternode payment
    if found, return 0
    these prevous stakes have no predecessor, terminate tx chain

7)  if current tx is a split tx, current tx terminates the chain
    return 0

8)  if previous tx ia not a coinstake, current tx terminates the chain
    return 0

9)  Check that the previous transaction timestamp is not to old for further analysis
    if to old, the current tx terminates the chain
    return 0

10)  Check that previous tx is NOT a split tx. If it is a split tx then
    calculate the correct stake value to return

11)  tx		update to point to previous tx
    verify that the prev stake is not a masternode payment which has no prevous tx to trace back
    return previous stake value

    ----------------------------------------------------------------------------------

    sa inputs = current transaction

    rv = prevStake	save, recurse usable tx, has parent
    rv = 0		save unusable terminal tx
    rv = -1		discard, unusable tx

                                    current tx    |  class object   |  masternode reward  |   block reward  | lowest height /earliest time pair for blocks/day calculation  | most recent block height
*/
CAmount CTrackRoi::traceprevious(CTransaction& tx, CStakeAnalyze& sa, CAmount nMNpayment, CAmount nBlkReward, unsigned int *nLowestHeight, int64_t *nEarliestTime, unsigned int nBackHeight)
{
/*
class CStakeAnalyze
{
public:
    CAmount       nStake;       // current stake value
    unsigned int  nCurHeight;   // from vROI
    unsigned int  nPrevHeight;  // set by traceprevious()
    int           nDepth;       // set by caller, modified by traceprevious()
};
*/
    CTransaction prevTx;
// some code from rpc/rawtransaction.cpp -- getrawtransaction
    CBlockIndex* pPrevBlkIndex = nullptr;
    uint256 hash_block;
    CAmount prevStake;

// prevout vars to set up GetTransaction
    uint256  nPrevHash = tx.vin[0].prevout.hash;
    uint32_t nPrevIndx = tx.vin[0].prevout.n;
//     {
// don't need this        LOCK(cs_main);  // this is safe, RecursiveMutex
// step 1)
//		locks cs_main
        if (!GetTransaction(nPrevHash, prevTx, hash_block, true, pPrevBlkIndex) || hash_block.IsNull()) {
            LogPrintf("ERROR: CTrackRoi::traceprevious no such mempool or blockchain previous transaction\n");
            return -1;
        }

// step 2)
        prevStake = prevTx.vout[nPrevIndx].nValue;
        if (sa.nStake != prevStake) {   // should never happen
            LogPrintf("ERROR: CTrackRoi::traceprevious %" PRId64 " could not find previous stake value %" PRId64 " \n",sa.nStake,prevStake);
            return -1;
        }
// step 3)
// Check to see if there has been a reward structure change
        if (pPrevBlkIndex == nullptr) {
            LOCK(cs_main);
            BlockMap::iterator mi = mapBlockIndex.find(hash_block);
            if (mi != mapBlockIndex.end()) {
                pPrevBlkIndex = (*mi).second;
            } else {
                LogPrintf("ERROR: CTrackRoi::traceprevious could not find previous block index %s\n",hash_block.GetHex());
                return -1;
            }
        }

        unsigned int nPrevBlkHeight = pPrevBlkIndex->nHeight;
        unsigned int nLookBack = (sampleInterval * lookBackDays) / samDays;
        if (nPrevBlkHeight + nLookBack > nBackHeight && nPrevBlkHeight < *nLowestHeight) { // find earliest set that is in the lookback window
            *nLowestHeight = nPrevBlkHeight;
            *nEarliestTime = pPrevBlkIndex->GetBlockTime();
        }
//	step 4)
        CMasternode cmn;
// check for reward structure change
        if (!(nMNpayment  == cmn.GetMasternodePayment(nPrevBlkHeight)) ||
            !(nBlkReward  == cmn.GetBlockValue(nPrevBlkHeight))) return -1; // block reward structure changed since current transaction
//	step 5)
// set returned values
        sa.nPrevHeight = nPrevBlkHeight;
        sa.nDepth += 1;
//	step 6)
        if (sa.nStake == nMNpayment) return 0;		// prevTx has no predecessor, terminate tx chain
//	step 7)
        if (tx.vout.size() > 3) return 0;		// current tx is a split transaction and terminates the chain
//	step 8)
        if (!prevTx.IsCoinStake()) return 0;		// current tx terminates chain
//	step 9)
        if (nPrevBlkHeight + nLookBack < nBackHeight) return 0;	// sample to old for next traceprev()
//    } // LOCK(cs_main)

//	step 10)
        int nTxEnd = prevTx.vout.size();
        if (nTxEnd > 3) {				// previous is split, get transaction value
            prevStake = 0;
            int nMNpaymentFound = 0;
            for (int i = 0; i < nTxEnd; i++) {
                CAmount nVoVal = prevTx.vout[i].nValue;
                if (nVoVal == nMNpayment) nMNpaymentFound++;
                prevStake += nVoVal;
            }

            if (nMNpaymentFound == 0) {			// should never happen
                LogPrintf("ERROR: CTrackRoi::traceprev previous masternode reward not found for tx %s\n", nPrevHash.GetHex());
                return 0;
            }
            if (nMNpaymentFound > 1) return 0;      	// ambigious corner condition, reject
            prevStake -= nBlkReward;
        } else {
            prevStake -= (nBlkReward - nMNpayment);
        }
//	step 11)
    tx = prevTx;
    return prevStake;
}

// insert / update key / value pair
void CTrackRoi::saveToMap(std::unordered_map<std::string, std::vector<CStakeAnalyze>>& mapPubAddrs, CStakeAnalyze& sa, std::string& addr)
{
    auto pmAddress = mapPubAddrs.find(addr);
    if (pmAddress != mapPubAddrs.end()) {	// key found
        (pmAddress->second).push_back(sa);	// add element to existing SA vector
    } else {
        std::vector<CStakeAnalyze> vSA;		// create new SA vector instance
        vSA.push_back(sa);
        mapPubAddrs.insert({addr, vSA});	// insert into map
    }
}

// convert COIN to string with thousands comma seperators
std::string CTrackRoi::CAmount2Kwithcommas(CAmount koin) {
    std::string s = strprintf("%" PRId64, (int64_t)koin);
    int j = 0;
    std::string k;
    for (int i = s.size() - 1; i >= 0;) {
        k.push_back(s[i]);
        j++;
        i--;
        if (j % 3 == 0 && i >= 0) k.push_back(',');
    }
    reverse(k.begin(), k.end());
    return k;
};

CStakeDB::CStakeDB()
{
    pathRoiCache = GetDataDir() / "roicache.dat";
}

bool CStakeDB::Write(const roivec_t& roiSet)
{    // Generate random temporary filename
    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string tmpfn = strprintf("roicache.dat.%04x", randv);
    // serialize roicache, checksum data up to that point, then append csum
    CDataStream ssRoiCache(SER_DISK, CLIENT_VERSION);
    ssRoiCache << FLATDATA(Params().MessageStart());
    ssRoiCache << roiSet;
    uint256 hash = Hash(ssRoiCache.begin(), ssRoiCache.end());
    ssRoiCache << hash;

    // open temp output file, and associate with CAutoFile
    fs::path pathTmp = GetDataDir() / tmpfn;
    FILE *file = fsbridge::fopen(pathTmp, "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: Failed to open file %s", __func__, pathTmp.string());

    // Write and commit header, data
    try {
        fileout << ssRoiCache;
    }
    catch (const std::exception& e) {
        return error("%s: Serialize or I/O error - %s", __func__, e.what());
    }
    FileCommit(fileout.Get());
    fileout.fclose();

    // replace existing roicache.dat, if any, with new roicache.dat.XXXX
    if (!RenameOver(pathTmp, pathRoiCache))
        return error("%s: Rename-into-place failed", __func__);

    return true;
}

bool CStakeDB::Read(roivec_t& roiSet)
{
    // open input file, and associate with CAutoFile
    FILE *file = fsbridge::fopen(pathRoiCache, "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: Failed to open file %s", __func__, pathRoiCache.string());

    // use file size to size memory buffer
    uint64_t fileSize = fs::file_size(pathRoiCache);
    uint64_t dataSize = 0;
    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
        dataSize = fileSize - sizeof(uint256);
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();

    CDataStream ssRoiCache(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssRoiCache.begin(), ssRoiCache.end());
    if (hashIn != hashTmp)
        return error("%s: Checksum mismatch, data corrupted", __func__);

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (network specific magic number) and ..
        ssRoiCache >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
            return error("%s: Invalid network magic number", __func__);

        // de-serialize address data into one CAddrMan object
        ssRoiCache >> roiSet;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    return true;
}

void CTrackRoi::loadVroi()
{
    roivec_t roiSet;
    CStakeDB sdb;
    int64_t nStart = GetTimeMillis();
    nLastRoilistSave = GetTime() - (3600 - 900);	// update in 15 minutes, test is (nBackBlkTime + 3600 < nBackBlkTime) in saveStake() above

    if (sdb.Read(roiSet)) {
        LogPrintf("Loaded %i transaction records from roicache.dat %dms\n", roiSet.size(), GetTimeMillis() - nStart);
        LOCK(cs_track);
        std::swap(vROI, roiSet);
    } else {
        roivec_t().swap(roiSet);
        LogPrintf("Invalid or missing roicache.dat: will recreate\n");
    }
}

void CTrackRoi::dumpVroi()
{
    CStakeDB sdb;
    LOCK(cs_track);
    roivec_t roiSet(vROI);
    sdb.Write(roiSet);
}
