    // trackroi.h
#ifndef CTRACK_ROI_H
#define CTRACK_ROI_H

#include "amount.h"
#include "chain.h"
#include "fs.h"
#include "primitives/transaction.h"
#include "streams.h"
#include "sync.h"
#include <univalue.h>

class CStakeSamples
{
public:
    int64_t	  nTime;	// transaction time
    unsigned int  nHeight;	// block height of this event
    uint256	  hTxid;	// transaction ID

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nTime);
        READWRITE(nHeight);
        READWRITE(hTxid);
    }
};

class CStakeAnalyze
{
public:
    CAmount	  nStake;	// current stake value
    unsigned int  nCurHeight;	// from vROI
    unsigned int  nPrevHeight;	// set by traceprevious()
    int  	  nDepth;	// set by caller
};

typedef std::vector<CStakeSamples> roivec_t;
class CTrackRoi
{
private:
// module tuning
    const int samDays		= 2;		// number of days to collect new tx data
    const int lookBackDays	= 5;		// number of days to look back at older block chain transactions
    const int nMinVroiSamples	= 30;		// minimum number of vROI samples to calculate masternode ROI
// set nMinimumGroupSize = 1 to just eliminate singleton samples. Set > 10 to emulate Vaultwatch... somewhat
    const int nMinBucketSize	= 10;		// minimum samples ABOVE which each qualified publicKeyAddress must have to calculate stake ROI
// the next two overlap in functionality
    const int nMinAddrsBuckets  = 7;		// minimum number of qualified address buckets to calculate weighted stake ROI, i.e. bucket size > nMinimumGroupSize
    const int nMinWeightPoints	= 480;		// minimum number of weight data points to calculate qualified stake ROI
    const bool fTroiUseRange	= true;		// show range of ROI values
    const bool fEnableCSV2Log	= false;	// enable output of CSV formated sample information to debug.log when -debug=trackroi is set
// end tuning

    static int sampleInterval;			// init in cpp file -- target number of blocks to hold in vROI = samDays * blks per day
    static CAmount nOldMNpayment;
    static CAmount nOldBlkReward;
    static int64_t nLastRoilistSave;		// last time roilist was saved

//    static std::vector<CStakeSamples> vROI;
    static roivec_t vROI;

    CAmount traceprevious(CTransaction& tx, CStakeAnalyze& sa, CAmount nMNpayment, CAmount nBlkReward, unsigned int *nOldestHeight, int64_t *nOldestTime, unsigned int nBackHeight);
    void saveToMap(std::unordered_map<std::string, std::vector<CStakeAnalyze>>& mapPubAddrs, CStakeAnalyze& sa, std::string& addressRet);
    std::string CAmount2Kwithcommas(CAmount koin);

public:
    mutable RecursiveMutex cs_track;
    void saveStake(CTransaction& tx, const CBlockIndex* pindex);
    bool generateROI(UniValue& roi, std::string& sGerror, bool fDetail);
    void loadVroi();
    void dumpVroi();
    void resetVroi()
    {
        LOCK(cs_track);
        vROI.resize(0);
        nLastRoilistSave = 0;
    }
    bool UseRange()
    {
        return fTroiUseRange;
    }
};

class CStakeDB
{
private:
    fs::path pathRoiCache;

public:
    CStakeDB();
    bool Write(const roivec_t& roiSet);
    bool Read(roivec_t& roiSet);
};

#  ifdef CTRACK_ROI_CPP
// storage space for statics
int CTrackRoi::sampleInterval       = 0;
CAmount CTrackRoi::nOldMNpayment    = 0;
CAmount CTrackRoi::nOldBlkReward    = 0;
int64_t CTrackRoi::nLastRoilistSave = 0;
//std::vector<CStakeSamples> CTrackRoi::vROI;
roivec_t CTrackRoi::vROI;
#  endif	// CTRACK_ROI_CPP
#endif		// CTRACK_ROI_H
