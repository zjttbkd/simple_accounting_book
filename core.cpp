#include "globalconfig.h"
#include "core.h"
#include "dbcomm.h"
#include "runinfo.h"
#include "error.h"
#include "common.h"
#include "decode.h"

extern GlobalConfig* gPtrConfig; // 配置文件

/*****************
 * 核心对外接口类 *
******************/

// 构造函数
CCore::CCore()
{  
    m_ptrSql = getCoreDBHandle();
}

//析构函数
CCore::~CCore()
{
    m_ptrSql = NULL;
}

//比较凭证的关键参数
void CCore::checkProof(CCoreProof& proof)
{   
    //生成行签名
    proof.genProofSign();
    //比较签名
    if(m_proof.Fproof_sign != proof.Fproof_sign)
    {
        throw CException(ERR_PARARM_DIFFER, "core proof: reentry but params differ", __FILE__, __LINE__);
    }
    //流转凭证状态
    checkProofState(proof.Ftype);
}

//流转凭证状态
void CCore::checkProofState(const int req_type)
{
    //冻结完成的凭证可以继续做解冻操作
    if(m_proof.Ftype == CCoreProof::TYPE_freeze && m_proof.Fstate == CCoreProof::STATE_after)
    {
        if(req_type == CCoreProof::TYPE_suc_unfreeze || req_type == CCoreProof::TYPE_fail_unfreeze)
        {
            m_proof.Ftype = req_type;
            m_proof.Fstate = CCoreProof::STATE_before; //将凭证置为使用前
            m_proof.reset();
        }
        else
        {
            throw CException(ERR_BAD_BRANCH, "core proof is in freeze state", __FILE__, __LINE__);
        }
    }  
    //记账完成、解冻完成的凭证不能再继续操作
    else if(m_proof.Fstate == CCoreProof::STATE_after)
    {
        throw CException(ERR_ALREADY_SUCCESS, "core proof already success", __FILE__, __LINE__);
    }
    //凭证处于使用前状态为失败重入，校验凭证类型与请求类型是否一致
    else if(m_proof.Ftype != req_type)
    {
        throw CException(ERR_PARARM_DIFFER, "core proof: reentry but req_type differ", __FILE__, __LINE__);
    }

}

//根据凭证类型记账
void CCore::dealProof()
{
    if(m_proof.Ftype == CCoreProof::TYPE_direct)
    {
        dealDirect();
    }
    else if(m_proof.Ftype == CCoreProof::TYPE_freeze)
    {
        dealFreeze();
    }
    else if(m_proof.Ftype == CCoreProof::TYPE_suc_unfreeze)
    {
        dealSucUnfreeze();
    }
    else if(m_proof.Ftype == CCoreProof::TYPE_fail_unfreeze)
    {
        dealFailUnfreeze();
    }
    else
    {
        throw CException(ERR_BAD_BRANCH, "core proof: wrong type", __FILE__, __LINE__);
    }
}

//直接处理余额
void CCore::dealDirect()
{
    //初始化账户
    CCoreAcct debit(m_proof.Fdebit_uid);
    CCoreAcct debit_gl(m_proof.Fdebit_gl_uid);
    
    CCoreAcct credit(m_proof.Fcredit_uid);
    CCoreAcct credit_gl(m_proof.Fcredit_gl_uid);

    CCoreAcct debit_ex(m_proof.Fdebit_ex_uid);
    CCoreAcct debit_exgl(m_proof.Fdebit_exgl_uid);

    CCoreAcct credit_ex(m_proof.Fcredit_ex_uid);
    CCoreAcct credit_exgl(m_proof.Fcredit_exgl_uid);
    
    try
    {
        m_ptrSql->Begin();

        //锁单
        m_proof.queryProof(true);

        //锁账户表
        debit.queryAcctInfo(true);
        credit.queryAcctInfo(true);
        debit_gl.queryAcctInfo(true);
        credit_gl.queryAcctInfo(true);

        //借方
        debit.setCounter(credit.Fuid, credit.Fuin);
        debit.setProofInfo(m_proof);
        debit.debit(m_proof.Fdebit_amount);
        //贷方
        credit.setCounter(debit.Fuid, debit.Fuin);
        credit.setProofInfo(m_proof);
        credit.credit(m_proof.Fcredit_amount);
        //借方总账
        debit_gl.setCounter(credit_gl.Fuid, credit_gl.Fuin);
        debit_gl.setProofInfo(m_proof);
        debit_gl.debit(m_proof.Fdebit_amount);
        //贷方总账
        credit_gl.setCounter(debit_gl.Fuid, debit_gl.Fuin);
        credit_gl.setProofInfo(m_proof);
        credit_gl.credit(m_proof.Fcredit_amount);

        //处理附加账户
        if(m_proof.Fdebit_ex_amount != 0)
        {
            debit_ex.queryAcctInfo(true);
            debit_exgl.queryAcctInfo(true);

            //借方
            debit_ex.setCounter(credit.Fuid, credit.Fuin);
            debit_ex.setProofInfo(m_proof);
            debit_ex.debit(m_proof.Fdebit_ex_amount);
            //借方总账
            debit_exgl.setCounter(credit_gl.Fuid, credit_gl.Fuin);
            debit_exgl.setProofInfo(m_proof);
            debit_exgl.debit(m_proof.Fdebit_ex_amount);
        }

        if(m_proof.Fcredit_ex_amount != 0)
        {
            credit_ex.queryAcctInfo(true);
            credit_exgl.queryAcctInfo(true);

            //贷方
            credit_ex.setCounter(debit.Fuid, debit.Fuin);
            credit_ex.setProofInfo(m_proof);
            credit_ex.credit(m_proof.Fcredit_ex_amount);
            //贷方总账
            credit_exgl.setCounter(debit_gl.Fuid, debit_gl.Fuin);
            credit_exgl.setProofInfo(m_proof);
            credit_exgl.credit(m_proof.Fcredit_ex_amount);
        }
        //凭证修改为已使用
        m_proof.complete();
        
        m_ptrSql->Commit();
    }
    catch(CException& e)
    {
        m_ptrSql->Rollback();
        throw;
    }
}

//处理冻结
void CCore::dealFreeze()
{
    //初始化账户
    CCoreAcct debit(m_proof.Fdebit_uid);
    CCoreAcct debit_gl(m_proof.Fdebit_gl_uid);
    
    CCoreAcct credit(m_proof.Fcredit_uid);
    CCoreAcct credit_gl(m_proof.Fcredit_gl_uid);
    
    try
    {
        m_ptrSql->Begin();

        //锁单
        m_proof.queryProof(true);

        //锁账户表
        debit.queryAcctInfo(true);
        credit.queryAcctInfo(true);
        debit_gl.queryAcctInfo(true);
        credit_gl.queryAcctInfo(true);

        //借方
        debit.setCounter(credit.Fuid, credit.Fuin);
        debit.setProofInfo(m_proof);
        debit.freeze(m_proof.Fdebit_amount);
        //贷方
        credit.setCounter(debit.Fuid, debit.Fuin);
        credit.setProofInfo(m_proof);
        credit.freeze(m_proof.Fcredit_amount);
        //借方总账
        debit_gl.setCounter(credit_gl.Fuid, credit_gl.Fuin);
        debit_gl.setProofInfo(m_proof);
        debit_gl.freeze(m_proof.Fdebit_amount);
        //贷方总账
        credit_gl.setCounter(debit_gl.Fuid, debit_gl.Fuin);
        credit_gl.setProofInfo(m_proof);
        credit_gl.freeze(m_proof.Fcredit_amount);

        //凭证修改为已使用
        m_proof.complete();

        m_ptrSql->Commit();
    }
    catch(CException& e)
    {
        m_ptrSql->Rollback();
        throw;
    }
}

//处理成功解冻（解冻并操作可用余额）
void CCore::dealSucUnfreeze()
{
    //初始化账户
    CCoreAcct debit(m_proof.Fdebit_uid);
    CCoreAcct debit_gl(m_proof.Fdebit_gl_uid);
    
    CCoreAcct credit(m_proof.Fcredit_uid);
    CCoreAcct credit_gl(m_proof.Fcredit_gl_uid);
    
    try
    {
        m_ptrSql->Begin();

        //锁单
        m_proof.queryProof(true);

        //锁账户表
        debit.queryAcctInfo(true);
        credit.queryAcctInfo(true);
        debit_gl.queryAcctInfo(true);
        credit_gl.queryAcctInfo(true);

        //借方
        debit.setCounter(credit.Fuid, credit.Fuin);
        debit.setProofInfo(m_proof);
        debit.unfreeze(m_proof.Fdebit_amount);
        debit.debit(m_proof.Fdebit_amount);
        //贷方
        credit.setCounter(debit.Fuid, debit.Fuin);
        credit.setProofInfo(m_proof);
        credit.unfreeze(m_proof.Fcredit_amount);
        credit.credit(m_proof.Fcredit_amount);
        //借方总账
        debit_gl.setCounter(credit_gl.Fuid, credit_gl.Fuin);
        debit_gl.setProofInfo(m_proof);
        debit_gl.unfreeze(m_proof.Fdebit_amount);
        debit_gl.debit(m_proof.Fdebit_amount);
        //贷方总账
        credit_gl.setCounter(debit_gl.Fuid, debit_gl.Fuin);
        credit_gl.setProofInfo(m_proof);
        credit_gl.unfreeze(m_proof.Fcredit_amount);
        credit_gl.credit(m_proof.Fcredit_amount);

        //凭证修改为已使用
        m_proof.complete();

        m_ptrSql->Commit();
    }
    catch(CException& e)
    {
        m_ptrSql->Rollback();
        throw;
    }
}

//处理失败解冻（仅解冻）
void CCore::dealFailUnfreeze()
{
    //初始化账户
    CCoreAcct debit(m_proof.Fdebit_uid);
    CCoreAcct debit_gl(m_proof.Fdebit_gl_uid);
    
    CCoreAcct credit(m_proof.Fcredit_uid);
    CCoreAcct credit_gl(m_proof.Fcredit_gl_uid);
    
    try
    {
        m_ptrSql->Begin();

        //锁单
        m_proof.queryProof(true);

        //锁账户表
        debit.queryAcctInfo(true);
        credit.queryAcctInfo(true);
        debit_gl.queryAcctInfo(true);
        credit_gl.queryAcctInfo(true);

        //借方
        debit.setCounter(credit.Fuid, credit.Fuin);
        debit.setProofInfo(m_proof);
        debit.unfreeze(m_proof.Fdebit_amount);
        //贷方
        credit.setCounter(debit.Fuid, debit.Fuin);
        credit.setProofInfo(m_proof);
        credit.unfreeze(m_proof.Fcredit_amount);
        //借方总账
        debit_gl.setCounter(credit_gl.Fuid, credit_gl.Fuin);
        debit_gl.setProofInfo(m_proof);
        debit_gl.unfreeze(m_proof.Fdebit_amount);
        //贷方总账
        credit_gl.setCounter(debit_gl.Fuid, debit_gl.Fuin);
        credit_gl.setProofInfo(m_proof);
        credit_gl.unfreeze(m_proof.Fcredit_amount);

        //凭证修改为已使用
        m_proof.complete();

        m_ptrSql->Commit();
    }
    catch(CException& e)
    {
        m_ptrSql->Rollback();
        throw;
    }
}

/*****************
 * 核心账户类 *
******************/

// 构造函数
CCoreAcct::CCoreAcct()
{  
    init();
}

// 构造函数
CCoreAcct::CCoreAcct(const LONG uid)
{  
    init();
    //设置uid
    Fuid = uid;
}

//析构函数
CCoreAcct::~CCoreAcct()
{
    m_ptrSql = NULL;
}

//参数初始化
void CCoreAcct::init()
{
    //DB参数初始化
    Fuid = 0;
    Fsymbol = 0;
    Fledger_type = 0;
    Fbalance_type = 0;
    Fbalance = 0;
    Fcon = 0;
    Ftransit = 0;
    Facct_state = 0;
    Frecord_mode = 0;
    Ftimestamp = 0;
    Ftimestamp_us = 0;
    Frecord_mode = 0;

    //私有变量初始化
    m_ptrSql = getCoreDBHandle();
    bSync = false;
}

//获取账户信息，bLock：是否加锁
bool CCoreAcct::queryAcctInfo(bool bLock)
{
    char szSql[MAX_SQL_LEN] = {0};
    MYSQL_RES* pRes = NULL;

    try
    {
        int iLen = snprintf(szSql, sizeof(szSql),
            "SELECT Fuid,Fsymbol,Fcur_type,Fledger_type,Fbalance_type,Fbalance,Fcon,Ftransit,Facct_state,"
            "Fuin,Fname,Fip,Fmemo,Fmodify_time,Fcreate_time,Fbalance_time,Ftimestamp,Ftimestamp_us,"
            "Frecord_mode,Facct_sign,Fproof_id "
            "FROM isp_os_core.t_account "
            "WHERE Fuid = %lld %s",
            Fuid, bLock? "FOR UPDATE": "");

        m_ptrSql->Query(szSql, iLen);
        pRes = m_ptrSql->FetchResult();
        int iRow = mysql_num_rows(pRes);

        if(0 == iRow)
        {
            if(bLock)
            {
                throw CException(ERR_DB_NONE_ROW, "queryAcctInfo: result num is 0!", __FILE__, __LINE__);
            }
            mysql_free_result(pRes);
            return false;
        }

        if(iRow > 1)
        {
            throw CException(ERR_DB_MULTI_ROW, "queryAcctInfo: result num is more than one!", __FILE__, __LINE__);
        }

        MYSQL_ROW row = mysql_fetch_row(pRes);

        Fuid = row[0]? atoll(row[0]): 0;
        Fsymbol = row[1]? atoi(row[1]): 0;
        Fcur_type = row[2]? row[2]: "";
        Fledger_type = row[3]? atoi(row[3]): 0;
        Fbalance_type = row[4]? atoi(row[4]): 0;
        Fbalance = row[5]? atoll(row[5]): 0;
        Fcon = row[6]? atoll(row[6]): 0;
        Ftransit = row[7]? atoll(row[7]): 0;
        Facct_state = row[8]? atoi(row[8]): 0;
        Fuin = row[9]? row[9]: "";
        Fname = row[10]? row[10]: "";
        Fip = row[11]? row[11]: "";
        Fmemo = row[12]? row[12]: "";
        Fmodify_time = row[13]? row[13]: "";
        Fcreate_time = row[14]? row[14]: "";
        Fbalance_time = row[15]? row[15]: "";
        Ftimestamp = row[16]? atoi(row[16]): 0;
        Ftimestamp_us = row[17]? atoi(row[17]): 0;
        Frecord_mode = row[18]? atoi(row[18]): 0;
        Facct_sign = row[19]? row[19]: "";
        Fproof_id = row[20]? row[20]: "";
        
        //验证行签名
        if(Facct_sign != genAcctSign())
        {
            throw CException(ERR_DB_TAMPER, "acct_sign not match", __FILE__, __LINE__);
        }
        
        bSync = true; //账户信息已同步
        mysql_free_result(pRes);
        return true;
    }
    catch(CException& e)
    {
        if(pRes)
        {
            mysql_free_result(pRes);
        }
        throw;
    }
}

//记借方
void CCoreAcct::debit(const LONG lAmount)
{
    //发生额
    m_flow.Fpaynum = lAmount;
    m_flow.Fconnum = 0;

    //借方余额
    if(Fbalance_type == CCoreAcct::BAlANCE_debit)
    {
        m_flow.Ftype = CCoreFlow::TYPE_in;
    }
    //贷方余额
    else if(Fbalance_type == CCoreAcct::BAlANCE_credit)
    {
        m_flow.Ftype = CCoreFlow::TYPE_out;   
    }

    process();
}

//记贷方
void CCoreAcct::credit(const LONG lAmount)
{
    //发生额
    m_flow.Fpaynum = lAmount;
    m_flow.Fconnum = 0;

    //借方余额
    if(Fbalance_type == CCoreAcct::BAlANCE_debit)
    {
        m_flow.Ftype = CCoreFlow::TYPE_out;
    }
    //贷方余额
    else if(Fbalance_type == CCoreAcct::BAlANCE_credit)
    {
        m_flow.Ftype = CCoreFlow::TYPE_in;
    }

    process();
}


//冻结
void CCoreAcct::freeze(const LONG lAmount)
{
    //金额为负（冲销时）不操作账户直接返回成功
    if(lAmount < 0) return;

    //冻结金额
    m_flow.Fpaynum = 0;
    m_flow.Fconnum = lAmount;
    m_flow.Ftype = CCoreFlow::TYPE_freeze;

    process();
}

//解冻
void CCoreAcct::unfreeze(const LONG lAmount)
{
    //金额为负（冲销时）不操作账户直接返回成功
    if(lAmount < 0) return;

    //冻结金额
    m_flow.Fpaynum = 0;
    m_flow.Fconnum = lAmount;
    m_flow.Ftype = CCoreFlow::TYPE_unfreeze;

    process();
}

//对账户余额进行变动
void CCoreAcct::process()
{
    //校验金额
    checkAmount();
    //准备更新
    prepareUpdate();
    //更新账户余额
    updateAcct();
    //记录流水
    createFlow();
}

//检查金额
void CCoreAcct::checkAmount()
{
    //账户信息未同步或者传入金额小于0
    //为了兼容冲销，余额发生额可以为负，冻结发生额还是不允许为负
    if(!bSync || m_flow.Fconnum < 0)
    {
        throw CException(ERR_BAD_BRANCH, "core acct: illegal operation", __FILE__, __LINE__);
    }
    
    //非共有类账户余额不允许为负
    if(Fsymbol != SYMBOL_common)
    {
        //出款校验可用余额
        if(m_flow.Ftype == CCoreFlow::TYPE_out)
        {
            if(Fbalance - Fcon - m_flow.Fpaynum < 0)
            {
                throw CException(ERR_LACK_BALANCE, Fuin + " not enough balance", __FILE__, __LINE__);
            }
        }

        //入款也要校验可用余额（冲销时）
        if(m_flow.Ftype == CCoreFlow::TYPE_in)
        {
            if(Fbalance - Fcon + m_flow.Fpaynum < 0)
            {
                throw CException(ERR_LACK_BALANCE, Fuin + " not enough balance", __FILE__, __LINE__);
            }
        }

        //冻结校验可用余额
        if(m_flow.Ftype == CCoreFlow::TYPE_freeze)
        {
            if(Fbalance - Fcon - m_flow.Fconnum < 0)
            {
                throw CException(ERR_LACK_BALANCE, Fuin + " not enough balance", __FILE__, __LINE__);
            }
        }
    }

    //解冻校验冻结金额
    if(m_flow.Ftype == CCoreFlow::TYPE_unfreeze)
    {
        if(Fcon - m_flow.Fconnum < 0)
        {
            throw CException(ERR_LACK_CON, Fuin + " not enough freeze amount", __FILE__, __LINE__);
        }
    }
}

//准备更新
void CCoreAcct::prepareUpdate()
{
    //余额和冻结余额
    if(m_flow.Ftype == CCoreFlow::TYPE_in)
    {
        Fbalance += m_flow.Fpaynum;
    }
    else if(m_flow.Ftype == CCoreFlow::TYPE_out)
    {
        Fbalance -= m_flow.Fpaynum;
    }
    else if(m_flow.Ftype == CCoreFlow::TYPE_freeze)
    {
        Fcon += m_flow.Fconnum;
    }
    else if(m_flow.Ftype == CCoreFlow::TYPE_unfreeze)
    {
        Fcon -= m_flow.Fconnum;
    }

    //更新时间戳, 生成行签名, 更新时间用DB时间
    MicroTimeStamp tStamp;
    getMicroTimeStamp(tStamp);
    Ftimestamp = tStamp.iTimeStamp;
    Ftimestamp_us = tStamp.iTimeStampUs;
    Facct_sign = genAcctSign();
    //Fmodify_time = getSysTime();
    //Fbalance_time = Fmodify_time;
}

//更新账户余额
void CCoreAcct::updateAcct()
{
    char szSql[MAX_SQL_LEN] = {0};

    int iLen = snprintf(szSql, sizeof(szSql) - 1,
        "UPDATE isp_os_core.t_account "
        "SET Fbalance = %lld, Fcon = %lld, "
        "Facct_sign = '%s', Fproof_id = '%s', "
        "Fmodify_time = now(), Fbalance_time = now(), "
        "Ftimestamp = %d, Ftimestamp_us = %d "
        "WHERE Fuid = %lld ",
        Fbalance, Fcon, 
        Facct_sign.c_str(), Fproof_id.c_str(),
        Ftimestamp, Ftimestamp_us, 
        Fuid);

    m_ptrSql->Query(szSql, iLen);

    if(1 != m_ptrSql->AffectedRows())
    {
        throw CException(ERR_DB_AFFECT_ROW, "updateAcct failed: affected row != 1", __FILE__, __LINE__);
    }

}

//记录流水
void CCoreAcct::createFlow()
{
    m_flow.Fcur_type = Fcur_type;
    m_flow.Fuid = Fuid;
    m_flow.Fuin = Fuin;
    m_flow.Fbalance = Fbalance;
    m_flow.Fcon = Fcon;
    m_flow.Fip = HOST_IP;
    m_flow.Fcreate_time = getSysTime();
    m_flow.Fmodify_time = m_flow.Fcreate_time;
    m_flow.Ftimestamp = genCurTimeStamp();
    m_flow.Flabel = m_flow.Fpaynum < 0 ? 2 : 0;

    //保存流水
    m_flow.saveFlow();
}


//设置对手方账户
void CCoreAcct::setCounter(const LONG uid, const string uin)
{
    m_flow.Fcounter_uid = uid;
    m_flow.Fcounter_uin = uin;
}

//设置凭证参数
void CCoreAcct::setProofInfo(const CCoreProof& proof)
{
    Fproof_id = proof.Flistid;
    m_flow.Flistid = proof.Flistid;
    m_flow.Fsubject = proof.Fsubject;
    m_flow.Fmemo = proof.Fmemo;
    m_flow.Ftrade_memo = proof.Ftrade_memo;
}

 //创建账户
void CCoreAcct::createAcct()
{
    char szSql[MAX_SQL_LEN] = {0};

    if(Facct_sign.empty()) Facct_sign = genAcctSign();

    int iLen = snprintf(szSql, sizeof(szSql) - 1,
        "INSERT INTO isp_os_core.t_account "
        "(Fuid,Fsymbol,Fcur_type,Fledger_type,Fbalance_type,Fbalance,Fcon,Ftransit,Facct_state,Fuin,"
        "Fname,Fip,Fmemo,Fmodify_time,Fcreate_time,Fbalance_time,Frecord_mode,Facct_sign,Fproof_id) "
        "VALUES (%lld,%d,'%s',%d,%d,%lld,%lld,%lld,%d,'%s','%s','%s','%s','%s','%s','%s',%d,'%s','%s')", 
        Fuid, Fsymbol, Fcur_type.c_str(), Fledger_type, Fbalance_type, Fbalance, Fcon, Ftransit, Facct_state, 
        Fuin.c_str(), m_ptrSql->EscapeStr(Fname).c_str(), Fip.c_str(), m_ptrSql->EscapeStr(Fmemo).c_str(), 
        Fmodify_time.c_str(), Fcreate_time.c_str(), Fbalance_time.c_str(), Frecord_mode, Facct_sign.c_str(), 
        Fproof_id.c_str());

    m_ptrSql->Query(szSql, iLen);
}

//生成行签名
string CCoreAcct::genAcctSign(bool bCreAcct)
{
    char szSrc[MAX_MSG_LEN] = {0};
    snprintf(szSrc, sizeof(szSrc), 
        "%lld:%s:%d:%s:%d:%d:%lld:%lld|acct",
        Fuid, Fuin.c_str(), Fsymbol, Fcur_type.c_str(), Fledger_type, Fbalance_type,
        bCreAcct? 0: Fbalance,
        bCreAcct? 0: Fcon);

    return GenerateDigest(szSrc);
}


/*****************
 * 核心流水类 *
******************/

// 构造函数
CCoreFlow::CCoreFlow()
{  
    //DB参数初始化
    Fuid = 0;
    Ftype = 0;
    Faction_type = 0;
    Fsubject = 0;
    Fcounter_uid = 0;
    Fbalance = 0;
    Fcon = 0;
    Fpaynum = 0;
    Fconnum = 0;
    Flabel = 0;
    Ftimestamp = 0;

    //私有变量初始化
    m_ptrSql = getCoreDBHandle();
}

//析构函数
CCoreFlow::~CCoreFlow()
{
    m_ptrSql = NULL;
}

//保存流水
void CCoreFlow::saveFlow()
{
    char szSql[MAX_SQL_LEN] = {0};

    int iLen = snprintf(szSql, sizeof(szSql) - 1,
        "INSERT INTO isp_os_core.t_flow "
        "(Fcur_type,Flistid,Fuid,Fuin,Flist_source,Ftype,Faction_type,Fsubject,"
        "Fcounter_uid,Fcounter_uin,Fbalance,Fcon,Fpaynum,Fconnum,Fip,Fmemo,Ftrade_memo,"
        "Fmodify_time,Fcreate_time,Frollback_time,Fexplain,Flabel,Ftimestamp) "
        "VALUES ('%s','%s',%lld,'%s','%s',%d,%d,%d,%lld,'%s',%lld,%lld,%lld,%lld,"
        "'%s','%s','%s','%s','%s','%s','%s',%d,%d)",
        Fcur_type.c_str(), Flistid.c_str(), Fuid, Fuin.c_str(), Flist_source.c_str(),
        Ftype, Faction_type, Fsubject, Fcounter_uid, Fcounter_uin.c_str(), Fbalance, 
        Fcon, Fpaynum, Fconnum, Fip.c_str(), m_ptrSql->EscapeStr(Fmemo).c_str(), 
        m_ptrSql->EscapeStr(Ftrade_memo).c_str(), Fmodify_time.c_str(), Fcreate_time.c_str(), 
        Frollback_time.c_str(), Fexplain.c_str(), Flabel, Ftimestamp);

    m_ptrSql->Query(szSql, iLen);
}


/*****************
 * 核心凭证类 *
******************/

// 构造函数
CCoreProof::CCoreProof()
{  
    //DB参数初始化
    clear();

    //私有变量初始化
    m_ptrSql = getCoreDBHandle();
}

//析构函数
CCoreProof::~CCoreProof()
{
    m_ptrSql = NULL;
}

//清理函数
void CCoreProof::clear()
{
    Flistid = "";
    Fcur_type = "";
    Fsubject = 0;
    Foutter_prove = "";
    Ftype = 0;
    Fstate = 0;
    Frecord_state = 0;
    Fip = "";
    Fmemo = "";
    Ftrade_memo = "";
    Fcreate_time = "";
    Fmodify_time = "";
    Ftotalnum = 0;
    Frolenum = 0;
    Fdebit_uid = 0;
    Fdebit_uin = "";
    Fdebit_amount = 0;
    Fdebit_ex_uid = 0;
    Fdebit_ex_uin = "";
    Fdebit_ex_amount = 0;
    Fcredit_uid = 0;
    Fcredit_uin = "";
    Fcredit_amount = 0;
    Fcredit_ex_uid = 0;
    Fcredit_ex_uin = "";
    Fcredit_ex_amount = 0;
    Fdebit_gl_uin = "";
    Fdebit_gl_uid = 0;
    Fdebit_exgl_uin = "";
    Fdebit_exgl_uid = 0;
    Fcredit_gl_uin = "";
    Fcredit_gl_uid = 0;
    Fcredit_exgl_uin = "";
    Fcredit_exgl_uid = 0;
    Fproof_sign = "";
}

//查询凭证
bool CCoreProof::queryProof(bool bLock)
{
    char szSql[MAX_SQL_LEN] = {0};
    MYSQL_RES* pRes = NULL;

    try
    {
        int iLen = snprintf(szSql, sizeof(szSql),
            "SELECT Flistid,Fcur_type,Fsubject,Foutter_prove,Ftype,Fstate,Frecord_state,Fip,Fmemo,Ftrade_memo,"
            "Fcreate_time,Fmodify_time,Ftotalnum,Frolenum,Fdebit_uid,Fdebit_uin,Fdebit_amount,Fdebit_ex_uid,"
            "Fdebit_ex_uin,Fdebit_ex_amount,Fcredit_uid,Fcredit_uin,Fcredit_amount,Fcredit_ex_uid,"
            "Fcredit_ex_uin,Fcredit_ex_amount,Fdebit_gl_uid,Fdebit_gl_uin,Fdebit_exgl_uid,Fdebit_exgl_uin,"
            "Fcredit_gl_uid,Fcredit_gl_uin,Fcredit_exgl_uid,Fcredit_exgl_uin,Fproof_sign "
            "FROM isp_os_core.t_proof "
            "WHERE Flistid = '%s' %s",
            Flistid.c_str(), bLock? "FOR UPDATE": "");

        m_ptrSql->Query(szSql, iLen);
        pRes = m_ptrSql->FetchResult();
        int iRow = mysql_num_rows(pRes);

        if(0 == iRow)
        {
            if(bLock)
            {
                throw CException(ERR_DB_NONE_ROW, "queryProof: result num is 0!", __FILE__, __LINE__);
            }
            return false;
        }

        if(iRow > 1)
        {
            throw CException(ERR_DB_MULTI_ROW, "queryProof: result num is more than one!", __FILE__, __LINE__);
        }

        MYSQL_ROW row = mysql_fetch_row(pRes);

        Flistid = row[0]? row[0]: "";
        Fcur_type = row[1]? row[1]: "";
        Fsubject = row[2]? atoi(row[2]): 0;
        Foutter_prove = row[3]? row[3]: "";
        Ftype = row[4]? atoi(row[4]): 0;
        Fstate = row[5]? atoi(row[5]): 0;
        Frecord_state = row[6]? atoi(row[6]): 0;
        Fip = row[7]? row[7]: "";
        Fmemo = row[8]? row[8]: "";
        Ftrade_memo = row[9]? row[9]: "";
        Fcreate_time = row[10]? row[10]: "";
        Fmodify_time = row[11]? row[11]: "";
        Ftotalnum = row[12]? atoll(row[12]): 0;
        Frolenum = row[13]? atoi(row[13]): 0;
        Fdebit_uid = row[14]? atoll(row[14]): 0;
        Fdebit_uin = row[15]? row[15]: "";
        Fdebit_amount = row[16]? atoll(row[16]): 0;
        Fdebit_ex_uid = row[17]? atoll(row[17]): 0;
        Fdebit_ex_uin = row[18]? row[18]: "";
        Fdebit_ex_amount = row[19]? atoll(row[19]): 0;
        Fcredit_uid = row[20]? atoll(row[20]): 0;
        Fcredit_uin = row[21]? row[21]: "";
        Fcredit_amount = row[22]? atoll(row[22]): 0;
        Fcredit_ex_uid = row[23]? atoll(row[23]): 0;
        Fcredit_ex_uin = row[24]? row[24]: "";
        Fcredit_ex_amount = row[25]? atoll(row[25]): 0;
        Fdebit_gl_uid = row[26]? atoll(row[26]): 0;
        Fdebit_gl_uin = row[27]? row[27]: "";
        Fdebit_exgl_uid = row[28]? atoll(row[28]): 0;
        Fdebit_exgl_uin = row[29]? row[29]: "";
        Fcredit_gl_uid = row[30]? atoll(row[30]): 0;
        Fcredit_gl_uin = row[31]? row[31]: "";
        Fcredit_exgl_uid = row[32]? atoll(row[32]): 0;
        Fcredit_exgl_uin = row[33]? row[33]: "";
        Fproof_sign = row[34]? row[34]: "";

        mysql_free_result(pRes);
    
        return true;
    }
    catch(CException& e)
    {
        if(pRes)
        {
            mysql_free_result(pRes);
        }
        throw;
    }
}

//保存凭证
void CCoreProof::saveProof()
{
    char szSql[MAX_SQL_LEN] = {0};
    
    if(Fproof_sign.empty()) genProofSign();

    int iLen = snprintf(szSql, sizeof(szSql) - 1,
        "INSERT INTO isp_os_core.t_proof "
        "(Flistid,Fcur_type,Fsubject,Foutter_prove,Ftype,Fstate,Frecord_state,Fip,Fmemo,Ftrade_memo,"
        "Fcreate_time,Fmodify_time,Ftotalnum,Frolenum,Fdebit_uid,Fdebit_uin,Fdebit_amount,"
        "Fdebit_ex_uid,Fdebit_ex_uin,Fdebit_ex_amount,Fcredit_uid,Fcredit_uin,Fcredit_amount,"
        "Fcredit_ex_uid,Fcredit_ex_uin,Fcredit_ex_amount,Fdebit_gl_uid,Fdebit_gl_uin,Fdebit_exgl_uid,"
        "Fdebit_exgl_uin,Fcredit_gl_uid,Fcredit_gl_uin,Fcredit_exgl_uid,Fcredit_exgl_uin,Fproof_sign) "
        "VALUES ('%s','%s',%d,'%s',%d,%d,%d,'%s','%s','%s','%s','%s',%lld,%d,%lld,'%s',%lld,%lld,'%s',"
        "%lld,%lld,'%s',%lld,%lld,'%s',%lld,%lld,'%s',%lld,'%s',%lld,'%s',%lld,'%s','%s')", 
        Flistid.c_str(), Fcur_type.c_str(), Fsubject, Foutter_prove.c_str(), Ftype, Fstate, Frecord_state, 
        Fip.c_str(), m_ptrSql->EscapeStr(Fmemo).c_str(), m_ptrSql->EscapeStr(Ftrade_memo).c_str(),
        Fcreate_time.c_str(), Fmodify_time.c_str(), Ftotalnum, Frolenum, Fdebit_uid, Fdebit_uin.c_str(), 
        Fdebit_amount, Fdebit_ex_uid, Fdebit_ex_uin.c_str(), Fdebit_ex_amount, Fcredit_uid, Fcredit_uin.c_str(), 
        Fcredit_amount, Fcredit_ex_uid, Fcredit_ex_uin.c_str(), Fcredit_ex_amount, Fdebit_gl_uid, 
        Fdebit_gl_uin.c_str(), Fdebit_exgl_uid, Fdebit_exgl_uin.c_str(), Fcredit_gl_uid, Fcredit_gl_uin.c_str(), 
        Fcredit_exgl_uid, Fcredit_exgl_uin.c_str(), Fproof_sign.c_str());

    m_ptrSql->Query(szSql, iLen);
}

//凭证置为已使用
void CCoreProof::complete()
{
    char szSql[MAX_SQL_LEN] = {0};

    int iLen = snprintf(szSql, sizeof(szSql) - 1,
        "UPDATE isp_os_core.t_proof "
        "SET Fstate = %d, Fmodify_time = now() "
        "WHERE Flistid = '%s' AND Fstate = %d "
        "AND Frecord_state = 1",
        CCoreProof::STATE_after,
        Flistid.c_str(),
        CCoreProof::STATE_before);

    m_ptrSql->Query(szSql, iLen);

    if(1 != m_ptrSql->AffectedRows())
    {
        throw CException(ERR_DB_AFFECT_ROW, "updateProofState failed: affected row != 1", __FILE__, __LINE__);
    }
}

//修改凭证类型，重置凭证状态
void CCoreProof::reset()
{
    char szSql[MAX_SQL_LEN] = {0};
    genProofSign();

    int iLen = snprintf(szSql, sizeof(szSql) - 1,
        "UPDATE isp_os_core.t_proof "
        "SET Ftype = %d, Fstate = %d, "
        "Fproof_sign = '%s', Fmodify_time = now() "
        "WHERE Flistid = '%s' AND Fstate = %d "
        "AND Frecord_state = 1",
        Ftype,
        CCoreProof::STATE_before,
        Fproof_sign.c_str(),
        Flistid.c_str(),
        CCoreProof::STATE_after);

    m_ptrSql->Query(szSql, iLen);

    if(1 != m_ptrSql->AffectedRows())
    {
        throw CException(ERR_DB_AFFECT_ROW, "updateProofState failed: affected row != 1", __FILE__, __LINE__);
    }
}

//生成行签名
void CCoreProof::genProofSign()
{
    char szSrc[MAX_MSG_LEN] = {0};
    snprintf(szSrc, sizeof(szSrc), 
        "%s:%s:%lld:%s:%lld:%lld:%s:%lld:%lld:%s:%lld:%lld:%s:%lld:%lld:%s:%lld:%s:%lld:%s:%lld:%s:%d|proof",
        Flistid.c_str(),Fcur_type.c_str(),Fdebit_uid,Fdebit_uin.c_str(),Fdebit_amount,Fdebit_ex_uid,Fdebit_ex_uin.c_str(),
        Fdebit_ex_amount,Fcredit_uid,Fcredit_uin.c_str(),Fcredit_amount,Fcredit_ex_uid,Fcredit_ex_uin.c_str(),
        Fcredit_ex_amount,Fdebit_gl_uid,Fdebit_gl_uin.c_str(),Fdebit_exgl_uid,Fdebit_exgl_uin.c_str(),Fcredit_gl_uid,
        Fcredit_gl_uin.c_str(),Fcredit_exgl_uid,Fcredit_exgl_uin.c_str(),Fsubject);

    Fproof_sign = GenerateDigest(szSrc);
}
