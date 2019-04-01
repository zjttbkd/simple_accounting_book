#ifndef _CORE_H_
#define _CORE_H_

#include <string>
#include <vector>
#include "exception.h"
#include "sqlapi.h"

/*
 * 核心凭证类
 */
class CCoreProof
{
public:
    enum STATE
    {
        STATE_before = 1,
        STATE_after = 2
    };

    enum TYPE
    {
        TYPE_direct = 1,
        TYPE_freeze = 2,
        TYPE_suc_unfreeze = 3,
        TYPE_fail_unfreeze = 4
    };

    //构造函数
    CCoreProof();

    //析构函数
    ~CCoreProof();

    //清理函数
    void clear();

    //查询凭证
    bool queryProof(bool bLock = false);

    //创建凭证
    void saveProof();

    //凭证置为已使用
    void complete();

    //修改凭证类型，重置凭证状态
    void reset();

    //生成行签名
    void genProofSign();

public:
    /*
     * 对外数据库字段
     * 方便第一，直接访问
     */
    string Flistid;
    string Fcur_type;
    int Fsubject;
    string Foutter_prove;
    int Ftype;
    int Fstate;
    int Frecord_state;
    string Fip;
    string Fmemo;
    string Ftrade_memo;
    string Fcreate_time;
    string Fmodify_time;
    LONG Ftotalnum;
    int Frolenum;
    LONG Fdebit_uid;
    string Fdebit_uin;
    LONG Fdebit_amount;
    LONG Fdebit_ex_uid;
    string Fdebit_ex_uin;
    LONG Fdebit_ex_amount;
    LONG Fcredit_uid;
    string Fcredit_uin;
    LONG Fcredit_amount;
    LONG Fcredit_ex_uid;
    string Fcredit_ex_uin;
    LONG Fcredit_ex_amount;
    LONG Fdebit_gl_uid;
    string Fdebit_gl_uin;
    LONG Fdebit_exgl_uid;
    string Fdebit_exgl_uin;
    LONG Fcredit_gl_uid;
    string Fcredit_gl_uin;
    LONG Fcredit_exgl_uid;
    string Fcredit_exgl_uin;
    string Fproof_sign;
    
protected:
    CMySQL* m_ptrSql; //数据库句柄
};

/*
 * 核心账户流水类
 */
class CCoreFlow
{
public:
    enum TYPE
    {
        TYPE_in = 1,
        TYPE_out = 2,
        TYPE_freeze = 3,
        TYPE_unfreeze = 4
    };

    //构造函数
    CCoreFlow();

    //析构函数
    ~CCoreFlow();

    //创建流水
    void saveFlow();

public:
    /*
     * 对外数据库字段
     * 方便第一，直接访问
     */
    string Fcur_type;
    string Flistid;
    LONG Fuid;
    string Fuin;
    string Flist_source;
    int Ftype;
    int Faction_type;
    int Fsubject;
    LONG Fcounter_uid;
    string Fcounter_uin;
    LONG Fbalance;
    LONG Fcon;
    LONG Fpaynum;
    LONG Fconnum;
    string Fip;
    string Fmemo;
    string Ftrade_memo;
    string Fmodify_time;
    string Fcreate_time;
    string Frollback_time;
    string Fexplain;
    int Flabel;
    int Ftimestamp;
    
protected:
    CMySQL* m_ptrSql; //数据库句柄
};

/*
 * 核心账户类
 */
class CCoreAcct
{
public:
    enum BALANCE_TYPE
    {
        BAlANCE_debit = 1,
        BAlANCE_credit = 2
    };

    enum SYMBOL
    {
        SYMBOL_assets = 1,
        SYMBOL_liabilities = 2,
        SYMBOL_common = 3
    };

    //构造函数
    CCoreAcct();
    CCoreAcct(const LONG uid);

    //析构函数
    ~CCoreAcct();

    //创建账户
    void createAcct();

    //获取账户信息
    bool queryAcctInfo(bool bLock = false);

    //记借方
    void debit(const LONG lAmount);

    //记贷方
    void credit(const LONG lAmount);

    //冻结余额
    void freeze(const LONG lAmount);

    //解冻余额
    void unfreeze(const LONG lAmount);

    //设置对手方账户
    void setCounter(const LONG uid, const string uin);

    //设置凭证参数
    void setProofInfo(const CCoreProof& proof);

    //生成账户签名
    string genAcctSign(bool bCreAcct = false);

public:
    /*
     * 对外数据库字段
     * 方便第一，直接访问
     */
    LONG Fuid;
    string Fuin;
    string Fname;
    int Fsymbol;
    string Fcur_type;
    int Fledger_type;
    int Fbalance_type;
    LONG Fbalance;
    LONG Fcon;
    LONG Ftransit;
    int Facct_state;
    string Fip;
    string Fmemo;
    string Fmodify_time;
    string Fcreate_time;
    string Fbalance_time;
    int Ftimestamp;
    int Ftimestamp_us;
    int Frecord_mode;
    string Facct_sign;
    string Fproof_id;

protected:
    //参数初始化
    void init();
    //对账户余额进行变动
    void process();
    //检查金额
    void checkAmount();
    //准备更新
    void prepareUpdate();
    //更新账户余额
    void updateAcct();
    //记录流水
    void createFlow();

protected:
    CMySQL* m_ptrSql; //数据库句柄
    CCoreFlow m_flow;
    bool bSync; //是否同步账户信息
};

/*
 * 核心对外接口类
 */
class CCore
{
public:
    //构造函数
    CCore();

    //析构函数
    ~CCore();

    //入口函数
    template <typename T> void callCore(const T& st) throw(CException)
    {
        try
        {
            //使用订单信息填充凭证
            fillProof(st, m_proof);
            //凭证是否已存在
            if(!m_proof.queryProof())
            {
                //不存在则保存凭证
                m_proof.saveProof();
            }
            else
            {   
                //存在则检查关键参数是否一致
                CCoreProof req_proof;
                fillProof(st, req_proof);
                checkProof(req_proof);
            }

            //根据凭证记账
            dealProof();
        }
        catch(CException& e)
        {
            if(e.error() != ERR_ALREADY_SUCCESS) throw;
        }
    }
    
protected:
    //比较凭证的关键参数
    void checkProof(CCoreProof& proof);
    //流转凭证状态
    void checkProofState(const int req_type);
    //根据凭证类型记账
    void dealProof();
    //直接处理
    void dealDirect();
    //处理冻结
    void dealFreeze();
    //处理成功解冻（解冻并操作可用余额）
    void dealSucUnfreeze();
    //处理失败解冻（仅解冻）
    void dealFailUnfreeze();

protected:
    CMySQL* m_ptrSql; 
    CCoreProof m_proof;
};

#endif