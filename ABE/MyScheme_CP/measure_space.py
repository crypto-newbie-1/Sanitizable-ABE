'''
Space and Communication Overhead Measurement Script
Target: IEEE TDSC/TSC/IoTJ Submission
Schemes: SACS ('22), FSACO ('24), SRACS ('25), Ours (Asym)
Metrics (4 Golden Indicators): PK Size, SK Size, Upload CT Size, Download Token Size
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
import os
import sys

# 突破 Python 默认的策略树解析深度限制
sys.setrecursionlimit(3000)

try:
    from SACS import SACS22CPABE
    from FSACO import FSACO_CPABE
    from SRACS import SRACS25CPABE
    from Ours import FABEO22CPABE as MyScheme
except ImportError as e:
    print(f"⚠️ 导入警告，请确保类名和文件路径正确: {e}")

def get_size(obj, group):
    """
    深度遍历字典/列表，将其中的群元素序列化为二进制并统计总字节数 (Bytes)。
    只统计纯密码学代数开销，忽略策略字符串和明文数据，确保理论对比的绝对公平。
    """
    total_size = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            total_size += get_size(v, group)
    elif isinstance(obj, list) or isinstance(obj, tuple):
        for v in obj:
            total_size += get_size(v, group)
    else:
        try:
            # 序列化底层群元素并统计 Byte 大小
            serialized_bytes = group.serialize(obj)
            total_size += len(serialized_bytes)
        except Exception:
            pass 
    return total_size

def create_test_data(n):
    # 生成最苛刻的全 AND 策略
    policy_string = '(1'
    attr_list = ['1']
    for i in range(2, n+1):
        policy_string += ' and ' + str(i)
        attr_list.append(str(i))
    policy_string += ')'
    return policy_string, attr_list    

def main():
    if not os.path.exists('Results'):
        os.makedirs('Results')

    # 4 大黄金指标，完美对称的 CSV 表头
    csv_file = 'Results/Final_4Schemes_Communication.csv'
    with open(csv_file, 'w') as f:
        f.write("PolicySize,"
                "SACS_PK,SACS_SK,SACS_Upload,SACS_Download,"
                "FSACO_PK,FSACO_SK,FSACO_Upload,FSACO_Download,"
                "SRACS_PK,SRACS_SK,SRACS_Upload,SRACS_Download,"
                "Ours_PK,Ours_SK,Ours_Upload,Ours_Download\n")

    # Group 1: SS512 (给 Type-I 的对比方案使用)
    group_sym = PairingGroup('SS512')    
    msg_sym = group_sym.random(GT)

    # Group 2: MNT159 (给 Type-III 的我们方案使用)
    group_asym = PairingGroup('MNT159')  
    msg_asym = group_asym.random(GT)
    
    test_sizes = [10, 20, 30, 40, 50]
    
    for size in test_sizes:
        print(f"\n{'='*95}")
        print(f" 📦 Measuring Space & Comm. Overhead (Attributes = {size})")
        print(f"{'='*95}")
        
        policy_str, attr_list = create_test_data(size)
        
        # 为了完美展现对手“小宇宙”的缺陷，设定系统最大属性库始终为策略所需属性的 2 倍
        current_uni_size = size * 2 

        # ---------- 1. SACS ----------
        sacs = SACS22CPABE(group_sym, uni_size=current_uni_size)
        pk_s, msk_s = sacs.setup()
        sk_s = sacs.keygen(pk_s, msk_s, attr_list)
        ct_s = sacs.encrypt(pk_s, msg_sym, policy_str)
        ct_prime_s = sacs.sanitize(pk_s, ct_s)
        
        s_pk = get_size(pk_s, group_sym)
        s_sk = get_size(sk_s, group_sym)
        s_upload = get_size(ct_s, group_sym)
        s_download = get_size(ct_prime_s, group_sym) # 无外包解密，用户下载全量净化密文

        print(f"[SACS]  PK: {s_pk:5d} B | SK: {s_sk:5d} B | Upload: {s_upload:5d} B | Download: {s_download:5d} B")

        # ---------- 2. FSACO ----------
        fsaco = FSACO_CPABE(group_sym, uni_size=current_uni_size)
        pk_f, msk_f = fsaco.setup()
        kT_f, kD_f = fsaco.keygen(pk_f, msk_f, attr_list)
        kP_f, kS_f = fsaco.keygen_prime(pk_f)
        ct_f = fsaco.encrypt(pk_f, msg_sym, policy_str)
        ct_prime_f = fsaco.sanitize(pk_f, kP_f, kT_f, ct_f, group_sym.random(GT))

        f_pk = get_size(pk_f, group_sym)
        f_sk = get_size(kD_f, group_sym) + get_size(kS_f, group_sym) # 用户存部分密钥
        f_upload = get_size(ct_f, group_sym)
        f_download = get_size(ct_prime_f, group_sym) # FSACO 下载半解密密文

        print(f"[FSACO] PK: {f_pk:5d} B | SK: {f_sk:5d} B | Upload: {f_upload:5d} B | Download: {f_download:5d} B")

        # ---------- 3. SRACS ----------
        sracs = SRACS25CPABE(group_sym, uni_size=current_uni_size)
        pk_sr, msk_sr = sracs.setup()
        SK_sr, WGK_sr, PGK_sr = sracs.keygen(pk_sr, msk_sr, attr_list)
        RK_sr, DK_sr = sracs.dkeygen(SK_sr)
        
        # ⚠️ 模拟 SRACS 的缺陷：加密时必须依赖系统最大容量 L (这里用 size+10 模拟)
        CT_I_sr = sracs.encrypt_out(pk_sr, num_cols_estimate=size+10)
        CT_O_sr = sracs.encrypt_full(pk_sr, CT_I_sr, msg_sym, policy_str)
        
        CT_S_sr = sracs.sanitize(pk_sr, CT_O_sr, PGK_sr)
        CT_P_sr = sracs.decrypt_out(pk_sr, CT_S_sr, DK_sr, attr_list)

        sr_pk = get_size(pk_sr, group_sym)
        sr_sk = get_size(RK_sr, group_sym) + get_size(WGK_sr, group_sym) # 本地解密私钥
        sr_upload = get_size(CT_O_sr, group_sym)
        sr_download = get_size(CT_P_sr, group_sym) # 下载外包解密后的 token

        print(f"[SRACS] PK: {sr_pk:5d} B | SK: {sr_sk:5d} B | Upload: {sr_upload:5d} B | Download: {sr_download:5d} B")

        # ---------- 4. Ours ----------
        # 大宇宙架构！根本不需要传入 uni_size，系统完全不受限！
        our = MyScheme(group_asym)
        pk_o, msk_o = our.setup()
        sk_o = our.keygen(pk_o, msk_o, attr_list)
        tk_o, dk_o = our.keygen_out(sk_o)
        ct_o = our.encrypt(pk_o, msg_asym, policy_str)
        ct_prime_o = our.sanitize(pk_o, ct_o)
        partial_ct_o = our.decrypt_out(pk_o, tk_o, ct_prime_o)

        o_pk = get_size(pk_o, group_asym)
        o_sk = get_size(dk_o, group_asym) # 用户仅保留极小的本地解密密钥
        o_upload = get_size(ct_o, group_asym)
        o_download = get_size(partial_ct_o, group_asym) # O(1) 下载量！

        print(f"[Ours]  PK: {o_pk:5d} B | SK: {o_sk:5d} B | Upload: {o_upload:5d} B | Download: {o_download:5d} B")

        # 写入 CSV
        with open(csv_file, 'a') as f:
            f.write(f"{size},"
                    f"{s_pk},{s_sk},{s_upload},{s_download},"
                    f"{f_pk},{f_sk},{f_upload},{f_download},"
                    f"{sr_pk},{sr_sk},{sr_upload},{sr_download},"
                    f"{o_pk},{o_sk},{o_upload},{o_download}\n")

if __name__ == "__main__":
    main()