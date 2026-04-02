'''
Industrial-Grade Performance Measurement Script
Schemes: SACS (TDSC'22), FSACO (IoT'24), SRACS (TSC'25), Ours (Asym)
Policy Sizes: 10 to 50
Metrics Mapped to 5 Standard Phases: 
    [Init, Encrypt, Sanitize, Total_Decrypt, Local_Decrypt]
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
import time
import os
import gc
import sys

# 突破 Python 默认的策略树解析深度限制
sys.setrecursionlimit(3000)

# ================= 导入四个方案的类 =================
try:
    from SACS import SACS22CPABE
    from FSACO import FSACO_CPABE
    from SRACS import SRACS25CPABE
    from Ours import FABEO22CPABE as MyScheme
except ImportError as e:
    print(f"⚠️ 导入警告，请确保类名和文件路径正确: {e}")

# =====================================================================
# 1. 测量 SACS (TDSC 2022)
# =====================================================================
def measure_sacs(cpabe, attr_list, attr_policy, msg, N=100): 
    sum_setup = sum_keygen = sum_enc = sum_sanitize = sum_decrypt = 0.0

    # 预热 (Warm-up)
    for _ in range(3):
        _pk, _msk = cpabe.setup()
        _sk = cpabe.keygen(_pk, _msk, attr_list)
        
    gc.disable() 

    for i in range(N):
        start = time.perf_counter()
        pk, msk = cpabe.setup()
        sum_setup += (time.perf_counter() - start)

        start = time.perf_counter()
        key = cpabe.keygen(pk, msk, attr_list)
        sum_keygen += (time.perf_counter() - start)

        start = time.perf_counter()
        ct = cpabe.encrypt(pk, msg, attr_policy)
        sum_enc += (time.perf_counter() - start)

        start = time.perf_counter()
        ct_prime = cpabe.sanitize(pk, ct)
        sum_sanitize += (time.perf_counter() - start)

        start = time.perf_counter()
        result = cpabe.decrypt(pk, ct_prime, key)
        sum_decrypt += (time.perf_counter() - start)       
        
        assert result == msg, f"{cpabe.name} 解密失败！测出的时间无效！"
    
    gc.enable() 
    
    # 指标归一化
    init_time = (sum_setup + sum_keygen) / N
    enc_time = sum_enc / N
    san_time = sum_sanitize / N
    total_dec = sum_decrypt / N
    local_dec = sum_decrypt / N # SACS 没有外包，用户承担全部解密

    return [init_time, enc_time, san_time, total_dec, local_dec]

# =====================================================================
# 2. 测量 FSACO (IoT 2024)
# =====================================================================
def measure_fsaco(cpabe, group, attr_list, attr_policy, msg, N=100):
    sum_setup = sum_keygen = sum_enc = sum_sanitize = sum_decrypt = 0.0
    
    for _ in range(3):
        _pk, _msk = cpabe.setup()
        
    gc.disable()
    for i in range(N):
        start = time.perf_counter()
        pk, msk = cpabe.setup()
        sum_setup += (time.perf_counter() - start)

        start = time.perf_counter()
        kT, kD = cpabe.keygen(pk, msk, attr_list)
        kP, kS = cpabe.keygen_prime(pk)
        sum_keygen += (time.perf_counter() - start)

        start = time.perf_counter()
        ct = cpabe.encrypt(pk, msg, attr_policy)
        sum_enc += (time.perf_counter() - start)

        K_prime = group.random(GT)
        start = time.perf_counter()
        # ⚠️ 注意：FSACO 的 sanitize 在底层执行了 O(|S|) 次的解密配对！
        ct_prime = cpabe.sanitize(pk, kP, kT, ct, K_prime)
        sum_sanitize += (time.perf_counter() - start)

        start = time.perf_counter()
        # 这里的 decrypt 仅仅是极轻量的用户本地模幂
        rec_K, rec_K_prime = cpabe.decrypt(ct_prime, kD, kS)
        sum_decrypt += (time.perf_counter() - start)
        
        assert rec_K == msg, f"{cpabe.name} 解密失败！"
        
    gc.enable()

    init_time = (sum_setup + sum_keygen) / N
    enc_time = sum_enc / N
    san_time = sum_sanitize / N
    
    # ✅ 核心修正：FSACO 的 Total_Dec 必须包含清洗器代工的外包解密时间！
    total_dec = (sum_sanitize + sum_decrypt) / N
    local_dec = sum_decrypt / N

    return [init_time, enc_time, san_time, total_dec, local_dec]

# =====================================================================
# 3. 测量 SRACS (TSC 2025)
# =====================================================================
def measure_sracs(cpabe, attr_list, attr_policy, msg, N=100, cols_est=100):
    sum_setup = sum_keygen = sum_enc = sum_sanitize = sum_dkeygen = sum_dec_out = sum_dec_full = 0.0
    
    for _ in range(3):
        _pk, _msk = cpabe.setup()
        
    gc.disable()
    for i in range(N):
        start = time.perf_counter()
        pk, msk = cpabe.setup()
        sum_setup += (time.perf_counter() - start)

        start = time.perf_counter()
        SK, WGK, PGK = cpabe.keygen(pk, msk, attr_list)
        sum_keygen += (time.perf_counter() - start)

        start = time.perf_counter()
        CT_I = cpabe.encrypt_out(pk, num_cols_estimate=cols_est) 
        CT_O = cpabe.encrypt_full(pk, CT_I, msg, attr_policy)
        sum_enc += (time.perf_counter() - start)

        start = time.perf_counter()
        CT_S = cpabe.sanitize(pk, CT_O, PGK)
        sum_sanitize += (time.perf_counter() - start)

        start = time.perf_counter()
        RK, DK = cpabe.dkeygen(SK)
        sum_dkeygen += (time.perf_counter() - start)

        start = time.perf_counter()
        CT_P = cpabe.decrypt_out(pk, CT_S, DK, attr_list)
        sum_dec_out += (time.perf_counter() - start)

        start = time.perf_counter()
        rec_msg = cpabe.decrypt_full(pk, CT_P, RK, WGK)
        sum_dec_full += (time.perf_counter() - start)
        
        assert rec_msg == msg, f"{cpabe.name} 解密失败！"
        
    gc.enable()

    # 合并指标：代理密钥 dkeygen 计入系统初始化开销
    init_time = (sum_setup + sum_keygen + sum_dkeygen) / N
    enc_time = sum_enc / N
    san_time = sum_sanitize / N
    total_dec = (sum_dec_out + sum_dec_full) / N
    local_dec = sum_dec_full / N

    return [init_time, enc_time, san_time, total_dec, local_dec]

# =====================================================================
# 4. 测量 Ours (Asymmetric)
# =====================================================================
def measure_ours(cpabe, attr_list, attr_policy, msg, N=100): 
    sum_setup = sum_keygen = sum_keygen_out = sum_enc = sum_sanitize = sum_dec_out = sum_dec_user = 0.0

    for _ in range(3):
        _pk, _msk = cpabe.setup()
        _sk = cpabe.keygen(_pk, _msk, attr_list)

    gc.disable() 
    for i in range(N):
        start = time.perf_counter()
        pk, msk = cpabe.setup()
        sum_setup += (time.perf_counter() - start)

        start = time.perf_counter()
        sk = cpabe.keygen(pk, msk, attr_list)
        sum_keygen += (time.perf_counter() - start)

        start = time.perf_counter()
        tk, dk = cpabe.keygen_out(sk)
        sum_keygen_out += (time.perf_counter() - start)

        start = time.perf_counter()
        ct = cpabe.encrypt(pk, msg, attr_policy)
        sum_enc += (time.perf_counter() - start)

        start = time.perf_counter()
        ct_prime = cpabe.sanitize(pk, ct)
        sum_sanitize += (time.perf_counter() - start)

        start = time.perf_counter()
        partial_ctxt = cpabe.decrypt_out(pk, tk, ct_prime)
        sum_dec_out += (time.perf_counter() - start)

        start = time.perf_counter()
        result = cpabe.decrypt_user(pk, dk, partial_ctxt)
        sum_dec_user += (time.perf_counter() - start)       
        
        assert result == msg, f"{cpabe.name} 解密失败！"
    
    gc.enable() 

    # 合并指标：代理密钥 keygen_out 计入系统初始化开销
    init_time = (sum_setup + sum_keygen + sum_keygen_out) / N
    enc_time = sum_enc / N
    san_time = sum_sanitize / N
    total_dec = (sum_dec_out + sum_dec_user) / N
    local_dec = sum_dec_user / N

    return [init_time, enc_time, san_time, total_dec, local_dec]

# =====================================================================
# 测试数据生成与主程序
# =====================================================================
def create_test_data(n):
    # 生成最苛刻的全 AND 策略: "(1 and 2 and 3 ... and n)"
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

    # 初始化最干净的 CSV 表头 (完美对称的 5 个指标)
    csv_file = 'Results/Final_4Schemes_Comparison_5Phases.csv'
    with open(csv_file, 'w') as f:
        f.write("PolicySize,"
                "SACS_Init,SACS_Enc,SACS_San,SACS_TotDec,SACS_LocDec,"
                "FSACO_Init,FSACO_Enc,FSACO_San,FSACO_TotDec,FSACO_LocDec,"
                "SRACS_Init,SRACS_Enc,SRACS_San,SRACS_TotDec,SRACS_LocDec,"
                "Ours_Init,Ours_Enc,Ours_San,Ours_TotDec,Ours_LocDec\n")

    # Group 1: SS512 (给 SACS, FSACO, SRACS 使用)
    group_sym = PairingGroup('SS512')    
    msg_sym = group_sym.random(GT)

    # Group 2: MNT159 (给 Ours 使用)
    group_asym = PairingGroup('MNT159')  
    msg_asym = group_asym.random(GT)
    
    policy_sizes = [10, 20, 30, 40, 50]
    N_loops = 50 
    
    for size in policy_sizes:
        print(f"\n{'='*105}")
        print(f" 🚀 正在测试 Policy Size = {size} | 统一指标 [Init, Enc, San, TotDec, LocDec]")
        print(f"{'='*105}")
        
        policy_str, attr_list = create_test_data(size)

        # ---------- 1. SACS ----------
        sacs = SACS22CPABE(group_sym, uni_size=100)
        t_s = measure_sacs(sacs, attr_list, policy_str, msg_sym, N=N_loops)
        print(f" [SACS]  Init:{t_s[0]*1000:6.2f} | Enc:{t_s[1]*1000:6.2f} | San:{t_s[2]*1000:6.2f} | TotDec:{t_s[3]*1000:6.2f} | LocDec:{t_s[4]*1000:6.2f} ms")

        # ---------- 2. FSACO ----------
        fsaco = FSACO_CPABE(group_sym, uni_size=100)
        t_f = measure_fsaco(fsaco, group_sym, attr_list, policy_str, msg_sym, N=N_loops)
        print(f" [FSACO] Init:{t_f[0]*1000:6.2f} | Enc:{t_f[1]*1000:6.2f} | San:{t_f[2]*1000:6.2f} | TotDec:{t_f[3]*1000:6.2f} | LocDec:{t_f[4]*1000:6.2f} ms")

        # ---------- 3. SRACS ----------
        sracs = SRACS25CPABE(group_sym, uni_size=100)
        t_sr = measure_sracs(sracs, attr_list, policy_str, msg_sym, N=N_loops, cols_est=size+10)
        print(f" [SRACS] Init:{t_sr[0]*1000:6.2f} | Enc:{t_sr[1]*1000:6.2f} | San:{t_sr[2]*1000:6.2f} | TotDec:{t_sr[3]*1000:6.2f} | LocDec:{t_sr[4]*1000:6.2f} ms")

        # ---------- 4. Ours ----------
        our = MyScheme(group_asym)
        t_o = measure_ours(our, attr_list, policy_str, msg_asym, N=N_loops)
        print(f" [Ours]  Init:{t_o[0]*1000:6.2f} | Enc:{t_o[1]*1000:6.2f} | San:{t_o[2]*1000:6.2f} | TotDec:{t_o[3]*1000:6.2f} | LocDec:{t_o[4]*1000:6.2f} ms")
        
        # 实时写入 CSV (全部转为 ms 级别)
        with open(csv_file, 'a') as f:
            f.write(f"{size},"
                    f"{t_s[0]*1000:.2f},{t_s[1]*1000:.2f},{t_s[2]*1000:.2f},{t_s[3]*1000:.2f},{t_s[4]*1000:.2f},"
                    f"{t_f[0]*1000:.2f},{t_f[1]*1000:.2f},{t_f[2]*1000:.2f},{t_f[3]*1000:.2f},{t_f[4]*1000:.2f},"
                    f"{t_sr[0]*1000:.2f},{t_sr[1]*1000:.2f},{t_sr[2]*1000:.2f},{t_sr[3]*1000:.2f},{t_sr[4]*1000:.2f},"
                    f"{t_o[0]*1000:.2f},{t_o[1]*1000:.2f},{t_o[2]*1000:.2f},{t_o[3]*1000:.2f},{t_o[4]*1000:.2f}\n")

if __name__ == "__main__":
    main()