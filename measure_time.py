'''
Performance Measurement Script for Proposed Sanitized Outsourced CP-ABE
Baselines: SACS (TDSC'22), Inscrypt'24
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
import time
import os
import gc 

from ABE.MyScheme_CP.waters11cp import SACS22CPABE
from ABE.MyScheme_CP.FABESA_CP import Inscrypt24CPABE
from ABE.MyScheme_CP.FABEO_CP import FABEO22CPABE as MyScheme
# =====================================================================


def measure_sacs(cpabe, attr_list, attr_policy, msg, N=100): 
    sum_setup = sum_keygen = sum_enc = sum_sanitize = sum_decrypt = 0.0

    for _ in range(5):
        _pk, _msk = cpabe.setup()
        _sk = cpabe.keygen(_pk, _msk, attr_list)
        
    gc.disable() 

    for i in range(N):
        start = time.perf_counter()
        (pk, msk) = cpabe.setup()
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
    
    return [sum_setup/N, sum_keygen/N, sum_enc/N, sum_sanitize/N, sum_decrypt/N]


def measure_outsourced(cpabe, attr_list, attr_policy, msg, N=100): 
    sum_setup = sum_keygen = sum_keygen_out = sum_enc = sum_sanitize = sum_dec_out = sum_dec_user = 0.0

    for _ in range(5):
        _pk, _msk = cpabe.setup()
        _sk = cpabe.keygen(_pk, _msk, attr_list)

    gc.disable() 

    for i in range(N):
        start = time.perf_counter()
        (pk, msk) = cpabe.setup()
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
        
       
        assert result == msg, f"{cpabe.name} 解密失败！测出的时间无效！"
    
    gc.enable() 

    return [sum_setup/N, sum_keygen/N, sum_keygen_out/N, sum_enc/N, sum_sanitize/N, sum_dec_out/N, sum_dec_user/N]


def create_test_data(n):
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

    with open('Results/TDSC_Performance_Comparison.csv', 'w') as f:
        f.write("PolicySize,SACS_Setup,SACS_KeyGen,SACS_Enc,SACS_San,SACS_Dec,"
                "Ins_Setup,Ins_KeyGen,Ins_KeyGenOut,Ins_Enc,Ins_San,Ins_DecOut,Ins_DecUser,"
                "Our_Setup,Our_KeyGen,Our_KeyGenOut,Our_Enc,Our_San,Our_DecOut,Our_DecUser\n")


    group_sym = PairingGroup('SS512')    
    msg_sym = group_sym.random(GT)

    group_asym = PairingGroup('MNT159')  
    msg_asym = group_asym.random(GT)
    
    policy_sizes = [20, 40, 60, 80, 100]
    
    for size in policy_sizes:
        print(f"\n{'='*100}")
        print(f"  Testing with Policy Size (Attributes) = {size}")
        print(f"{'='*100}")
        
        policy_str, attr_list = create_test_data(size)


        print(">> Running SACS'22 (Symmetric - SS512)...")
        sacs = SACS22CPABE(group_sym, uni_size=150)
        s_t = measure_sacs(sacs, attr_list, policy_str, msg_sym, N=100) # 【修改】：传入 N=100
        print(f"[SACS'22]  Setup: {s_t[0]*1000:.2f} ms | KeyGen: {s_t[1]*1000:.2f} ms | Enc: {s_t[2]*1000:.2f} ms | Sanitize: {s_t[3]*1000:.2f} ms | Dec: {s_t[4]*1000:.2f} ms")

        print(">> Running Inscrypt'24 (Asymmetric - MNT159)...")
        inscrypt = Inscrypt24CPABE(group_asym)
        i_t = measure_outsourced(inscrypt, attr_list, policy_str, msg_asym, N=100) # 【修改】：传入 N=100
        print(f"[Inscrypt] Setup: {i_t[0]*1000:.2f} ms | KeyGen: {i_t[1]*1000:.2f} ms | KeyOut: {i_t[2]*1000:.2f} ms | Enc: {i_t[3]*1000:.2f} ms | San: {i_t[4]*1000:.2f} ms | DecOut: {i_t[5]*1000:.2f} ms | DecUsr: {i_t[6]*1000:.2f} ms")

        print(">> Running Our Scheme (Asymmetric - MNT159)...")
        our = MyScheme(group_asym)
        o_t = measure_outsourced(our, attr_list, policy_str, msg_asym, N=100) # 【修改】：传入 N=100
        print(f"[Our]      Setup: {o_t[0]*1000:.2f} ms | KeyGen: {o_t[1]*1000:.2f} ms | KeyOut: {o_t[2]*1000:.2f} ms | Enc: {o_t[3]*1000:.2f} ms | San: {o_t[4]*1000:.2f} ms | DecOut: {o_t[5]*1000:.2f} ms | DecUsr: {o_t[6]*1000:.2f} ms")
        
        with open('Results/TDSC_Performance_Comparison.csv', 'a') as f:
            f.write(f"{size},"
                    f"{s_t[0]*1000:.2f},{s_t[1]*1000:.2f},{s_t[2]*1000:.2f},{s_t[3]*1000:.2f},{s_t[4]*1000:.2f},"
                    f"{i_t[0]*1000:.2f},{i_t[1]*1000:.2f},{i_t[2]*1000:.2f},{i_t[3]*1000:.2f},{i_t[4]*1000:.2f},{i_t[5]*1000:.2f},{i_t[6]*1000:.2f},"
                    f"{o_t[0]*1000:.2f},{o_t[1]*1000:.2f},{o_t[2]*1000:.2f},{o_t[3]*1000:.2f},{o_t[4]*1000:.2f},{o_t[5]*1000:.2f},{o_t[6]*1000:.2f}\n")

if __name__ == "__main__":
    main()