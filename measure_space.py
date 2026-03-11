'''
Space and Communication Overhead Measurement Script
Target: IEEE TDSC Submission
Baselines: SACS (TDSC'22), Inscrypt'24
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
import os


from ABE.MyScheme_CP.waters11cp import SACS22CPABE
from ABE.MyScheme_CP.FABESA_CP import Inscrypt24CPABE
from ABE.MyScheme_CP.FABEO_CP import FABEO22CPABE as MyScheme

def get_size(obj, group):
    """
    深度遍历字典/列表，将其中的群元素序列化为二进制并统计总字节数
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

            serialized_bytes = group.serialize(obj)
            total_size += len(serialized_bytes)
        except Exception:

            pass 
    return total_size


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


    with open('Results/TDSC_Space_Comparison.csv', 'w') as f:
        f.write("Attribute_Policy_Size,"
                "SACS_PK,SACS_SK,SACS_CT_Raw,SACS_CT_Sanitized,SACS_User_Download,"
                "Ins_PK,Ins_SK,Ins_CT_Raw,Ins_CT_Sanitized,Ins_User_Download,"
                "Our_PK,Our_SK,Our_CT_Raw,Our_CT_Sanitized,Our_User_Download\n")


    group_sym = PairingGroup('SS512')    
    msg_sym = group_sym.random(GT)

    group_asym = PairingGroup('MNT159')  
    msg_asym = group_asym.random(GT)
    
    test_sizes = [20, 40, 60, 80, 100]
    
    for size in test_sizes:
        print(f"\n{'='*90}")
        print(f"  Measuring Storage & Communication with Size = {size}")
        print(f"{'='*90}")
        
        policy_str, attr_list = create_test_data(size)

        sacs = SACS22CPABE(group_sym, uni_size=150)
        pk_s, msk_s = sacs.setup()
        sk_s = sacs.keygen(pk_s, msk_s, attr_list)
        ct_s = sacs.encrypt(pk_s, msg_sym, policy_str)
        ct_prime_s = sacs.sanitize(pk_s, ct_s)
        
        s_pk_size = get_size(pk_s, group_sym)
        s_sk_size = get_size(sk_s, group_sym)
        s_ct_size = get_size(ct_s, group_sym)
        s_san_size = get_size(ct_prime_s, group_sym)
        s_download_size = s_san_size 

        print(f"[SACS'22]  PK: {s_pk_size} B | SK: {s_sk_size} B | CT: {s_ct_size} B | San_CT: {s_san_size} B | Download: {s_download_size} B")


        inscrypt = Inscrypt24CPABE(group_asym)
        pk_i, msk_i = inscrypt.setup()
        sk_i = inscrypt.keygen(pk_i, msk_i, attr_list)
        tk_i, dk_i = inscrypt.keygen_out(sk_i)
        ct_i = inscrypt.encrypt(pk_i, msg_asym, policy_str)
        ct_prime_i = inscrypt.sanitize(pk_i, ct_i)
        partial_ct_i = inscrypt.decrypt_out(pk_i, tk_i, ct_prime_i)

        i_pk_size = get_size(pk_i, group_asym)
        i_sk_size = get_size(sk_i, group_asym)
        i_ct_size = get_size(ct_i, group_asym)
        i_san_size = get_size(ct_prime_i, group_asym)
        i_download_size = get_size(partial_ct_i, group_asym) 

        print(f"[Inscrypt] PK: {i_pk_size} B | SK: {i_sk_size} B | CT: {i_ct_size} B | San_CT: {i_san_size} B | Download: {i_download_size} B")

        our = MyScheme(group_asym)
        pk_o, msk_o = our.setup()
        sk_o = our.keygen(pk_o, msk_o, attr_list)
        tk_o, dk_o = our.keygen_out(sk_o)
        ct_o = our.encrypt(pk_o, msg_asym, policy_str)
        ct_prime_o = our.sanitize(pk_o, ct_o)
        partial_ct_o = our.decrypt_out(pk_o, tk_o, ct_prime_o)

        o_pk_size = get_size(pk_o, group_asym)
        o_sk_size = get_size(sk_o, group_asym)
        o_ct_size = get_size(ct_o, group_asym)
        o_san_size = get_size(ct_prime_o, group_asym)
        o_download_size = get_size(partial_ct_o, group_asym) # 我们的用户同样只需下载部分密文

        print(f"[Our]      PK: {o_pk_size} B | SK: {o_sk_size} B | CT: {o_ct_size} B | San_CT: {o_san_size} B | Download: {o_download_size} B")
        

        with open('Results/TDSC_Space_Comparison.csv', 'a') as f:
            f.write(f"{size},"
                    f"{s_pk_size},{s_sk_size},{s_ct_size},{s_san_size},{s_download_size},"
                    f"{i_pk_size},{i_sk_size},{i_ct_size},{i_san_size},{i_download_size},"
                    f"{o_pk_size},{o_sk_size},{o_ct_size},{o_san_size},{o_download_size}\n")

if __name__ == "__main__":
    main()