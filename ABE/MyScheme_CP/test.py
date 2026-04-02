from charm.toolbox.pairinggroup import PairingGroup, GT
import time

# 导入四个方案的类 (请确保类名与你 __init__.py 中定义的一致)
try:
    from Ours import FABEO22CPABE
    from SACS import SACS22CPABE
    from FSACO import FSACO_CPABE
    from SRACS import SRACS25CPABE
except ImportError as e:
    print(f"导入错误，请检查目录和类名: {e}")

def run_tests():
    # 1. 初始化全局环境
    print("="*50)
    print("初始化测试环境 (Type 1 对称群 SS512)...")
    group = PairingGroup('SS512')
    uni_size = 50  # 属性宇宙大小
    
    # 设定测试属性和策略 (使用数字字符串以对齐 SACS/FSACO/SRACS)
    attr_list = ['1', '3', '5', '7', '9']
    policy_str = '(1 and 3) and (5 or 7)'
    
    # 生成一个随机的 GT 群元素作为统一的测试明文/对称密钥
    msg = group.random(GT)
    
    print(f"测试属性列表: {attr_list}")
    print(f"测试访问策略: {policy_str}")
    print("="*50)

    # ==========================================
    # 1. 测试 Ours (FABEO22 改进版)
    # ==========================================
    print("\n[1/4] 开始测试 Ours (FABEO22 改进版) ...")
    try:
        ours = FABEO22CPABE(group)
        pk_ours, msk_ours = ours.setup()
        
        sk_ours = ours.keygen(pk_ours, msk_ours, attr_list)
        tk_ours, dk_ours = ours.keygen_out(sk_ours)
        
        ctxt_ours = ours.encrypt(pk_ours, msg, policy_str)
        ctxt_prime_ours = ours.sanitize(pk_ours, ctxt_ours)
        
        partial_ctxt_ours = ours.decrypt_out(pk_ours, tk_ours, ctxt_prime_ours)
        rec_msg_ours = ours.decrypt_user(pk_ours, dk_ours, partial_ctxt_ours)
        
        assert msg == rec_msg_ours, "Ours: 解密出的明文与原明文不匹配！"
        print("✅ Ours 测试通过！")
    except Exception as e:
        print(f"❌ Ours 测试失败: {e}")

    # ==========================================
    # 2. 测试 SACS (TDSC 2022)
    # ==========================================
    print("\n[2/4] 开始测试 SACS (TDSC 2022) ...")
    try:
        sacs = SACS22CPABE(group, uni_size)
        pk_sacs, msk_sacs = sacs.setup()
        
        key_sacs = sacs.keygen(pk_sacs, msk_sacs, attr_list)
        
        ctxt_sacs = sacs.encrypt(pk_sacs, msg, policy_str)
        ctxt_prime_sacs = sacs.sanitize(pk_sacs, ctxt_sacs)
        
        rec_msg_sacs = sacs.decrypt(pk_sacs, ctxt_prime_sacs, key_sacs)
        
        assert msg == rec_msg_sacs, "SACS: 解密出的明文与原明文不匹配！"
        print("✅ SACS 测试通过！")
    except Exception as e:
        print(f"❌ SACS 测试失败: {e}")

    # ==========================================
    # 3. 测试 FSACO
    # ==========================================
    print("\n[3/4] 开始测试 FSACO ...")
    try:
        fsaco = FSACO_CPABE(group, uni_size)
        pk_fsaco, msk_fsaco = fsaco.setup()
        
        kT_fsaco, kD_fsaco = fsaco.keygen(pk_fsaco, msk_fsaco, attr_list)
        kP_fsaco, kS_fsaco = fsaco.keygen_prime(pk_fsaco)
        
        ctxt_orig_fsaco = fsaco.encrypt(pk_fsaco, msg, policy_str) # msg 作为 K
        
        K_prime_fsaco = group.random(GT) # Sanitizer 的辅助密钥
        ctxt_sanitized_fsaco = fsaco.sanitize(pk_fsaco, kP_fsaco, kT_fsaco, ctxt_orig_fsaco, K_prime_fsaco)
        
        rec_K_fsaco, rec_K_prime_fsaco = fsaco.decrypt(ctxt_sanitized_fsaco, kD_fsaco, kS_fsaco)
        
        assert msg == rec_K_fsaco, "FSACO: 解密出的 K 与原 K 不匹配！"
        assert K_prime_fsaco == rec_K_prime_fsaco, "FSACO: 解密出的 K' 不匹配！"
        print("✅ FSACO 测试通过！")
    except Exception as e:
        print(f"❌ FSACO 测试失败: {e}")

    # ==========================================
    # 4. 测试 SRACS (TSC 2025)
    # ==========================================
    print("\n[4/4] 开始测试 SRACS (TSC 2025) ...")
    try:
        sracs = SRACS25CPABE(group, uni_size)
        pk_sracs, msk_sracs = sracs.setup()
        
        SK_sracs, WGK_sracs, PGK_sracs = sracs.keygen(pk_sracs, msk_sracs, attr_list)
        
        # 离线加密 + 在线加密
        CT_I_sracs = sracs.encrypt_out(pk_sracs, num_cols_estimate=10)
        CT_O_sracs = sracs.encrypt_full(pk_sracs, CT_I_sracs, msg, policy_str)
        
        # 净化 (注意传入 PGK 字典)
        CT_S_sracs = sracs.sanitize(pk_sracs, CT_O_sracs, PGK_sracs)
        
        # 解密密钥生成 + 外包解密 + 完整解密
        RK_sracs, DK_sracs = sracs.dkeygen(SK_sracs)
        CT_P_sracs = sracs.decrypt_out(pk_sracs, CT_S_sracs, DK_sracs, attr_list)
        rec_msg_sracs = sracs.decrypt_full(pk_sracs, CT_P_sracs, RK_sracs, WGK_sracs)
        
        assert msg == rec_msg_sracs, "SRACS: 解密出的明文与原明文不匹配！"
        print("✅ SRACS 测试通过！")
    except Exception as e:
        print(f"❌ SRACS 测试失败: {e}")

    print("\n" + "="*50)
    print("功能性验证完毕！")

if __name__ == "__main__":
    run_tests()