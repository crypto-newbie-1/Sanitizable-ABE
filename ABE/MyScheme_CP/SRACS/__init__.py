'''
Implementation of the 2025 TSC Paper:
"SRACS: Sanitizable and Revocable Access Control Scheme for Crowdsourcing Healthcare"
Modified for Symmetric Group (Type 1), with Revocation feature temporarily bypassed.
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class SRACS25CPABE(ABEnc):
    def __init__(self, group_obj, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.name = "SRACS (TSC 2025) - No Revocation"
        self.group = group_obj
        self.uni_size = uni_size  
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Trusted Authority (TA) initializes the system.
        """
        if debug: print('\nSetup algorithm:\n')
        g = self.group.random(G1)
        alpha = self.group.random(ZR)
        a = self.group.random(ZR)
        
        h = g ** a
        egg_alpha = pair(g, g) ** alpha

        beta = {}
        for i in range(self.uni_size + 1):
            beta[str(i)] = self.group.random(ZR)

        pk = {'g': g, 'h': h, 'beta': beta, 'egg_alpha': egg_alpha}
        msk = {'g_alpha': g ** alpha, 'alpha': alpha}
        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Worker Registration: Combined AKeyGen and simplified GKeyGen (No Revocation).
        """
        if debug: print('\nKey generation algorithm:\n')
        r = self.group.random(ZR)

        # 1. Attribute Key Generation
        K1 = msk['g_alpha'] * (pk['h'] ** r)
        K2 = pk['g'] ** r
        K_x = {}
        for attr in attr_list:
            attr_stripped = self.util.strip_index(attr)
            K_x[attr_stripped] = pk['g'] ** (pk['beta'][attr_stripped] * r)

        # 2. Group Key Generation (Simplified: No binary tree)
        WGK = {}
        PGK = {}
        gT = pair(pk['g'], pk['g']) # 获取 GT 群的生成元
        for attr in attr_list:
            attr_stripped = self.util.strip_index(attr)
            ak_val = self.group.random(ZR)
            WGK[attr_stripped] = ak_val              
            PGK[attr_stripped] = gT ** ak_val    # ✅ 将 PGK 生成在 GT 群

        SK = {'attr_list': attr_list, 'K1': K1, 'K2': K2, 'K_x': K_x}
        return SK, WGK, PGK

    def encrypt_out(self, pk, num_cols_estimate=50):
        """
        Outsourced Encryption by ESP.
        """
        if debug: print('\nOutsourced Encryption:\n')
        s_tilde = self.group.random(ZR)
        C0 = pk['g'] ** s_tilde

        rows_offline = {}
        for i in range(num_cols_estimate):
            beta_tilde = self.group.random(ZR)
            t_tilde = self.group.random(ZR)
            omega_tilde = self.group.random(ZR)

            C_i_1 = (pk['h'] ** omega_tilde) * (pk['g'] ** (-beta_tilde * t_tilde))
            C_i_2 = pk['g'] ** t_tilde
            
            rows_offline[i] = {
                'beta_tilde': beta_tilde, 't_tilde': t_tilde, 'omega_tilde': omega_tilde,
                'C_i_1': C_i_1, 'C_i_2': C_i_2
            }
            
        return {'s_tilde': s_tilde, 'C0': C0, 'rows_offline': rows_offline}

    def encrypt_full(self, pk, CT_I, msg, policy_str):
        """
        Full Encryption by Requester using offline parameters.
        """
        if debug: print('\nFull Encryption:\n')
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        u = [self.group.random(ZR) for _ in range(num_cols)]
        s = u[0]

        EK = self.group.random(GT)
        C1 = s - CT_I['s_tilde']
        C2 = msg * EK   
        C3 = EK * (pk['egg_alpha'] ** s)

        CT_O_rows = {}
        row_idx = 0
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            cols = len(row)
            omega_i = sum(row[j] * u[j] for j in range(cols))
            t_i = self.group.random(ZR)

            row_off = CT_I['rows_offline'][row_idx]

            C_i_3 = omega_i - row_off['omega_tilde']
            C_i_4 = t_i - row_off['t_tilde']
            C_i_5 = (row_off['beta_tilde'] * row_off['t_tilde']) - (pk['beta'][attr_stripped] * t_i)

            CT_O_rows[attr] = {
                'C_i_1': row_off['C_i_1'], 'C_i_2': row_off['C_i_2'],
                'C_i_3': C_i_3, 'C_i_4': C_i_4, 'C_i_5': C_i_5
            }
            row_idx += 1

        tau = self.group.hash((EK, C2), ZR)

        return {'policy': policy, 'C0': CT_I['C0'], 'C1': C1, 'C2': C2, 'C3': C3, 'rows': CT_O_rows, 'tau': tau}

    def sanitize(self, pk, CT_O, PGK_dict):
        """
        Task Sanitizing by Sanitizer.
        """
        if debug: print('\nSanitize algorithm:\n')
        mono_span_prog = self.util.convert_policy_to_msp(CT_O['policy'])

        # Step 1: Integrity Checking
        dummy_S = list(set([self.util.strip_index(attr) for attr in mono_span_prog.keys()]))
        gamma = self.group.random(ZR)
        t_tilde_chk = self.group.random(ZR)

        K1_prime = (pk['g'] ** gamma) * (pk['h'] ** t_tilde_chk)
        K2_prime = pk['g'] ** t_tilde_chk
        K_x_prime = {attr: pk['g'] ** (pk['beta'][attr] * t_tilde_chk) for attr in dummy_S}

        nodes = self.util.prune(CT_O['policy'], dummy_S)
        if not nodes:
            raise ValueError("Sanitize Checking Failed: Policy structurally invalid.")

        # coeffs = self.util.getCoefficients(CT_O['policy'])
        prodGT = self.group.init(GT, 1)  # ✅ 修改点1: 强行初始化为GT单位元
        
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            # c_i = coeffs[attr]
            row = CT_O['rows'][attr]
            
            e1 = pair(K2_prime, row['C_i_1'] * (pk['h'] ** row['C_i_3']) * (pk['g'] ** row['C_i_5']))
            e2 = pair(K_x_prime[attr_stripped], row['C_i_2'] * (pk['g'] ** row['C_i_4']))
            prodGT *= (e1 * e2)

        left_side = pair(K1_prime, CT_O['C0'] * (pk['g'] ** CT_O['C1'])) / prodGT
        right_side = pair(pk['g'] ** gamma, CT_O['C0'] * (pk['g'] ** CT_O['C1']))

        if left_side != right_side:
            raise ValueError("Sanitize Checking Failed: Original ciphertext was corrupted!")

        # Step 2: Ciphertext Sanitizing
        z = self.group.random(ZR)
        EK_prime = self.group.random(GT)

        C2_prime = CT_O['C2'] * EK_prime
        V_tilde = pair(pk['g'], pk['g']) ** z    # ✅ 生成在 GT 群

        prod_PGK = self.group.init(GT, 1)        # ✅ 正确初始化 GT 单位元
        for attr in mono_span_prog.keys():
            attr_stripped = self.util.strip_index(attr)
            prod_PGK *= PGK_dict[attr_stripped] ** (-z)
            
        V = EK_prime * prod_PGK

        CT_S = {
            'policy': CT_O['policy'], 'C0': CT_O['C0'], 'C1': CT_O['C1'],
            'C2_prime': C2_prime, 'C3': CT_O['C3'], 'rows': CT_O['rows'],
            'V': V, 'V_tilde': V_tilde, 'tau': CT_O['tau']
        }
        return CT_S

    def dkeygen(self, sk):
        """
        Decryption Key Generation by Worker.
        """
        if debug: print('\nDecryption Key Generation:\n')
        gamma_rk = self.group.random(ZR) 
        
        DK = {
            'DK1': sk['K1'] ** gamma_rk,
            'DK2': sk['K2'] ** gamma_rk,
            'DK_x': {attr: key ** gamma_rk for attr, key in sk['K_x'].items()}
        }
        return gamma_rk, DK

    def decrypt_out(self, pk, CT_S, DK, attr_list):
        """
        Outsourced Decryption by DSP.
        """
        if debug: print('\nOutsourced Decryption:\n')
        nodes = self.util.prune(CT_S['policy'], attr_list)
        if not nodes:
            return None

        # coeffs = self.util.getCoefficients(CT_S['policy'])
        B = self.group.init(GT, 1) # ✅ 修改点2: 强行初始化为GT单位元
        
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            # c_i = coeffs[attr]
            row = CT_S['rows'][attr]

            # ✅ 包含 C_i_3 的完整盲化还原
            e1 = pair(DK['DK2'], row['C_i_1'] * (pk['h'] ** row['C_i_3']) * (pk['g'] ** row['C_i_5']))
            e2 = pair(DK['DK_x'][attr_stripped], row['C_i_2'] * (pk['g'] ** row['C_i_4']))
            B *= (e1 * e2)

        D = pair(DK['DK1'], CT_S['C0'] * (pk['g'] ** CT_S['C1'])) / B
        
        CT_P = {
            'policy': CT_S['policy'], 'C2_prime': CT_S['C2_prime'], 'C3': CT_S['C3'],
            'D': D, 'V': CT_S['V'], 'V_tilde': CT_S['V_tilde'], 'tau': CT_S['tau']
        }
        return CT_P

    def decrypt_full(self, pk, CT_P, RK, WGK_dict):
        """
        Full Decryption by Worker.
        """
        if debug: print('\nFull Decryption:\n')
        if CT_P is None:
            return None
            
        mono_span_prog = self.util.convert_policy_to_msp(CT_P['policy'])

        # 1. Recover first encryption key EK
        egg_alpha_s = CT_P['D'] ** (RK ** -1) # ✅ 修改点3: 使用模逆运算而不是取反运算
        EK = CT_P['C3'] / egg_alpha_s

        # 2. Recover second encryption key EK'
        sum_AK = 0
        for attr in mono_span_prog.keys():
            attr_stripped = self.util.strip_index(attr)
            sum_AK += WGK_dict[attr_stripped]
            
        EK_prime = CT_P['V'] * (CT_P['V_tilde'] ** sum_AK)

        # 3. Verify correctness using tau
        recovered_C2 = CT_P['C2_prime'] / EK_prime
        tau_prime = self.group.hash((EK, recovered_C2), ZR)
        
        if tau_prime != CT_P['tau']:
            raise ValueError("Decryption Verification Failed: DSP returned incorrect results!")

        # 4. Final decryption
        msg = CT_P['C2_prime'] / (EK * EK_prime)
        return msg