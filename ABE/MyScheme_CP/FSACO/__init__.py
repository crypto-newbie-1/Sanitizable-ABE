from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class FSACO_CPABE(ABEnc):
    def __init__(self, group_obj, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.name = "FSACO CP-ABE (Symmetric Pure for Benchmark)"
        self.group = group_obj
        self.uni_size = uni_size
        self.util = MSP(self.group, verbose)

    def setup(self):
        if debug: print('\nSetup algorithm:\n')

        g = self.group.random(G1)
        alpha = self.group.random(ZR)
        a = self.group.random(ZR)
        
        e_gg_alpha = pair(g, g) ** alpha
        g_a = g ** a
        gT = pair(g, g) 

        h = [0]
        for i in range(self.uni_size):
            h.append(self.group.random(G1))

        msk = {'alpha': alpha, 'a': a}
        pk = {'g': g, 'g_a': g_a, 'h': h, 'e_gg_alpha': e_gg_alpha, 'gT': gT}

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        if debug: print('\nKey generation algorithm (ABE):\n')

        beta = self.group.random(ZR)
        u = self.group.random(ZR)

        sk0 = (pk['g'] ** (msk['alpha'] / beta)) * (pk['g'] ** (msk['a'] * u))
        sk1 = pk['g'] ** u
        
        sk2 = {}
        for attr in attr_list:
            attr_idx = int(attr) 
            sk2[attr] = pk['h'][attr_idx] ** u
            
        kT = {'attr_list': attr_list, 'sk0': sk0, 'sk1': sk1, 'sk2': sk2}
        kD = beta

        return kT, kD

    def keygen_prime(self, pk):
        if debug: print('\nKey generation algorithm (ElGamal):\n')
        
        d = self.group.random(ZR)
        kS = d
        kP = pk['gT'] ** d
        
        return kP, kS

    def encrypt(self, pk, K, policy_str):
        if debug: print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        s = self.group.random(ZR)
        
        C_prime = pk['g'] ** s
        C_double_prime = K * (pk['e_gg_alpha'] ** s)

        v = [s]
        for i in range(num_cols - 1):
            v.append(self.group.random(ZR))

        C_i = {}
        D_i = {}
        
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attr_idx = int(attr_stripped) 
            
            len_row = len(row)
            lambda_i = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            t_i = self.group.random(ZR)
            
            C_i[attr] = (pk['g_a'] ** lambda_i) * (pk['h'][attr_idx] ** (-t_i))
            D_i[attr] = pk['g'] ** t_i

        return {'policy': policy, 'C_prime': C_prime, 'C_double_prime': C_double_prime, 'C_i': C_i, 'D_i': D_i}

    def sanitize(self, pk, kP, kT, ctxt_orig, K_prime):
        if debug: print('\nSanitize algorithm:\n')

        nodes = self.util.prune(ctxt_orig['policy'], kT['attr_list'])
        if not nodes:
            print("Policy not satisfied during sanitization.")
            return None

        # ❌ 这行完全不需要了，直接删掉或者注释掉
        # coeffs = self.util.getCoefficients(ctxt_orig['policy']) 

        prod = self.group.init(GT, 1)
        
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)

            # 这里的顺序无论是 (C_i, sk1) 还是反过来，在 SS512 下都可以
            pair_C = pair(ctxt_orig['C_i'][attr], kT['sk1'])
            pair_D = pair(ctxt_orig['D_i'][attr], kT['sk2'][attr_stripped])
            
            # ✅ 修复点：删除 ** c_i，直接相乘累加！
            prod *= (pair_C * pair_D) 

        C_sd = pair(ctxt_orig['C_prime'], kT['sk0']) / prod

        b = self.group.random(ZR)
        V1_1 = pk['gT'] ** b
        V1_2 = K_prime * (kP ** b)

        return {'policy': ctxt_orig['policy'], 'V1_1': V1_1, 'V1_2': V1_2, 'C_double_prime': ctxt_orig['C_double_prime'], 'C_sd': C_sd}

    def decrypt(self, ctxt_sanitized, kD, kS):
        if debug: print('\nDecryption algorithm:\n')

        if ctxt_sanitized is None:
            return None

        e_gg_alpha_s = ctxt_sanitized['C_sd'] ** kD
        
        K_recovered = ctxt_sanitized['C_double_prime'] / e_gg_alpha_s
        
        K_prime_recovered = ctxt_sanitized['V1_2'] / (ctxt_sanitized['V1_1'] ** kS)
        
        return K_recovered, K_prime_recovered