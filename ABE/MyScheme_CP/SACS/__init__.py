'''
Implementation of the 2022 TDSC Paper:
"Sanitizable Access Control System for Secure Cloud Storage Against Malicious Data Publishers"
Modified to Strictly Enforce Symmetric Group (Type 1) for SS512 Benchmarking.
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class SACS22CPABE(ABEnc):
    def __init__(self, group_obj, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.name = "SACS (TDSC 2022) - Symmetric Pure"
        self.group = group_obj
        self.uni_size = uni_size
        self.util = MSP(self.group, verbose)

    def setup(self):
        if debug: print('\nSetup algorithm:\n')
        g1 = self.group.random(G1)
        g2 = self.group.random(G1) 
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        a = self.group.random(ZR)

        g1_a = g1 ** a
        e_gg_alpha = pair(g1, g2) ** alpha
        e_gg_beta = pair(g1, g2) ** beta

        h = [0]
        for i in range(self.uni_size):
            h.append(self.group.random(G1))

        pk = {'g1': g1, 'g2': g2, 'g1_a': g1_a, 'h': h, 'e_gg_alpha': e_gg_alpha, 'e_gg_beta': e_gg_beta}
        msk = {'g1_alpha': g1 ** alpha, 'g1_beta': g1 ** beta}
        return pk, msk

    def keygen(self, pk, msk, attr_list):
        if debug: print('\nKey generation algorithm:\n')
        t = self.group.random(ZR)
        t_prime = self.group.random(ZR)

        K0 = msk['g1_alpha'] * (pk['g1_a'] ** t)
        L = pk['g2'] ** t
        K_dict = {}

        K0_prime = msk['g1_beta'] * (pk['g1_a'] ** t_prime)
        L_prime = pk['g2'] ** t_prime
        K_dict_prime = {}

        for attr in attr_list:
            attr_idx = int(attr)
            K_dict[attr] = pk['h'][attr_idx] ** t
            K_dict_prime[attr] = pk['h'][attr_idx] ** t_prime

        return {'attr_list': attr_list, 'K0': K0, 'L': L, 'K': K_dict,
                'K0_prime': K0_prime, 'L_prime': L_prime, 'K_prime': K_dict_prime}

    def encrypt(self, pk, msg, policy_str):
        if debug: print('\nEncryption algorithm:\n')
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        u = []
        for i in range(num_cols):
            u.append(self.group.random(ZR))
        s = u[0]

        K = self.group.random(GT)
        C0 = msg * K
        C1 = K * (pk['e_gg_alpha'] ** s)
        C2 = pk['e_gg_beta'] ** s
        D0 = pk['g2'] ** s

        D1 = {}
        D2 = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum_val = sum(row[i] * u[i] for i in range(cols))
            attr_stripped = self.util.strip_index(attr)
            attr_idx = int(attr_stripped)

            z = self.group.random(ZR)
            D1[attr] = (pk['g1_a'] ** sum_val) * (pk['h'][attr_idx] ** -z)
            D2[attr] = pk['g2'] ** z

        return {'policy': policy, 'C0': C0, 'C1': C1, 'C2': C2, 'D0': D0, 'D1': D1, 'D2': D2}

    def sanitize(self, pk, ct):
        if debug: print('\nSanitize algorithm:\n')
        mono_span_prog = self.util.convert_policy_to_msp(ct['policy'])
        num_cols = self.util.len_longest_row

        u_prime = []
        for i in range(num_cols):
            u_prime.append(self.group.random(ZR))
        s_prime = u_prime[0]

        K_prime = self.group.random(GT)
        V0 = ct['C0'] * K_prime
        V1 = ct['C1'] * (pk['e_gg_alpha'] ** s_prime)
        V2 = ct['C2'] * K_prime * (pk['e_gg_beta'] ** s_prime)
        V3 = ct['D0'] * (pk['g2'] ** s_prime)

        A = {}
        B = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum_val = sum(row[i] * u_prime[i] for i in range(cols))
            attr_stripped = self.util.strip_index(attr)
            attr_idx = int(attr_stripped)

            z_prime = self.group.random(ZR)
            A[attr] = ct['D1'][attr] * (pk['g1_a'] ** sum_val) * (pk['h'][attr_idx] ** -z_prime)
            B[attr] = ct['D2'][attr] * (pk['g2'] ** z_prime)

        return {'policy': ct['policy'], 'V0': V0, 'V1': V1, 'V2': V2, 'V3': V3, 'A': A, 'B': B}

    def decrypt(self, pk, ct_prime, key):
        if debug: print('\nDecryption algorithm:\n')
        nodes = self.util.prune(ct_prime['policy'], key['attr_list'])
        if not nodes:
            return None

        prodGT_alpha = 1
        prodGT_beta = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            
            # SACS requires doubling the pairing operations (for alpha and beta)
            e_A_L = pair(ct_prime['A'][attr], key['L'])
            e_K_B = pair(key['K'][attr_stripped], ct_prime['B'][attr])
            prodGT_alpha *= (e_A_L * e_K_B)
            
            e_A_L_prime = pair(ct_prime['A'][attr], key['L_prime'])
            e_K_B_prime = pair(key['K_prime'][attr_stripped], ct_prime['B'][attr])
            prodGT_beta *= (e_A_L_prime * e_K_B_prime)

        egg_alpha_ss = pair(key['K0'], ct_prime['V3']) / prodGT_alpha
        K = ct_prime['V1'] / egg_alpha_ss

        egg_beta_ss = pair(key['K0_prime'], ct_prime['V3']) / prodGT_beta
        K_prime = ct_prime['V2'] / egg_beta_ss

        msg = ct_prime['V0'] / (K * K_prime)
        return msg