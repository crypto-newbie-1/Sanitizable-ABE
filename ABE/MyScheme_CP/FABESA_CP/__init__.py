'''
Implementation of the 2024 Inscrypt Paper:
"Efficient Privacy-Preserving Data Sharing Mechanisms Against Malicious Senders in Smart Grid"
Based on FABESA CP-ABE with Sanitization and Outsourcing.
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class Inscrypt24CPABE(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "Inscrypt 2024 Scheme (FABESA-based)"
        self.group = group_obj
        self.util = MSP(self.group, verbose)
   
    def setup(self):
        if debug: print('\nSetup algorithm:\n')
        # Section 5.2 Setup [cite: 188]
        g_1 = self.group.random(G1)
        g_2 = self.group.random(G2)
        g_3 = self.group.random(G1)
        alpha, b_1, b_2 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        
        e_g1g2 = pair(g_1, g_2)
        Y_1 = e_g1g2 ** alpha

        pk = {'g_1': g_1, 'g_2': g_2, 'g_3': g_3, 'g_2^b_1': g_2 ** b_1, 'g_2^b_2': g_2 ** b_2, 'Y_1': Y_1}
        msk = {'a': alpha, 'b_1': b_1, 'b_2': b_2}
        return pk, msk

    def keygen(self, pk, msk, attr_list):  
        if debug: print('\nKeyGen algorithm:\n')
        # Section 5.2 KeyGen [cite: 194]
        r = self.group.random(ZR)

        sk_1 = pk['g_2'] ** r   
        sk_2 = (pk['g_1'] ** msk['a']) * (pk['g_3'] ** (-r)) # sk2 = g1^alpha * g3^-r 
        
        sk_3 = {}
        sk_4 = {}
        mskt_1 = r / msk['b_1']
        mskt_2 = r / msk['b_2']        
        
        for attr in attr_list:
            attr_0 = '0' + attr
            attr_1 = '1' + attr
            attrHash_0 = self.group.hash(attr_0, G1)
            attrHash_1 = self.group.hash(attr_1, G1)
            sk_3[attr] = attrHash_0 ** mskt_1
            sk_4[attr] = attrHash_1 ** mskt_2      
                                                      
        return {'attr_list': attr_list, 'sk_1': sk_1, 'sk_2': sk_2, 'sk_3': sk_3, 'sk_4': sk_4}     

    def keygen_out(self, sk):
        if debug: print('\nKeyGen_out algorithm:\n')
        # Section 5.2 KeyGen_out [cite: 201]
        z = self.group.random(ZR)
        
        tk_sk3 = {}
        tk_sk4 = {}
        for attr in sk['attr_list']:
            tk_sk3[attr] = sk['sk_3'][attr] ** z
            tk_sk4[attr] = sk['sk_4'][attr] ** z
            
        tk = {'attr_list': sk['attr_list'], 'sk_1': sk['sk_1'] ** z, 'sk_2': sk['sk_2'] ** z, 'sk_3': tk_sk3, 'sk_4': tk_sk4}
        dk = z
        return tk, dk

    def encrypt(self, pk, msg, attr_policy):    
        if debug: print('\nEncrypt algorithm:\n')
        # Section 5.2 Encrypt [cite: 206]
        policy = self.util.createPolicy(attr_policy)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        s_1, s_2 = self.group.random(ZR), self.group.random(ZR)
        s = s_1 + s_2
        
        v = [s]
        for i in range(num_cols-1):
            v.append(self.group.random(ZR))
        
        ct_1 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            
            attr_stripped_0 = '0' + attr_stripped
            attr_stripped_1 = '1' + attr_stripped
            attrHash_0 = self.group.hash(attr_stripped_0, G1)
            attrHash_1 = self.group.hash(attr_stripped_1, G1)
            
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            
            # ct_{1,i} = g_3^{P_i * v} * H(0||attr)^{s_1} * H(1||attr)^{s_2} [cite: 208]
            tep = pk['g_3'] ** Mivtop 
            ct_1[attr]  = tep * (attrHash_0 ** s_1) * (attrHash_1 ** s_2) 
        
        ct_2 = pk['g_2'] ** s 
        ct_3 = pk['g_2^b_1'] ** s_1
        ct_4 = pk['g_2^b_2'] ** s_2        
        ct_5 = (pk['Y_1'] ** s) * msg
        
        return {'policy': policy, 'ct_1': ct_1, 'ct_2': ct_2, 'ct_3': ct_3, 'ct_4': ct_4, 'ct_5': ct_5}

    def sanitize(self, pk, ct):
        if debug: print('\nSanitize algorithm:\n')
        # Section 5.2 Sanitize [cite: 211]
        mono_span_prog = self.util.convert_policy_to_msp(ct['policy'])
        num_cols = self.util.len_longest_row

        t_1, t_2 = self.group.random(ZR), self.group.random(ZR)
        t = t_1 + t_2
        
        k = [t]
        for i in range(num_cols-1):
            k.append(self.group.random(ZR))

        ct_prime_1 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash_0 = self.group.hash('0' + attr_stripped, G1)
            attrHash_1 = self.group.hash('1' + attr_stripped, G1)
            
            len_row = len(row)
            Mivtop_k = sum(i[0] * i[1] for i in zip(row, k[:len_row]))
            
            tep = pk['g_3'] ** Mivtop_k
            ct_prime_1[attr] = ct['ct_1'][attr] * tep * (attrHash_0 ** t_1) * (attrHash_1 ** t_2) 
            
        ct_prime_2 = ct['ct_2'] * (pk['g_2'] ** t)
        ct_prime_3 = ct['ct_3'] * (pk['g_2^b_1'] ** t_1)
        ct_prime_4 = ct['ct_4'] * (pk['g_2^b_2'] ** t_2)
        ct_prime_5 = ct['ct_5'] * (pk['Y_1'] ** t) 

        return {'policy': ct['policy'], 'ct_1': ct_prime_1, 'ct_2': ct_prime_2, 'ct_3': ct_prime_3, 'ct_4': ct_prime_4, 'ct_5': ct_prime_5}

    def decrypt_out(self, pk, tk, ct_prime):
        if debug: print('\nDecrypt_out algorithm:\n')
        # Section 5.2 Decrypt_out [cite: 216]
        nodes = self.util.prune(ct_prime['policy'], tk['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return 0
                       
        prod_ct_1 = 1
        prod_sk_3 = 1
        prod_sk_4 = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr) 
                
            prod_ct_1 *= ct_prime['ct_1'][attr]                                                                   
            prod_sk_3 *= tk['sk_3'][attr_stripped]       
            prod_sk_4 *= tk['sk_4'][attr_stripped]                                         
                                                          
        # Execute 4 pairings 
        e1 = pair(prod_ct_1, tk['sk_1'])
        e2 = pair(tk['sk_2'], ct_prime['ct_2'])
        e3 = pair(prod_sk_3, ct_prime['ct_3'])
        e4 = pair(prod_sk_4, ct_prime['ct_4'])           
                                                                       
        PC = (e3 * e4) / (e1 * e2)
        return {'ct_5': ct_prime['ct_5'], 'PC': PC} 
        
    def decrypt_user(self, pk, dk, DC):
        if debug: print('\nDecrypt_user algorithm:\n')
        # Section 5.2 Decrypt [cite: 220]
        if DC == 0:
            return 0
        z_inv = 1 / dk
        # Mathematical derivation shows PC evaluates to Y_1^{-z(s+t)}, so we multiply [cite: 221]
        M = DC['ct_5'] * (DC['PC'] ** z_inv) 
        return M