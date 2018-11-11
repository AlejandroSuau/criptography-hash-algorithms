#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

#from T2018_Practica1_Solution_Skeleton import *
from hash_functions import *


class HashBasedOnBlockSystem(unittest.TestCase):

    def test_basic_hash_based_on_blocksystem_1(self):
        block_len = 4
        m = "01011000"
        initial_vector = "0111"
        hash_result = "1010"
        self.assertEqual(hash_based_on_blocksystem(block_len, m, initial_vector), hash_result)
        
        
    def test_basic_hash_based_on_blocksystem_2(self):
        # Calculate hash function based on blocksystem
        block_len = 4
        m = "00000100"
        initial_vector = "1011"
        hash_result = "0000"
        self.assertEqual(hash_based_on_blocksystem(block_len, m, initial_vector), hash_result)
        
    def test_basic_hash_based_on_blocksystem_3(self):
        # Calculate hash function based on blocksystem
        block_len = 4
        m = "01101001"
        initial_vector = "1111"
        hash_result = "1111"
        self.assertEqual(hash_based_on_blocksystem(block_len, m, initial_vector), hash_result)
    
class SHA256BlockExpansion(unittest.TestCase):
    
    def test_basic_SHA256_block_expansion_sigma_0_1(self):
        # Calculate sigma_0 from block expansion process SHA256
        a ="0xffffff0f"
        sigma_0_result = "0xffc3ffe0"
        self.assertEqual(SHA256_block_expansion_sigma_0(a), sigma_0_result)
        
    def test_basic_SHA256_block_expansion_sigma_0_2(self):
        # Calculate sigma_0 from block expansion process SHA256
        a ="0xf00ff000"
        sigma_0_result = "0xe3e1dde3"
        self.assertEqual(SHA256_block_expansion_sigma_0(a), sigma_0_result)
            
    def test_basic_SHA256_block_expansion_sigma_1_1(self):
        # Calculate sigma_1 from block expansion process SHA256
        a ="0xff00000f"
        sigma_1_result = "0x0039c060"
        self.assertEqual(SHA256_block_expansion_sigma_1(a), sigma_1_result)
    
    def test_basic_SHA256_block_expansion_sigma_1_2(self):
        # Calculate sigma_1 from block expansion process SHA256
        a ="0xf0fff00f"
        sigma_1_result = "0x063a399c"
        self.assertEqual(SHA256_block_expansion_sigma_1(a), sigma_1_result)
    
    def test_basic_SHA256_block_expansion_sigma_1_3(self):
        # Calculate sigma_1 from block expansion process SHA256
        a ="0xf0f0000f"
        sigma_1_result = "0x003a3a66"
        self.assertEqual(SHA256_block_expansion_sigma_1(a), sigma_1_result)
    
class SHA256CompressionFunction(unittest.TestCase):
    
    def test_basic_SHA256_compression_function_sigma_0_1(self):
        # Calculate sigma_0 from compression function
        a ="0xfff0ffff"
        sigma_0_result = "0xc3fc3f87"
        self.assertEqual(SHA256_compression_function_sigma_0(a), sigma_0_result)
        
    def test_basic_SHA256_compression_function_sigma_0_2(self):
        # Calculate sigma_0 from compression function
        a = "0xf00fffff"
        sigma_0_result = "0x3c038040"
        self.assertEqual(SHA256_compression_function_sigma_0(a), sigma_0_result)
    
    def test_basic_SHA256_compression_function_sigma_0_3(self):
        # Calculate sigma_0 from compression function
        a = "0xf0f00f0f"
        sigma_0_result = "0x447fbb80"
        self.assertEqual(SHA256_compression_function_sigma_0(a), sigma_0_result)
    
    def test_basic_SHA256_compression_function_sigma_0_4(self):
        # Calculate sigma_0 from compression function
        a = "0xf000f0ff"
        sigma_0_result = "0x783c43f8"
        self.assertEqual(SHA256_compression_function_sigma_0(a), sigma_0_result)
        
    def test_basic_SHA256_compression_function_sigma_1_1(self):
        # Calculate sigma_1 from compression function
        a ="0xf0ff0000"
        sigma_1_result = "0x7c5de398"
        self.assertEqual(SHA256_compression_function_sigma_1(a), sigma_1_result)
        
    def test_basic_SHA256_compression_function_sigma_1_2(self):
        # Calculate sigma_1 from compression function
        a ="0xf0ff00ff"
        sigma_1_result = "0x9fbd9c1b"
        self.assertEqual(SHA256_compression_function_sigma_1(a), sigma_1_result)
    
    def test_basic_SHA256_compression_function_sigma_1_3(self):
        # Calculate sigma_1 from compression function
        a ="0xff0ff0f0"
        sigma_1_result = "0x5a1ba642"
        self.assertEqual(SHA256_compression_function_sigma_1(a), sigma_1_result)
    
    def test_basic_SHA256_compression_function_sigma_1_3(self):
        # Calculate sigma_1 from compression function
        a ="0xff0fffff"
        sigma_1_result = "0x87fc21ff"
        self.assertEqual(SHA256_compression_function_sigma_1(a), sigma_1_result)
    
    def test_basic_SHA256_compression_function_Maj_1(self):
        # Calculate Maj from compression function
        a = "0xffffff00"
        b = "0xf0000f0f"
        c = "0xfff0f0f0"
        Maj_result = "0xfff0ff00"
        self.assertEqual(SHA256_compression_function_Maj(a, b, c), Maj_result)
        
    def test_basic_SHA256_compression_function_Maj_2(self):
        # Calculate Maj from compression function
        a = "0xff0f0f0f"
        b = "0xfff0ff0f"
        c = "0xf0f00ff0"
        Maj_result = "0xfff00f0f"
        self.assertEqual(SHA256_compression_function_Maj(a, b, c), Maj_result)
        
    def test_basic_SHA256_compression_function_Maj_3(self):
        # Calculate Maj from compression function
        a = "0xffffff0f"
        b = "0xf000f000"
        c = "0xf000f0f0"
        Maj_result = "0xf000f000"
        self.assertEqual(SHA256_compression_function_Maj(a, b, c), Maj_result)
    
    def test_basic_SHA256_compression_function_Ch_1(self):
        # Calculate Ch from compression function
        a = "0xf0000f0f"
        b = "0xf0f00f0f"
        c = "0xf00f00f0"
        Ch_result = "0xf00f0fff"
        self.assertEqual(SHA256_compression_function_Ch(a, b, c), Ch_result)
    
    def test_basic_SHA256_compression_function_Ch_2(self):
        # Calculate Ch from compression function
        a = "0xfff0f0f0"
        b = "0xf00000f0"
        c = "0xf0ffffff"
        Ch_result = "0xf00f0fff"
        self.assertEqual(SHA256_compression_function_Ch(a, b, c), Ch_result)
    
    def test_basic_SHA256_compression_function_Ch_3(self):
        # Calculate Ch from compression function
        a = "0xfffff000"
        b = "0xf00000f0"
        c = "0xf0ff00f0"
        Ch_result = "0xf00000f0"
        self.assertEqual(SHA256_compression_function_Ch(a, b, c), Ch_result)
    
if __name__ == '__main__':

    # create a suite with all tests
    test_classes_to_run = [HashBasedOnBlockSystem, SHA256BlockExpansion, SHA256CompressionFunction]
    loader = unittest.TestLoader()
    suites_list = []
    for test_class in test_classes_to_run:
        suite = loader.loadTestsFromTestCase(test_class)
        suites_list.append(suite)

    all_tests_suite = unittest.TestSuite(suites_list)

    # run the test suite with high verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    results = runner.run(all_tests_suite)
