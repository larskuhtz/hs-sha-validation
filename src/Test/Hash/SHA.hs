{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

-- |
-- Module: Test.Hash.SHA
-- Copyright: Copyright © 2022-2024 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
-- Description: SHA Test Vectors for Hashing Byte-Oriented Messages
--
-- https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
--
-- Details can be found here:
--
-- https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf.
--
-- Response files are available here:
--
-- https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
--
module Test.Hash.SHA
(
-- ** Selected Long Messages Test for Byte-Oriented Implementations
  MsgFile(..)
, MsgVector(..)
, sha1LongMsg
, sha224LongMsg
, sha256LongMsg
, sha384LongMsg
, sha512LongMsg
, sha512_224LongMsg
, sha512_256LongMsg

-- ** Selected Short Messages Test for Byte-Oriented Implementations
, sha1ShortMsg
, sha224ShortMsg
, sha256ShortMsg
, sha384ShortMsg
, sha512ShortMsg
, sha512_224ShortMsg
, sha512_256ShortMsg

-- ** The Pseudorandomly Generated Messages (Monte Carlo) Tests
, MonteFile(..)
, MonteVector(..)
, sha1Monte
, sha224Monte
, sha256Monte
, sha384Monte
, sha512Monte
, sha512_224Monte
, sha512_256Monte

-- * Test Utils
, msgTest
, msgAssert
, monteTest
, monteAssert
) where

import Data.ByteString qualified as B

-- internal modules

import Test.Hash.Internal

-- -------------------------------------------------------------------------- --
-- Tools

-- | Test a given SHA1 or SHA2 implementation for the test vectors in a monte
-- file. See 'monteAssert' for details.
--
monteTest :: (B.ByteString -> B.ByteString) -> MonteFile -> Bool
monteTest = monteTestInternal 3

-- | For a given SHA1 or SHA2 implementation, assert the correct result for each
-- test vector in a 'MonteFile'.
--
-- The function to assert equality is usually provided by some testing
-- framework.
--
-- NOTE that the test algorithms for SHA (SHA1 and SHA2) and SHA3 are different.
--
-- The test algorithm is describe in cf. https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf.
-- The pseudo code is as follows:
--
-- @
-- INPUT: Seed - A random seed n bits long
-- {
--     for (j=0; j<100; j++) {
--         MD0 = MD1 = MD2 = Seed;
--         for (i=3; i<1003; i++) {
--             Mi = MDi-3 || MDi-2 || MDi-1;
--             MDi = SHA(Mi);
--         }
--         MDj = Seed = MD1002;
--         OUTPUT: MDj
--     }
-- }
-- @
--
monteAssert
    :: Monad m
    => (String -> B.ByteString -> B.ByteString -> m ())
        -- ^ Function to assertion Equality. The first argument is a test label,
        -- the second argument is the actual value, and the thrid value is the
        -- expected value.
    -> (B.ByteString -> B.ByteString)
        -- ^ Hash function
    -> MonteFile
    -> m ()
monteAssert = monteAssertInternal 3

-- -------------------------------------------------------------------------- --
--

-- | SHA1LongMsg.rsp
--
sha1LongMsg :: MsgFile
sha1LongMsg = $$(embedMsgFile "data/shabytetestvectors/SHA1LongMsg.rsp")

-- | SHA224LongMsg.rsp
--
sha224LongMsg :: MsgFile
sha224LongMsg = $$(embedMsgFile "data/shabytetestvectors/SHA224LongMsg.rsp")

-- | SHA256LongMsg.rsp
--
sha256LongMsg :: MsgFile
sha256LongMsg = $$(embedMsgFile "data/shabytetestvectors/SHA256LongMsg.rsp")

-- | SHA384LongMsg.rsp
--
sha384LongMsg :: MsgFile
sha384LongMsg = $$(embedMsgFile "data/shabytetestvectors/SHA384LongMsg.rsp")

-- | SHA512LongMsg.rsp
--
sha512LongMsg :: MsgFile
sha512LongMsg = $$(embedMsgFile "data/shabytetestvectors/SHA512LongMsg.rsp")

-- | SHA512_224LongMsg.rsp
--
sha512_224LongMsg :: MsgFile
sha512_224LongMsg = $$(embedMsgFile "data/shabytetestvectors/SHA512_224LongMsg.rsp")

-- | SHA512_256LongMsg.rsp
--
sha512_256LongMsg :: MsgFile
sha512_256LongMsg = $$(embedMsgFile "data/shabytetestvectors/SHA512_256LongMsg.rsp")

-- -------------------------------------------------------------------------- --
--

-- | SHA1ShortMsg.rsp
--
sha1ShortMsg :: MsgFile
sha1ShortMsg = $$(embedMsgFile "data/shabytetestvectors/SHA1ShortMsg.rsp")

-- | SHA224ShortMsg.rsp
--
sha224ShortMsg :: MsgFile
sha224ShortMsg = $$(embedMsgFile "data/shabytetestvectors/SHA224ShortMsg.rsp")

-- | SHA256ShortMsg.rsp
--
sha256ShortMsg :: MsgFile
sha256ShortMsg = $$(embedMsgFile "data/shabytetestvectors/SHA256ShortMsg.rsp")

-- | SHA384ShortMsg.rsp
--
sha384ShortMsg :: MsgFile
sha384ShortMsg = $$(embedMsgFile "data/shabytetestvectors/SHA384ShortMsg.rsp")

-- | SHA512ShortMsg.rsp
--
sha512ShortMsg :: MsgFile
sha512ShortMsg = $$(embedMsgFile "data/shabytetestvectors/SHA512ShortMsg.rsp")

-- | SHA512_224ShortMsg.rsp
--
sha512_224ShortMsg :: MsgFile
sha512_224ShortMsg = $$(embedMsgFile "data/shabytetestvectors/SHA512_224ShortMsg.rsp")

-- | SHA512_256ShortMsg.rsp
--
sha512_256ShortMsg :: MsgFile
sha512_256ShortMsg = $$(embedMsgFile "data/shabytetestvectors/SHA512_256ShortMsg.rsp")

-- -------------------------------------------------------------------------- --
--

-- | SHA1Monte.rsp
--
sha1Monte :: MonteFile
sha1Monte = $$(embedMonteFile "data/shabytetestvectors/SHA1Monte.rsp")

-- | SHA224Monte.rsp
--
sha224Monte :: MonteFile
sha224Monte = $$(embedMonteFile "data/shabytetestvectors/SHA224Monte.rsp")

-- | SHA256Monte.rsp
--
sha256Monte :: MonteFile
sha256Monte = $$(embedMonteFile "data/shabytetestvectors/SHA256Monte.rsp")

-- | SHA384Monte.rsp
--
sha384Monte :: MonteFile
sha384Monte = $$(embedMonteFile "data/shabytetestvectors/SHA384Monte.rsp")

-- | SHA512Monte.rsp
--
sha512Monte :: MonteFile
sha512Monte = $$(embedMonteFile "data/shabytetestvectors/SHA512Monte.rsp")

-- | SHA512_224Monte.rsp
--
sha512_224Monte :: MonteFile
sha512_224Monte = $$(embedMonteFile "data/shabytetestvectors/SHA512_224Monte.rsp")

-- | SHA512_256Monte.rsp
--
sha512_256Monte :: MonteFile
sha512_256Monte = $$(embedMonteFile "data/shabytetestvectors/SHA512_256Monte.rsp")

