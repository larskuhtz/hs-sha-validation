{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

-- |
-- Module: Test.Hash.SHA3
-- Copyright: Copyright © 2022 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
-- Description: SHA-3 Hash Function Tests for Hashing Byte-Oriented Messages
--
-- https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
--
-- Details can be found here:
--
-- https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
--
-- Response files are available here:
--
-- https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
--
module Test.Hash.SHA3
(
-- *  Selected Long Messages Test for Byte-Oriented Implementations
  MsgFile(..)
, MsgVector(..)
, sha3_224LongMsg
, sha3_256LongMsg
, sha3_384LongMsg
, sha3_512LongMsg

-- *  Selected Short Messages Test for Byte-Oriented Implementations
, sha3_224ShortMsg
, sha3_256ShortMsg
, sha3_384ShortMsg
, sha3_512ShortMsg

-- * The Pseudorandomly Generated Messages (Monte Carlo) Tests
, MonteFile(..)
, MonteVector(..)
, sha3_224Monte
, sha3_256Monte
, sha3_384Monte
, sha3_512Monte

-- * Test Utils
, msgTest
, msgAssert
, monteTest
, monteAssert
) where

-- internal modules

import Test.Hash.Internal

-- -------------------------------------------------------------------------- --
-- Long Selected Message SHA-3 Hash Function Tests for Hashing Byte-Oriented Messages

-- | SHA3_224LongMsg.rsp
--
sha3_224LongMsg :: MsgFile
sha3_224LongMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_224LongMsg.rsp")

-- | SHA3_256LongMsg.rsp
--
sha3_256LongMsg :: MsgFile
sha3_256LongMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_256LongMsg.rsp")

-- | SHA3_384LongMsg.rsp
--
sha3_384LongMsg :: MsgFile
sha3_384LongMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_384LongMsg.rsp")

-- | SHA3_512LongMsg.rsp
--
sha3_512LongMsg :: MsgFile
sha3_512LongMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_512LongMsg.rsp")

-- -------------------------------------------------------------------------- --
-- Long Selected Message SHA-3 Hash Function Tests for Hashing Byte-Oriented Messages

-- | SHA3_224ShortMsg.rsp
--
sha3_224ShortMsg :: MsgFile
sha3_224ShortMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_224ShortMsg.rsp")

-- | SHA3_256ShortMsg.rsp
--
sha3_256ShortMsg :: MsgFile
sha3_256ShortMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_256ShortMsg.rsp")

-- | SHA3_384ShortMsg.rsp
--
sha3_384ShortMsg :: MsgFile
sha3_384ShortMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_384ShortMsg.rsp")

-- | SHA3_512ShortMsg.rsp
--
sha3_512ShortMsg :: MsgFile
sha3_512ShortMsg = $$(embedMsgFile "data/sha-3bytetestvectors/SHA3_512ShortMsg.rsp")

-- -------------------------------------------------------------------------- --
-- | Monte Carlo SHA-3 Hash Function Tests for Hashing Byte-Oriented Messages

-- | SHA3_224Monte.rsp
--
sha3_224Monte :: MonteFile
sha3_224Monte = $$(embedMonteFile "data/sha-3bytetestvectors/SHA3_224Monte.rsp")

-- | SHA3_256Monte.rsp
--
sha3_256Monte :: MonteFile
sha3_256Monte = $$(embedMonteFile "data/sha-3bytetestvectors/SHA3_256Monte.rsp")

-- | SHA3_384Monte.rsp
--
sha3_384Monte :: MonteFile
sha3_384Monte = $$(embedMonteFile "data/sha-3bytetestvectors/SHA3_384Monte.rsp")

-- | SHA3_512Monte.rsp
--
sha3_512Monte :: MonteFile
sha3_512Monte = $$(embedMonteFile "data/sha-3bytetestvectors/SHA3_512Monte.rsp")

