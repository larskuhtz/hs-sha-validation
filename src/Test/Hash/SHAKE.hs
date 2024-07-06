{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

-- |
-- Module: Test.Hash.SHAKE
-- Copyright: Copyright © 2022-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
-- Description: SHA-3 XOF Test Vectors for Byte-Oriented Output
--
-- https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
--
-- Details can be found here:
--
-- https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
--
-- Response files are available here:
--
-- https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip
--
module Test.Hash.SHAKE
(
-- * Selected Short Messages Test for Byte-Oriented Implementations
  ShakeMsgFile(..)
, ShakeMsgVector(..)
, shake128ShortMsg
, shake256ShortMsg

-- * Selected Long Messages Test for Byte-Oriented Implementations
, shake128LongMsg
, shake256LongMsg

-- * Pseudorandomly Generated Messages (Monte Carlo) Tests
, ShakeMonteFile(..)
, ShakeMonteVector(..)
, shake128Monte
, shake256Monte

-- *  Variable Output Tests for Byte-Oriented Implementations
, ShakeVarOutFile(..)
, ShakeVarOutVector(..)
, shake128VarOut
, shake256VarOut
) where

-- internal modules

import Test.Hash.Internal


-- -------------------------------------------------------------------------- --
--

-- | SHAKE128LongMsg.rsp
--
shake128LongMsg :: ShakeMsgFile
shake128LongMsg = $$(embedShakeMsgFile "data/shakebytetestvectors/SHAKE128LongMsg.rsp")

-- | SHAKE256LongMsg.rsp
--
shake256LongMsg :: ShakeMsgFile
shake256LongMsg = $$(embedShakeMsgFile "data/shakebytetestvectors/SHAKE128LongMsg.rsp")

-- -------------------------------------------------------------------------- --
--

-- | SHAKE128ShortMsg.rsp
--
shake128ShortMsg :: ShakeMsgFile
shake128ShortMsg = $$(embedShakeMsgFile "data/shakebytetestvectors/SHAKE128ShortMsg.rsp")

-- | SHAKE256ShortMsg.rsp
--
shake256ShortMsg :: ShakeMsgFile
shake256ShortMsg = $$(embedShakeMsgFile "data/shakebytetestvectors/SHAKE128ShortMsg.rsp")

-- -------------------------------------------------------------------------- --
--

-- | SHAKE128Monte.rsp
--
shake128Monte :: ShakeMonteFile
shake128Monte = $$(embedShakeMonteFile "data/shakebytetestvectors/SHAKE128Monte.rsp")

-- | SHAKE256Monte.rsp
--
shake256Monte :: ShakeMonteFile
shake256Monte = $$(embedShakeMonteFile "data/shakebytetestvectors/SHAKE128Monte.rsp")

-- -------------------------------------------------------------------------- --
--

-- | SHAKE128VarOut.rsp
--
shake128VarOut :: ShakeVarOutFile
shake128VarOut = $$(embedShakeVarOutFile "data/shakebytetestvectors/SHAKE128VariableOut.rsp")

-- | SHAKE256VarOut.rsp
--
shake256VarOut :: ShakeVarOutFile
shake256VarOut = $$(embedShakeVarOutFile "data/shakebytetestvectors/SHAKE256VariableOut.rsp")

