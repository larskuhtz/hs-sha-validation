{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveLift #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskellQuotes #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE ViewPatterns #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- |
-- Module: Test.Hash.Internal
-- Copyright: Copyright © 2022 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
-- Description: Internal Definitions
--
module Test.Hash.Internal
(
-- * Validation Tests for SHA1, SHA2, and SHA3 Hash Algorithms
-- **  Response Files for Selected Long And Short Messages Test for Byte-Oriented Implementations
  MsgFile(..)
, MsgVector(..)
, readMsgFile
, embedMsgFile

-- ** Response Files for Pseudorandomly Generated Messages (Monte Carlo) Tests
, MonteFile(..)
, MonteVector(..)
, readMonteFile
, embedMonteFile

-- * Validation Tests for SHA3-XOFs (Shake) Hash Algorithms
-- **  Response Files for Selected Long And Short Messages Test for Byte-Oriented Implementations
, ShakeMsgFile(..)
, ShakeMsgVector(..)
, readShakeMsgFile
, embedShakeMsgFile

-- ** Response Files for Pseudorandomly Generated Messages (Monte Carlo) Tests
, ShakeMonteFile(..)
, ShakeMonteVector(..)
, readShakeMonteFile
, embedShakeMonteFile

-- ** Response Files for Variable Output Tests for Byte-Oriented Implementations
, ShakeVarOutFile(..)
, ShakeVarOutVector(..)
, readShakeVarOutFile
, embedShakeVarOutFile

-- * Test Tools
, msgTest
, msgAssert
, monteTest
, monteAssert

-- * Internal: Embedding Response Files in Haskell Code
, embedIO

) where

import Control.Applicative
import Control.Monad

import Data.Attoparsec.Text.Lazy
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Internal as B (ByteString(..))
import qualified Data.ByteString.Unsafe as B
import Data.Foldable
import Data.Functor
import qualified Data.List as L
import Data.Maybe
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.IO as TL
import qualified Data.Vector as V

import Language.Haskell.TH
import Language.Haskell.TH.Syntax

import Numeric.Natural

import System.Directory
import System.FilePath
import System.IO.Unsafe

-- -------------------------------------------------------------------------- --
-- Msg File

data MsgFile = MsgFile
    { _msgDescription :: !T.Text
    , _msgL :: !Natural
    , _msgVectors :: !(V.Vector MsgVector)
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

data MsgVector = MsgVector
    { _msgLen :: !Natural
    , _msgMsg :: !B.ByteString
    , _msgMd :: !B.ByteString
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

pMsgFile :: Parser MsgFile
pMsgFile = MsgFile
    <$> pDescription
    <*> (skipSpace *> pL)
    <*> (skipSpace *> pVectors)
    <* (skipSpace *> endOfInput)
    <?> "RspMsgFile"
  where
    pVectors :: Parser (V.Vector MsgVector)
    pVectors = V.fromList
        <$> many1 (skipSpace *> pVector)
        <?> "MsgVectors"

    pVector :: Parser MsgVector
    pVector = MsgVector
        <$> (skipSpace *> pEquals "Len" decimal)
        <*> (skipSpace *> pEquals "Msg" hexbytes)
        <*> (skipSpace *> pEquals "MD" hexbytes)
        <?> "MsgVector"

readMsgFile :: FilePath -> IO MsgFile
readMsgFile = parseFile "readMsgFile" pMsgFile

embedMsgFile :: FilePath -> Code Q MsgFile
embedMsgFile = embedIO . readMsgFile

-- -------------------------------------------------------------------------- --
-- SHA3 Monte File

data MonteFile = MonteFile
    { _monteDescription :: !T.Text
    , _monteL :: !Natural
    , _monteSeed :: !B.ByteString
    , _monteVectors :: !(V.Vector MonteVector)
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

data MonteVector = MonteVector
    { _monteCount :: !Natural
    , _monteMd :: !B.ByteString
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

pMonteFile :: Parser MonteFile
pMonteFile = MonteFile
    <$> pDescription
    <*> (skipSpace *> pL)
    <*> (skipSpace *> pSeed)
    <*> (skipSpace *> pVectors)
    <* (skipSpace *> endOfInput)
    <?> "RspMonteFile"
  where
    pSeed :: Parser B.ByteString
    pSeed = pEquals "Seed" hexbytes <?> "Seed"

    pVectors :: Parser (V.Vector MonteVector)
    pVectors = V.fromList
        <$> many1 (skipSpace *> pVector)
        <?> "MonteVectors"

    pVector :: Parser MonteVector
    pVector = MonteVector
        <$> (skipSpace *> pEquals "COUNT" decimal)
        <*> (skipSpace *> pEquals "MD" hexbytes)
        <?> "MonteVector"

readMonteFile :: FilePath -> IO MonteFile
readMonteFile = parseFile "readMonteFile" pMonteFile

embedMonteFile :: FilePath -> Code Q MonteFile
embedMonteFile = embedIO . readMonteFile

-- -------------------------------------------------------------------------- --
-- Shake Msg File

data ShakeMsgFile = ShakeMsgFile
    { _shakeMsgDescription :: !T.Text
    , _shakeMsgOutputLen:: !Natural
    , _shakeMsgVectors :: !(V.Vector MsgVector)
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

data ShakeMsgVector = ShakeMsgVector
    { _shakeMsgLen :: !Natural
    , _shakeMsgMsg :: !B.ByteString
    , _shakeMsgOutput :: !B.ByteString
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

pShakeMsgFile :: Parser ShakeMsgFile
pShakeMsgFile = ShakeMsgFile
    <$> pDescription
    <*> (skipSpace *> pOutputLength)
    <*> (skipSpace *> pVectors)
    <* (skipSpace *> endOfInput)
    <?> "RspMsgFile"
  where
    pOutputLength :: Parser Natural
    pOutputLength = pInBrackets (pEquals "Outputlen" decimal)
        <?> "Outputlen"

    pVectors :: Parser (V.Vector MsgVector)
    pVectors = V.fromList
        <$> many1 (skipSpace *> pVector)
        <?> "MsgVectors"

    pVector :: Parser MsgVector
    pVector = MsgVector
        <$> (skipSpace *> pEquals "Len" decimal)
        <*> (skipSpace *> pEquals "Msg" hexbytes)
        <*> (skipSpace *> pEquals "Output" hexbytes)
        <?> "MsgVector"

readShakeMsgFile :: FilePath -> IO ShakeMsgFile
readShakeMsgFile = parseFile "readShakeMsgFile" pShakeMsgFile

embedShakeMsgFile :: FilePath -> Code Q ShakeMsgFile
embedShakeMsgFile = embedIO . readShakeMsgFile

-- -------------------------------------------------------------------------- --
-- SHAKE Monte File

data ShakeMonteFile = ShakeMonteFile
    { _shakeMonteDescription :: !T.Text
    , _shakeMonteMinOutputBits :: !Natural
    , _shakeMonteMaxOutputBits :: !Natural
    , _shakeMonteMsg :: !B.ByteString
    , _shakeMonteVectors :: !(V.Vector ShakeMonteVector)
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

data ShakeMonteVector = ShakeMonteVector
    { _shakeMonteCount :: !Natural
    , _shakeMonteOutputLen :: !Natural
    , _shakeMonteOutput :: !B.ByteString
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

pShakeMonteFile :: Parser ShakeMonteFile
pShakeMonteFile = ShakeMonteFile
    <$> pDescription
    <*> (skipSpace *> pMinOutput)
    <*> (skipSpace *> pMaxOutput)
    <*> (skipSpace *> pMsg)
    <*> (skipSpace *> pVectors)
    <* (skipSpace *> endOfInput)
    <?> "RspMonteFile"
  where
    pMinOutput :: Parser Natural
    pMinOutput = pInBrackets (pEquals "Minimum Output Length (bits)" decimal)
        <?> "MinOutput"

    pMaxOutput :: Parser Natural
    pMaxOutput = pInBrackets (pEquals "Maximum Output Length (bits)" decimal)
        <?> "MaxOutput"

    pMsg :: Parser B.ByteString
    pMsg = pEquals "Msg" hexbytes <?> "Msg"

    pVectors :: Parser (V.Vector ShakeMonteVector)
    pVectors = V.fromList
        <$> many1 (skipSpace *> pVector)
        <?> "ShakeMonteVectors"

    pVector :: Parser ShakeMonteVector
    pVector = ShakeMonteVector
        <$> (skipSpace *> pEquals "COUNT" decimal)
        <*> (skipSpace *> pEquals "Outputlen" decimal)
        <*> (skipSpace *> pEquals "Output" hexbytes)
        <?> "ShakeMonteVector"

readShakeMonteFile :: FilePath -> IO ShakeMonteFile
readShakeMonteFile = parseFile "readShakeMonteFile" pShakeMonteFile

embedShakeMonteFile :: FilePath -> Code Q ShakeMonteFile
embedShakeMonteFile = embedIO . readShakeMonteFile

-- -------------------------------------------------------------------------- --
-- SHAKE Variable Out File

data ShakeVarOutFile = ShakeVarOutFile
    { _shakeVarOutDescription :: !T.Text
    , _shakeVarOutInputLength :: !Natural
    , _shakeVarOutMinOutputBits :: !Natural
    , _shakeVarOutMaxOutputBits :: !Natural
    , _shakeVarOutVectors :: !(V.Vector ShakeVarOutVector)
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

data ShakeVarOutVector = ShakeVarOutVector
    { _shakeVarOutCount :: !Natural
    , _shakeVarOutOutputLen :: !Natural
    , _shakeVarOutMsg :: !B.ByteString
    , _shakeVarOutOutput :: !B.ByteString
    }
    deriving (Show, Eq, Ord)
    deriving (Lift)

pShakeVarOutFile :: Parser ShakeVarOutFile
pShakeVarOutFile = ShakeVarOutFile
    <$> pDescription
    <*  (skipSpace *> string "[Tested for Output of byte-oriented messages]")
    <*> (skipSpace *> pInputLength)
    <*> (skipSpace *> pMinOutput)
    <*> (skipSpace *> pMaxOutput)
    <*> (skipSpace *> pVectors)
    <* (skipSpace *> endOfInput)
    <?> "RspVarOutFile"
  where
    pInputLength :: Parser Natural
    pInputLength = pInBrackets (pEquals "Input Length" decimal)
        <?> "InputLength"

    pMinOutput :: Parser Natural
    pMinOutput = pInBrackets (pEquals "Minimum Output Length (bits)" decimal)
        <?> "MinOutput"

    pMaxOutput :: Parser Natural
    pMaxOutput = pInBrackets (pEquals "Maximum Output Length (bits)" decimal)
        <?> "MaxOutput"

    pVectors :: Parser (V.Vector ShakeVarOutVector)
    pVectors = V.fromList
        <$> many1 (skipSpace *> pVector)
        <?> "ShakeVarOutVectors"

    pVector :: Parser ShakeVarOutVector
    pVector = ShakeVarOutVector
        <$> (skipSpace *> pEquals "COUNT" decimal)
        <*> (skipSpace *> pEquals "Outputlen" decimal)
        <*> (skipSpace *> pEquals "Msg" hexbytes)
        <*> (skipSpace *> pEquals "Output" hexbytes)
        <?> "ShakeVarOutVector"

readShakeVarOutFile :: FilePath -> IO ShakeVarOutFile
readShakeVarOutFile = parseFile "readShakeVarOutFile" pShakeVarOutFile

embedShakeVarOutFile :: FilePath -> Code Q ShakeVarOutFile
embedShakeVarOutFile = embedIO . readShakeVarOutFile

-- -------------------------------------------------------------------------- --
-- Common Parsers

pInBrackets :: Parser a -> Parser a
pInBrackets p = char '[' *> p <* char ']' <?> "pInBrackets"

pEquals :: T.Text -> Parser a -> Parser a
pEquals prompt p = string prompt
    *> skipSpace
    *> char '='
    *> skipSpace *> p
    <?> ("pEquals[" <> T.unpack prompt <> "]")

pDescription :: Parser T.Text
pDescription = T.intercalate "\n"
    <$> sepBy descLine endOfLine
    <?> "Description"
  where
    descLine = string "#  " *> takeTill isEndOfLine <?> "Line"

pL :: Parser Natural
pL = pInBrackets (pEquals "L" decimal) <?> "L"

hexbytes :: Parser B.ByteString
hexbytes = go <?> "hexbytes"
  where
    go = do
        h <- takeWhile1 (inClass "0-9a-fA-F")
        -- h <- takeWhile1 (inClass "0123456789abcdefABCDEF")
        -- h <- Data.Attoparsec.Text.Lazy.takeWhile (inClass "0-9a-fA-F")
        case B16.decode (T.encodeUtf8 h) of
            Left e -> fail $ "failed to decode hex-encoded bytes: " <> e
            Right r -> return r

parseFile :: String -> Parser a -> FilePath -> IO a
parseFile label p fp = parseOnly p <$> TL.readFile fp >>= \case
    Right r -> return r
    Left e -> error $ label <> ": failed to parse file " <> fp <> ": " <> e

-- -------------------------------------------------------------------------- --
-- File embedding

embedIO :: Lift a => IO a -> Code Q a
embedIO action = runIO action `bindCode` liftTyped

-- | The returned paths are relative to the given directory
--
listFiles :: String -> FilePath -> IO [FilePath]
listFiles suffix r = listDirectory r
    >>= filterM (doesFileExist . (r </>))
    >>= filterM (fmap readable . getPermissions . (r </>))
    <&> filter (L.isSuffixOf ("." <> suffix))

{-
-- | Running this slice produces @[(FilePath, RspFile)]@.
--
-- It does not recurse into subdirectories and ignores any files that do
-- not have an the suffix @.rsp@.
--
-- The file path is the (relative) file name within the given directory.
--
embedRspFiles :: FilePath -> ExpQ
embedRspFiles fp = SigE
    <$> (runIO (readRspDir fp) >>= lift)
    <*> [t| [(FilePath, RspFile)] |]

readRspDir :: FilePath -> IO [(FilePath, RspFile)]
readRspDir fp = do
    paths <- listRspFiles fp
    forM paths $ \p -> (p,) <$> readRspFile (fp </> p)
-}

-- -------------------------------------------------------------------------- --
-- Orphan Lift instances
--
-- Requires template-haskell >=2.16

#if MIN_VERSION_template_haskell(2,17,0)
code :: m (TExp a) -> Code m a
code = Code
#else
code :: a -> a
code = id
#endif

instance Lift B.ByteString where
    lift bs = return
        $ AppE (VarE 'unsafePerformIO)
        $ AppE
        ( AppE
            (VarE 'B.unsafePackAddressLen)
            (LitE (IntegerL $ fromIntegral $ B8.length bs))
        )
        (LitE (bytesPrimL (mkBytes ptr (fromIntegral off) (fromIntegral sz))))
      where
        B.PS ptr off sz = bs

    liftTyped = code . unsafeTExpCoerce . lift

instance (Lift a) => Lift (V.Vector a) where
    lift v = [| V.fromListN n' v' |]
      where
        n' = V.length v
        v' = V.toList v
    liftTyped = code . unsafeTExpCoerce . lift

-- -------------------------------------------------------------------------- --
-- Test Tools

-- | Check that all test vectors in a File are satisfied by a given hash
-- implementation.
--
msgTest :: (B.ByteString -> B.ByteString) -> MsgFile -> Bool
msgTest hash f = all (\v -> hashVector v == _msgMd v) (toList $ _msgVectors f)
  where
    hashVector v = hash
        $ B.take (fromIntegral (_msgLen v) `quot` 8)
        $ _msgMsg v

-- | For a given hash implementation, assert the correct result for each test
-- vector in a 'MsgFile'.
--
-- The function to assert equality is usually provided by some testing
-- framework.
--
msgAssert
    :: Monad m
    => (String -> B.ByteString -> B.ByteString -> m ())
        -- ^ Function to assertion Equality. The first argument is a test label,
        -- the second argument is the actual value, and the thrid value is the
        -- expected value.
    -> (B.ByteString -> B.ByteString)
        -- ^ Hash function
    -> MsgFile
    -> m ()
msgAssert assert hash f = forM_ vs $ \(i, v) ->
    assert (mkTestLabel i (_msgMsg v)) (hashVector v) (_msgMd v)
  where
    vs = zip [1..] (toList $ _msgVectors f)
    hashVector v = hash
        $ B.take (fromIntegral (_msgLen v) `quot` 8)
        $ _msgMsg v

-- | Check that all test vectors in a Monte Carlo File are satisfied by a given hash
-- implementation.
--
monteTest :: (B.ByteString -> B.ByteString) -> MonteFile -> Bool
monteTest hash f = go (_monteSeed f) (toList $ _monteVectors f)
  where
    go :: B.ByteString -> [MonteVector] -> Bool
    go _ [] = True
    go s ((_monteMd -> h) : t) = hashI 1000 s == h && go h t

    -- Each Round consists of 1000 hash applications
    hashI :: Natural -> B.ByteString -> B.ByteString
    hashI 0 s = s
    hashI i s = let s' = hash s in hashI (i - 1) s'

-- | For a given hash implementation, assert the correct result for each test
-- vector in a 'MonteFile'.
--
-- The function to assert equality is usually provided by some testing
-- framework.
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
monteAssert assert hash f = go (_monteSeed f) (toList $ _monteVectors f)
  where
    go _ [] = return ()
    go s (v : t) = do
        let r = hashI 1000 s
        let md = _monteMd v
        assert (mkTestLabel (_monteCount v) md) md r
        when (r == md) $ go md t

    -- Each Round consists of 1000 hash applications
    hashI :: Natural -> B.ByteString -> B.ByteString
    hashI 0 s = s
    hashI i s = let s' = hash s in hashI (i - 1) s'

mkTestLabel :: Natural -> B.ByteString -> String
mkTestLabel i input = show i <> "[" <> B8.unpack msg <> "]"
    where
    hex = B16.encode input
    msg
        | B.length hex <= 16 = B.take 16 hex
        | otherwise = B.take 13 hex <> "..."

