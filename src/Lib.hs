module Lib
    (getRarArchive
    ) where

-- import qualified Codec.Archive.Zip as Z
import qualified Data.ByteString.Lazy as B
import Data.Binary
import Data.Binary.Get
import Data.Bits ((.&.))
import System.FilePath
import Control.Monad.Loops (whileM)
import Data.Maybe (catMaybes)
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TL
import Debug.Trace
import Numeric (showHex)

prettyPrint :: B.ByteString -> String
prettyPrint = concat . map (flip showHex "") . B.unpack

-- http://www.forensicswiki.org/w/images/5/5b/RARFileStructure.txt

data RarArchive = RarArchive
  { rarEntries :: [RarEntry]
  , rarComment :: B.ByteString
  } deriving (Show)

data RarEntry = RarEntry
  { entrySize :: Word32
  , entryPackedSize :: Word32
  , entryPath :: FilePath
  , entryTimestamp :: Int
  , entryOS :: HostOS
  , entryCRC32 :: Word32
  , entryPackMethod :: PackMethod
  , entryComment :: B.ByteString
  , entryAttributes :: Word32
  , entryPackedData :: B.ByteString
  }

instance Show RarEntry where
  show e = "RarEntry { "
        ++ "size = " ++ (show $ entrySize e) ++ ", "
        ++ "packedSize = " ++ (show $ entryPackedSize e) ++ ", "
        ++ "path = " ++ (show $ entryPath e) ++ ", "
        ++ "timestamp = " ++ (show $ entryTimestamp e) ++ ", "
        ++ "OS = " ++ (show $ entryOS e) ++ ", "
        ++ "CRC32 = " ++ (show $ entryCRC32 e) ++ ", "
        ++ "packMethod = " ++ (show $ entryPackMethod e) ++ ", "
        ++ "comment = " ++ (show $ entryComment e) ++ ", "
        ++ "attributes = " ++ (show $ entryAttributes e) ++ " }"

data HostOS = MS_DOS
            | OS_2
            | Windows
            | Unix
            | Mac_OS
            | BeOS
            deriving (Eq, Show)

data PackMethod = Stored
                | FastestCompression
                | FastCompression
                | NormalCompression
                | GoodCompression
                | BestCompression
                deriving (Eq, Show)

markerBlock :: B.ByteString
markerBlock = B.pack [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]

getRarArchive :: Get RarArchive
getRarArchive = do
  signature <- getLazyByteString 7
  if signature /= markerBlock
  then fail "bad signature"
  else return ()

  headCrc <- getWord16le -- TODO verify

  headType <- getWord8
  if headType /= 0x73
  then fail "not head type!"
  else return ()

  headFlags <- getWord16le

  headSize <- getWord16le
  traceM $ "headsize: " ++ (show headSize)
  skip 6 -- reserved bytes

  traceM $ "commentsize: " ++ (show (fromIntegral (headSize - 13)))
  -- rest of header is the comment
  comment <- getLazyByteString $ fromIntegral (headSize - 13)

  traceM $ "comment: " ++ (prettyPrint comment)

  maybeEntries <- whileM (not <$> isEmpty) $ label "reading entry" $ do
    entryCrc <- getWord16le -- TODO verify
    entryType <- getWord8
    entryFlags <- getWord16le
    entrySize <- getWord16le
    case entryType of
      0x74      -> Just <$> getRarEntry entryFlags entrySize
      otherwise ->
        if (entryFlags .&. 0x8000) /= 0
        then label ("skipping entry " ++ (show entryType)) $ do
          addSize <- getWord32le
          skip $ ((fromIntegral entrySize) + (fromIntegral addSize) - 7)
          return Nothing
        else do
          skip $ fromIntegral (entrySize - 7) -- already read 7 bytes
          return Nothing

  let entries = catMaybes maybeEntries

  return $ RarArchive entries comment

getRarEntry :: Word16 -> Word16 -> Get RarEntry
getRarEntry headFlags headSize = do
  packedSize <- getWord32le
  unpackedSize <- getWord32le
  hostOs <- getWord8 >>= \b -> case b of
    0x00 -> return MS_DOS
    0x01 -> return OS_2
    0x02 -> return Windows
    0x03 -> return Unix
    0x04 -> return Mac_OS
    0x05 -> return BeOS
    otherwise -> fail $ "unrecognized os" ++ (show b) -- probably should Maybe instead

  fileCrc <- getWord32le
  ftime <- parseMsDosTime <$> getWord32le

  skip 1 -- rar version needed to extract file, don't care here

  packingMethod <- getWord8 >>= \b -> case b of
    0x30 -> return Stored
    0x31 -> return FastestCompression
    0x32 -> return FastCompression
    0x33 -> return NormalCompression
    0x34 -> return GoodCompression
    0x35 -> return BestCompression
    otherwise -> fail $ "unrecognized packing" ++ (show b)

  nameSize <- getWord16le
  attributes <- getWord32le

  -- TODO support high pack
  -- highPackSize <- if (headFlags .&. 0x100) /= 0
  --   then getWord32le
  --   else return 0
  -- highUnpackedSize <- if (headFlags .&. 0x100) /= 0
  --   then getWord32le
  --   else return 0

  -- assume UTF-8, TODO handle flag
  fileName <- (TL.unpack . TL.decodeUtf8) <$>
     getLazyByteString (fromIntegral nameSize)

  -- TODO support salt present, changes comment offset
  -- if (headFlags .&. 0x0400) /= 0 -- salt
  -- then skip 8
  -- else return ()

  -- TODO xtime, apparently undocumented in forensicswiki
  -- extendedTime <- if (headFlags .&. 0x1000) /= 0
  --   then getWord32le -- variable size?
  --   else return 0

  -- read up to start of packedData
  comment <- getLazyByteString $ fromIntegral (headSize - 32 - nameSize)

  packedData <- getLazyByteString $ fromIntegral packedSize

  return $ RarEntry
    { entrySize = unpackedSize
    , entryPackedSize = packedSize
    , entryPath = fileName
    , entryTimestamp = ftime
    , entryOS = hostOs
    , entryCRC32 = fileCrc
    , entryPackMethod = packingMethod
    , entryComment = comment
    , entryAttributes = attributes
    , entryPackedData = packedData
    }

parseMsDosTime :: Word32 -> Int
parseMsDosTime = fromIntegral -- TODO
