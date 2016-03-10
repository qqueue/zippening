{-# LANGUAGE DeriveGeneric #-}

module Lib
    ( getRarArchive
    , RarArchive (..)
    , RarEntry (..)
    , RarMetadata (..)
    , ExtTime (..)
    , HostOS (..)
    , PackMethod (..)
    ) where

-- import qualified Codec.Archive.Zip as Z
import           Control.Monad           (when)
import           Control.Monad.Loops     (whileM)
import           Data.Aeson
import           Data.Binary
import           Data.Binary.Get
import           Data.Bits               (shiftL, shiftR, (.&.))
import qualified Data.ByteString.Lazy    as B
import           Data.Maybe              (catMaybes)
import qualified Data.Text.Lazy          as TL
import qualified Data.Text.Lazy.Encoding as TL
import           Data.Time.Calendar      (fromGregorian)
import           Data.Time.Clock         (UTCTime (..))
import           Debug.Trace
import           GHC.Generics
import           Numeric                 (showHex)
import           System.FilePath

prettyPrint :: B.ByteString -> String
prettyPrint = concatMap (`showHex` "") . B.unpack

-- http://www.forensicswiki.org/w/images/5/5b/RARFileStructure.txt

data RarArchive = RarArchive
  { rarEntries :: [RarEntry]
  , rarComment :: B.ByteString
  }

data RarEntry = RarEntry
  { entryMetadata   :: RarMetadata
  , entryPackedData :: B.ByteString
  }

newtype RarComment = RarComment { getComment :: B.ByteString }

instance ToJSON RarComment where
  toJSON comment = toJSON $ prettyPrint $ getComment comment

data RarMetadata = RarMetadata
  { entrySize         :: Word32
  , entryPackedSize   :: Word32
  , entryPath         :: FilePath
  , entryTimestamp    :: UTCTime
  , entryExtendedTime :: ExtTime
  , entryOS           :: HostOS
  , entryCRC32        :: Word32
  , entryPackMethod   :: PackMethod
  , entryComment      :: RarComment
  , entryAttributes   :: Word32
  } deriving (Generic)

instance ToJSON RarMetadata

data ExtTime = ExtTime
  { extMtime   :: Maybe Int
  , extCtime   :: Maybe Int
  , extAtime   :: Maybe Int
  , extArctime :: Maybe Int
  } deriving (Generic, Eq, Show)

instance ToJSON ExtTime

emptyExtTime :: ExtTime
emptyExtTime = ExtTime Nothing Nothing Nothing Nothing

data HostOS = MS_DOS
            | OS_2
            | Windows
            | Unix
            | MacOS
            | BeOS
            deriving (Generic, Eq, Show)

instance ToJSON HostOS

data PackMethod = Stored
                | FastestCompression
                | FastCompression
                | NormalCompression
                | GoodCompression
                | BestCompression
                deriving (Generic, Eq, Show)

instance ToJSON PackMethod

markerBlock :: B.ByteString
markerBlock = B.pack [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]

getRarArchive :: Get RarArchive
getRarArchive = do
  signature <- getLazyByteString 7
  when (signature /= markerBlock) $ fail "bad signature"

  headCrc <- getWord16le -- TODO verify

  headType <- getWord8
  when (headType /= 0x73) $ fail "not head type!"

  headFlags <- getWord16le

  headSize <- getWord16le
  -- traceM $ "headsize: " ++ (show headSize)
  skip 6 -- reserved bytes

  -- traceM $ "commentsize: " ++ (show (fromIntegral (headSize - 13)))
  -- rest of header is the comment
  comment <- getLazyByteString $ fromIntegral (headSize - 13)

  -- traceM $ "comment: " ++ (prettyPrint comment)

  maybeEntries <- whileM (not <$> isEmpty) $ label "reading entry" $ do
    entryCrc <- getWord16le -- TODO verify
    entryType <- getWord8
    entryFlags <- getWord16le
    entrySize <- getWord16le
    case entryType of
      0x74      -> Just <$> getRarEntry entryFlags entrySize
      otherwise ->
        if (entryFlags .&. 0x8000) /= 0
        then label ("skipping entry " ++ show entryType) $ do
          addSize <- getWord32le
          skip $ fromIntegral entrySize + fromIntegral addSize - 7
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
    0x04 -> return MacOS
    0x05 -> return BeOS
    otherwise -> fail $ "unrecognized os" ++ show b -- probably should Maybe instead

  fileCrc <- getWord32le
  ftime <- parseMsDosTime <$> getWord16le <*> getWord16le

  skip 1 -- rar version needed to extract file, don't care here

  packingMethod <- getWord8 >>= \b -> case b of
    0x30 -> return Stored
    0x31 -> return FastestCompression
    0x32 -> return FastCompression
    0x33 -> return NormalCompression
    0x34 -> return GoodCompression
    0x35 -> return BestCompression
    otherwise -> fail $ "unrecognized packing" ++ show b

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

  let extendedTimePresent = (headFlags .&. 0x1000) /= 0
  pos <- bytesRead
  extendedTime <- if extendedTimePresent
    then getExtendedTime
    else return emptyExtTime
  newPos <- bytesRead
  let xtimeReadBytes = fromIntegral (newPos - pos)

  -- read up to start of packedData
  comment <- getLazyByteString $
    fromIntegral headSize - 32 - fromIntegral nameSize - xtimeReadBytes

  packedData <- getLazyByteString $ fromIntegral packedSize

  return RarEntry
    { entryMetadata = RarMetadata
      { entrySize = unpackedSize
      , entryPackedSize = packedSize
      , entryPath = fileName
      , entryTimestamp = ftime
      , entryExtendedTime = extendedTime
      , entryOS = hostOs
      , entryCRC32 = fileCrc
      , entryPackMethod = packingMethod
      , entryComment = RarComment comment
      , entryAttributes = attributes
      }
    , entryPackedData = packedData
    }

getExtendedTime :: Get ExtTime
getExtendedTime = do
  flags <- getWord16le

  -- traceM $ "extflags: " ++ (show $ (flags `shiftR` 12) .&. 0x3)
  mtime <- if ((flags `shiftR` 12) .&. 8) /= 0
    then getVarInt $ (flags `shiftR` 12) .&. 0x3
    else return Nothing
  -- traceM $ "mtime: " ++ (show mtime)
  ctime <- if ((flags `shiftR` 8) .&. 8) /= 0
    then getVarInt $ (flags `shiftR` 8) .&. 0x3
    else return Nothing
  atime <- if ((flags `shiftR` 4) .&. 8) /= 0
    then getVarInt $ (flags `shiftR` 4) .&. 0x3
    else return Nothing
  arctime <- if ((flags `shiftR` 0) .&. 8) /= 0
    then getVarInt $ (flags `shiftR` 0) .&. 0x3
    else return Nothing
  return $ ExtTime mtime ctime atime arctime

getVarInt :: Word16 -> Get (Maybe Int)
getVarInt 1 = Just . fromIntegral <$> getWord8
getVarInt 2 = Just . fromIntegral <$> getWord16le
getVarInt 3 = Just . fromIntegral <$> getWord24le
getVarInt 0 = return Nothing -- apparently 0 can be present
getVarInt x = fail $ "can't do that on 0 " ++ show x

getWord24le :: Get Word32
getWord24le = do
  b1 <- getWord8
  b2 <- getWord8
  b3 <- getWord8
  -- append extra 0 byte and read as Word32
  -- probably could be more efficient some other way
  return $ runGet getWord32le $ B.pack [b1, b2, b3, 0x00]

-- copied from zip-archive
--
-- > TIME bit     0 - 4           5 - 10          11 - 15
-- >      value   seconds*        minute          hour
-- >              *stored in two-second increments
-- > DATE bit     0 - 4           5 - 8           9 - 15
-- >      value   day (1 - 31)    month (1 - 12)  years from 1980
--
parseMsDosTime :: Word16 -> Word16 -> UTCTime
parseMsDosTime dosTime dosDate =
  let seconds = fromIntegral $ 2 * (dosTime .&. 0O37)
      minutes = fromIntegral $ (shiftR dosTime 5) .&. 0O77
      hour    = fromIntegral $ shiftR dosTime 11
      day     = fromIntegral $ dosDate .&. 0O37
      month   = fromIntegral $ (shiftR dosDate 5) .&. 0O17
      year    = fromIntegral $ 1980 + shiftR dosDate 9 -- dos epoch is 1980
  in UTCTime (fromGregorian year month day)
             (hour * 3600 + minutes * 60 + seconds)
