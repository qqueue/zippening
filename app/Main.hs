module Main where

import Lib
import qualified Data.ByteString.Lazy as B
import Data.Binary.Get
import Data.Aeson

main :: IO ()
main = B.interact $
  encode . (map entryMetadata) . rarEntries . (runGet getRarArchive)
  
