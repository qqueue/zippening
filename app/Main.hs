module Main where

import Lib
import qualified Data.ByteString.Lazy as B
import Data.Binary.Get

main :: IO ()
main = do
  input <- B.getContents
  let rar = runGet getRarArchive input 
  print rar
  
