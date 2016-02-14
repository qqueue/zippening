{-# LANGUAGE OverloadedStrings #-}
module Main where

import Lib
import qualified Data.ByteString.Lazy as B
import System.Environment (getArgs)
import Data.Binary.Get
import Data.Aeson

main :: IO ()
main = do
  (filePath:_) <- getArgs
  input <- B.readFile filePath
  let rar = runGet (label ("reading: " ++ filePath) getRarArchive) input
  let meta = (map entryMetadata) $ rarEntries rar
  B.putStr $ encode $ object 
    [ "entries" .= meta
    , "file" .= filePath
    ]
  
