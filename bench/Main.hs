{-# LANGUAGE DataKinds #-}

{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-orphans #-}

import Control.DeepSeq (NFData (rnf))
import Criterion.Main
import Crypto.Hash (HashAlgorithm, SHA256)
import Crypto.Hash.CompactSparseMerkleTree
import Data.ByteArray (ByteArrayAccess)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Foldable (toList)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.String (IsString)
import Test.QuickCheck (Arbitrary (arbitrary), Gen)
import qualified Test.QuickCheck as QC

type BenchmarkCSMT = CSMT 'NonEmpty SHA256 Data

instance NFData a => NFData (CSMT i alg a) where
  rnf = \case
    Nil {} -> rnf ()
    Leaf {digest, value} ->
      rnf digest `seq` rnf value
    Parent {left, digest, maxDigest, right} ->
      rnf left `seq` rnf digest `seq` rnf maxDigest `seq` rnf right

newtype Data = Data ByteString
  deriving (IsString, Eq, Show, ByteArrayAccess, NFData)

instance Arbitrary Data where
  arbitrary = fmap (Data . BS.pack . ("data-" <>) . show . QC.getNonNegative) (QC.arbitrary :: QC.Gen (QC.NonNegative Integer))

instance Arbitrary (CSMT 'Empty alg a) where
  arbitrary = return empty

instance (Arbitrary a, ByteArrayAccess a, HashAlgorithm alg) => Arbitrary (CSMT 'NonEmpty alg a) where
  arbitrary = do
    arbitrary >>= \case
      QC.NonEmpty (x : xs) -> return $ fromList $ x :| xs
      _ -> error "impossible"

treeOfSize :: Integer -> Gen BenchmarkCSMT
treeOfSize 1 = return $ singleton "data-0"
treeOfSize n = do
  let x = Data $ BS.pack $ "data-" <> show (n - 1)
  insert x <$> treeOfSize (n - 1)

membershipTestOfSize :: Integer -> Gen (Data, BenchmarkCSMT)
membershipTestOfSize n = do
  t <- treeOfSize n
  x <- QC.oneof [elementIn t, elementNotIn t]
  return (x, t)

elementIn :: BenchmarkCSMT -> Gen Data
elementIn = QC.elements . toList

elementNotIn :: BenchmarkCSMT -> Gen Data
elementNotIn t = arbitrary `QC.suchThat` (`notMember` t)

main :: IO ()
main =
  defaultMain
    [ bgroup
        "CSMT"
        [ benchSizes
            (upTo 10000)
            "maximumDigest"
            (QC.generate . treeOfSize)
            $ nf maximumDigest,
          benchSizes
            (upTo 10000)
            "minimumDigest"
            (QC.generate . treeOfSize)
            $ nf minimumDigest,
          benchSizes
            (upTo 1000)
            "member"
            (QC.generate . membershipTestOfSize)
            $ \ ~(x, t) -> nf (member x) t,
          benchSizes
            (upTo 1000)
            "insert"
            (QC.generate . membershipTestOfSize)
            $ \ ~(x, t) -> nf (insert x) t
        ]
    ]

benchSizes :: (NFData t, Show a) => [a] -> String -> (a -> IO t) -> (t -> Benchmarkable) -> Benchmark
benchSizes ns name e b = bgroup name $
  flip map ns $ \n ->
    env (e n) $ \x ->
      bench (show n) $ b x

upTo :: Integral a => a -> [a]
upTo n = go [n]
  where
    go (x : xs) | x > 10 = go (x `div` 10 : x : xs)
    go xs = xs
