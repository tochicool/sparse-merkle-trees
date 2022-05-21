{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-orphans #-}

import Crypto.Hash (HashAlgorithm, SHA256)
import Crypto.Hash.CompactSparseMerkleTree
import Data.ByteArray (ByteArrayAccess)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Functor.Identity (Identity)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Maybe (isNothing)
import Data.String (IsString)
import Test.SmallCheck.Series (Serial (series), Series, cons0)
import qualified Test.SmallCheck.Series as SC
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck (Arbitrary, Gen)
import qualified Test.Tasty.QuickCheck as QC
import qualified Test.Tasty.SmallCheck as SC
import Prelude hiding (lookup)

newtype Data = Data ByteString
  deriving newtype (IsString, Eq, Show, ByteArrayAccess)

instance Monad m => Serial m Data where
  series = fmap (Data . BS.pack . ("data-" <>) . show) (series :: Series m (SC.NonNegative Integer))

instance Monad m => Serial m (CSMT 'Empty alg a) where
  series = cons0 Nil

instance (Monad m, Serial Identity a, ByteArrayAccess a, HashAlgorithm alg) => Serial m (CSMT 'NonEmpty alg a) where
  series = SC.generate $ \d -> do
    case SC.listSeries d of
      [] -> []
      (x : xs) -> scanl (flip insert) (singleton x) xs

instance Arbitrary Data where
  arbitrary = fmap (Data . BS.pack . ("data-" <>) . show . QC.getNonNegative) (QC.arbitrary :: Gen (QC.NonNegative Integer))

instance Arbitrary (CSMT 'Empty alg a) where
  arbitrary = return empty

instance (Arbitrary a, ByteArrayAccess a, HashAlgorithm alg) => Arbitrary (CSMT 'NonEmpty alg a) where
  arbitrary = do
    QC.arbitrary >>= \case
      QC.NonEmpty (x : xs) -> return $ fromList $ x :| xs
      _ -> error "impossible"

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests, properties]

properties :: TestTree
properties = testGroup "Properties" [scProps, qcProps]

scProps :: TestTree
scProps =
  testGroup
    "(checked by SmallCheck)"
    [ SC.testProperty "x `member` foldr insert (insert x xs) ys" $
        \(x :: Data, xs :: SC.NonEmpty Data, ys :: [Data]) ->
          x `member` foldr insert (insert x (scFromList xs :: UnderTest)) ys,
      SC.testProperty "x `member` xs ==> digest (singleton x) `lookup` xs = Just x" $
        \(x :: Data, xs :: UnderTest) ->
          x `member` xs SC.==> (digest (singleton x) `lookup` xs == Just x),
      SC.testProperty "x `notMember` delete x (foldr insert (insert x xs) ys)" $
        \(x :: Data, xs :: SC.NonEmpty Data, ys :: [Data]) ->
          delete x (foldr insert (insert x (scFromList xs :: UnderTest)) ys) (x `notMember`),
      SC.testProperty "x `notMember` xs ==> digest (singleton x) `lookup` xs = Nothing" $
        \(x :: Data, xs :: UnderTest) ->
          x `notMember` xs SC.==> isNothing (digest (singleton x) `lookup` xs),
      SC.testProperty "delete x (insert x empty) = empty" $
        \x ->
          ( delete x (insert x empty :: UnderTest) $ \case
              Nil {} -> True
              _ -> False
          ) ::
            Bool,
      SC.testProperty "delete x (insert x xs) = delete x xs" $
        \(x :: Data, ys :: SC.NonEmpty Data) ->
          let xs :: UnderTest = scFromList ys
           in ( delete x xs $ \case
                  Nil {} -> delete x (insert x xs) null
                  t@Leaf {} -> delete x (insert x xs) $ \case
                    t'@Leaf {} -> t == t'
                    _ -> False
                  t@Parent {} -> delete x (insert x xs) $ \case
                    t'@Parent {} -> t == t'
                    _ -> False
              ) ::
                Bool,
      SC.testProperty "validProof (merkleRoot xs) (membershipProof x xs)" $
        \(x :: Data, ys :: SC.NonEmpty Data) ->
          let xs :: UnderTest = scFromList ys
           in validProof (merkleRoot xs) (membershipProof x xs),
      SC.testProperty "valid (fromList xs)" $
        \xs -> valid (scFromList xs :: UnderTest)
    ]

qcProps :: TestTree
qcProps =
  testGroup
    "(checked by QuickCheck)"
    [ QC.testProperty "x `member` foldr insert (insert x xs) ys" $
        \(x :: Data, xs :: QC.NonEmptyList Data, ys :: [Data]) ->
          x `member` foldr insert (insert x (qcFromList xs :: UnderTest)) ys,
      QC.testProperty "x `member` xs ==> digest (singleton x) `lookup` xs = Just x" $
        \(x :: Data, xs :: UnderTest) ->
          x `member` xs QC.==> (digest (singleton x) `lookup` xs == Just x),
      QC.testProperty "x `notMember` delete x (foldr insert (insert x xs) ys)" $
        \(x :: Data, xs :: QC.NonEmptyList Data, ys :: [Data]) ->
          delete x (foldr insert (insert x (qcFromList xs :: UnderTest)) ys) (x `notMember`),
      QC.testProperty "x `notMember` xs ==> digest (singleton x) `lookup` xs = Nothing" $
        \(x :: Data, xs :: UnderTest) ->
          x `notMember` xs QC.==> isNothing (digest (singleton x) `lookup` xs),
      QC.testProperty "delete x (insert x empty) = empty" $
        \x ->
          ( delete x (insert x empty :: UnderTest) $ \case
              Nil {} -> True
              _ -> False
          ) ::
            Bool,
      QC.testProperty "delete x (insert x xs) = delete x xs" $
        \(x :: Data, ys :: QC.NonEmptyList Data) ->
          let xs :: UnderTest = qcFromList ys
           in ( delete x xs $ \case
                  Nil {} -> delete x (insert x xs) null
                  t@Leaf {} -> delete x (insert x xs) $ \case
                    t'@Leaf {} -> t == t'
                    _ -> False
                  t@Parent {} -> delete x (insert x xs) $ \case
                    t'@Parent {} -> t == t'
                    _ -> False
              ) ::
                Bool,
      QC.testProperty "validProof (merkleRoot xs) (membershipProof x xs)" $
        \(x :: Data, ys :: QC.NonEmptyList Data) ->
          let xs :: UnderTest = qcFromList ys
           in validProof (merkleRoot xs) (membershipProof x xs),
      QC.testProperty "valid (fromList xs)" $
        \xs -> valid (qcFromList xs :: UnderTest)
    ]

unitTests :: TestTree
unitTests =
  testGroup
    "Unit tests"
    [ testCase "Test" $
        let xs :: UnderTest = scFromList $ SC.NonEmpty ["data-1", "data-2"]
            x = "data-0"
         in validProof (merkleRoot xs) (membershipProof x xs) @?= True,
      testCase "Insert adds element" $
        (insert "a" $ insert "b" empty :: UnderTest) == insert "b" empty @?= False,
      testCase "Insert is order agnostic" $
        insert "a" (insert "b" (insert "c" empty :: UnderTest)) @?= insert "c" (insert "b" (insert "a" empty)),
      testCase "Empty tree has no member" $
        isExclusionProof (membershipProof "a" (empty :: EmptyUnderTest)) @?= True,
      testCase "Singleton tree has member" $
        isInclusionProof (membershipProof "a" (insert "a" empty :: UnderTest)) @?= True,
      testCase "Singleton tree has no other member" $
        isExclusionProof (membershipProof "b" (insert "a" empty :: UnderTest)) @?= True
    ]

type EmptyUnderTest = CSMT 'Empty SHA256 Data

type UnderTest = CSMT 'NonEmpty SHA256 Data

scFromList :: (ByteArrayAccess a, HashAlgorithm alg) => SC.NonEmpty a -> CompactSparseMerkleTree 'NonEmpty alg a
scFromList (SC.NonEmpty (x : xs)) = fromList (x :| xs)
scFromList _ = error "impossible"

qcFromList :: (ByteArrayAccess a, HashAlgorithm alg) => QC.NonEmptyList a -> CompactSparseMerkleTree 'NonEmpty alg a
qcFromList (QC.NonEmpty (x : xs)) = fromList (x :| xs)
qcFromList _ = error "impossible"
