{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeSynonymInstances #-}

-- |
-- Module      : Crypto.Hash.CompactSparseMerkleTree
-- Description : Compact sparse merkle trees
-- Copyright   : (c) Tochi Obudulu 2022
-- License     : BSD-3
-- Maintainer  : tochicool@gmail.com
-- Portability : portable
-- Stability   : experimental
--
--
-- = Compact Sparse Merkle Trees
--
-- The @'CompactSparseMerkleTree' i alg a@ type represents a merkle tree of size
-- @i@ containing elements of type @a@ authenticated with a secure cryptographic
-- hash function @alg@. This allows for the novel generation and verification of
-- memory efficient cryptographic zero-knowledge proofs of inclusion and
-- /exclusion/ of elements in the tree. Most operations require that @a@ be an
-- instance of the 'ByteArrayAccess' class and @alg@ be an instance of the
-- 'HashAlgorithm' class.
--
-- This module is intended to be imported qualified:
--
-- >  import Crypto.Hash.CompactSparseMerkleTree (CSMT)
-- >  import qualified Crypto.Hash.CompactSparseMerkleTree as CSMT
--
--
-- == Warning
--
-- The size of the tree obviously cannot exceed the size of the image of the
-- hash algorithm @2^(8 * hashDigestSize alg)@. The word length of the hash
-- digest for the algorithm must not exceed @maxBound :: Int@. Violation of
-- these limits are not detected and a breach implies undefined behaviour.
--
--
-- == Implementation
--
-- The implementation of 'CompactSparseMerkleTree' is based on /compact/ sparse
-- merkle trees as described by:
--
--    * Faraz Haider. "Compact sparse merkle trees.",
--      Cryptology ePrint Archive, October 2018,
--      <https://eprint.iacr.org/2018/955>.
--
-- Asymptotic bounds for the average case time complexity are given with the
-- assumption that the supplied hash function acts as a random oracle under the
-- random oracle model and that the compact sparse merkle tree is 'valid'. In
-- practice, the probability that the observed complexity differs from the
-- average case is vanishingly small.
--
-- Additionally, this implementation enforces /domain separation/ for the inputs
-- to the hash algorithm @alg@ to provide the proofs with resistance to second
-- preimage attacks. Inputs to hashes for leaf and parent nodes are prefixed
-- with the bytes @0x00@ and @0x01@ respectively before applying the hash
-- algorithm.
module Crypto.Hash.CompactSparseMerkleTree
  ( -- * CompactSparseMerkleTree Type
    CSMT,
    CompactSparseMerkleTree (..),
    Size (..),

    -- * Construction
    empty,
    singleton,
    fromList,

    -- * Insertion
    insert,

    -- * Deletion
    delete,

    -- * Query
    lookup,
    member,
    notMember,

    -- * Min\/Max
    minimumDigest,
    maximumDigest,

    -- * Proofs
    MembershipProof (..),
    Proof (..),
    Direction (..),
    ProofType (..),
    isInclusionProof,
    isExclusionProof,

    -- ** Proof construction
    membershipProof,
    hashLeaf,

    -- ** Proof verification
    MerkleRoot (..),
    merkleRoot,
    validProof,
    validInclusionProof,
    validExclusionProof,
    valid,

    -- * Debugging
    depth,
    toTree,
    drawTree,
  )
where

import Crypto.Hash (Digest, HashAlgorithm, hashFinalize, hashInit, hashUpdate, hashUpdates)
import Crypto.Hash.CompactSparseMerkleTree.DataNode (DataNode)
import qualified Crypto.Hash.CompactSparseMerkleTree.DataNode as DN
import Data.Bifunctor (first)
import Data.Bits (FiniteBits (countLeadingZeros))
import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Data.Foldable (foldl', toList)
import Data.Functor (void)
import Data.Functor.Classes (Eq1 (liftEq), Ord1 (liftCompare))
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Maybe (mapMaybe)
import Data.Ord (comparing)
import Data.Tree (Tree)
import qualified Data.Tree as Tree
import Prelude hiding (lookup)

-- | A compact sparse merkle tree of size @i@ with values @a@ authenticated over
-- the algorithm @alg@.
type CSMT = CompactSparseMerkleTree

-- | A compact sparse merkle tree of size @i@ with values @a@ authenticated over
-- the algorithm @alg@.
data CompactSparseMerkleTree (i :: Size) alg a where
  -- | The empty tree.
  Nil :: CSMT 'Empty alg a
  -- | A leaf node.
  Leaf ::
    { -- | The hash digest of the data element.
      digest :: Digest alg,
      -- | The data value.
      value :: a
    } ->
    CSMT 'NonEmpty alg a
  -- | A parent node.
  Parent ::
    { -- | The left non-empty subtree.
      left :: CSMT 'NonEmpty alg a,
      -- | The hash digest of the concatenation of the left and right subtree digests.
      digest :: Digest alg,
      -- | The maximum digest in the tree.
      maxDigest :: Digest alg,
      -- | The right non-empty subtree.
      right :: CSMT 'NonEmpty alg a
    } ->
    CSMT 'NonEmpty alg a

-- | The size of a compact sparse merkle tree.
data Size
  = -- | The empty tree
    Empty
  | -- | A non-empty tree
    NonEmpty

deriving instance (Show a) => Show (CSMT i alg a)

deriving instance Foldable (CSMT i alg)

deriving instance (Eq a) => Eq (CSMT i alg a)

deriving instance (Ord a) => Ord (CSMT i alg a)

instance Eq1 (CSMT i alg) where
  liftEq eq m n = liftEq eq (toList m) (toList n)

instance Ord1 (CSMT i alg) where
  liftCompare cmp m n = liftCompare cmp (toList m) (toList n)

-- | The empty tree.
--
-- Worst case Θ(1).
empty :: CSMT 'Empty alg a
empty = Nil

-- | Create a singleton tree.
--
-- Worst case Θ(1).
singleton :: (ByteArrayAccess a, HashAlgorithm alg) => a -> CSMT 'NonEmpty alg a
singleton x = singletonDigest (hashLeaf x) x

singletonDigest :: Digest alg -> a -> CSMT 'NonEmpty alg a
singletonDigest h x = Leaf {digest = h, value = x}

-- | Insert an element in a tree. If the tree already contains an element whose
-- hash is equal to the given value, it is replaced with the new value.
--
-- Average case Θ(log n), Worst case Θ(n) where n is the size of the tree.
insert :: (ByteArrayAccess a, HashAlgorithm alg) => a -> CSMT i alg a -> CSMT 'NonEmpty alg a
insert x = insertDigest (hashLeaf x) x

insertDigest :: (ByteArrayAccess a, HashAlgorithm alg) => Digest alg -> a -> CSMT i alg a -> CSMT 'NonEmpty alg a
insertDigest h x = \case
  Nil -> singletonDigest h x
  root@Leaf {} ->
    let newLeaf = singletonDigest h x
     in case h `compare` maximumDigest root of
          LT -> parent newLeaf root
          EQ -> singletonDigest h x
          GT -> parent root newLeaf
  root@Parent {left, right} ->
    case compareSubTrees h left right of
      EQ ->
        let newLeaf = singletonDigest h x
            minKey = min (maximumDigest left) (maximumDigest right)
         in case h `compare` minKey of
              LT -> parent newLeaf root
              __ -> parent root newLeaf
      LT -> parent (insertDigest h x left) right
      GT -> parent left (insertDigest h x right)

-- | Delete an element from a tree if such an element exists.
--
-- Average case Θ(log n), Worst case Θ(n) where n is the size of the tree.
delete :: (ByteArrayAccess a, HashAlgorithm alg) => a -> CSMT i alg a -> (forall j. CSMT j alg a -> b) -> b
delete x = deleteDigest (hashLeaf x)

deleteDigest :: HashAlgorithm alg => Digest alg -> CSMT i alg a -> (forall j. CSMT j alg a -> b) -> b
deleteDigest h root returnTree = case root of
  Nil {} -> returnTree root
  Leaf {digest}
    | h == digest -> returnTree empty
    | otherwise -> returnTree root
  Parent {left, right} ->
    case compareSubTrees h left right of
      EQ -> returnTree root
      LT -> deleteDigest h left $ \case
        Nil {} -> returnTree right
        left'@Leaf {} -> returnTree $ parent left' right
        left'@Parent {} -> returnTree $ parent left' right
      GT -> deleteDigest h right $ \case
        Nil {} -> returnTree left
        right'@Leaf {} -> returnTree $ parent left right'
        right'@Parent {} -> returnTree $ parent left right'

compareSubTrees :: Digest alg -> CSMT 'NonEmpty alg a -> CSMT 'NonEmpty alg a -> Ordering
compareSubTrees h = comparing (distance h . maximumDigest)

distance :: Digest alg -> Digest alg -> Int
distance a = logBase2 . BA.xor a
  where
    logBase2 x =
      8 * BS.length x - 1 - case span (== 0) (BS.unpack x) of
        (zeros, nonZeros) ->
          8 * length zeros + case nonZeros of
            [] -> 0
            (w : _) -> countLeadingZeros w

-- | The maximum digest in the tree.
--
-- Worst case Θ(1).
maximumDigest :: CSMT 'NonEmpty alg a -> Digest alg
maximumDigest Leaf {digest} = digest
maximumDigest Parent {maxDigest} = maxDigest

-- | The minimum digest in the tree.
--
-- Average case Θ(log n), Worst case Θ(n) where n is the size of the tree.
minimumDigest :: CSMT 'NonEmpty alg a -> Digest alg
minimumDigest = \case
  Leaf {digest} -> digest
  Parent {left} -> minimumDigest left

parent :: HashAlgorithm alg => CSMT 'NonEmpty alg a -> CSMT 'NonEmpty alg a -> CSMT 'NonEmpty alg a
parent left right =
  Parent
    { left,
      digest = hashParent (digest left) (digest right),
      maxDigest = max (maximumDigest left) (maximumDigest right),
      right
    }

hashLeaf :: (HashAlgorithm a, ByteArrayAccess ba) => ba -> Digest a
hashLeaf = hashFinalize . hashUpdate (hashUpdate hashInit (BS.singleton 0))

hashParent :: (HashAlgorithm a, ByteArrayAccess ba) => ba -> ba -> Digest a
hashParent x y = hashFinalize $ hashUpdates (hashUpdate hashInit (BS.singleton 1)) [x, y]

--------------------------------------------------------------------------------

-- | A membership proof over a hash algorithm @alg@.
data MembershipProof alg = forall p. MembershipProof (Proof Direction p alg)

-- | A proof of @p@ with direction @d@ over a hash algorithm @alg@.
data Proof d (p :: ProofType) alg where
  -- | A proof of inclusion.
  InclusionProof ::
    { -- | A digest of an included element.
      includedDigest :: Digest alg,
      -- | A list of sibling digests from the root to the included element with the directions from their parents.
      rootPath :: [(Digest alg, d)]
    } ->
    Proof d 'Inclusion alg
  -- | A proof of exclusion.
  ExclusionProof ::
    { -- | The digest of an excluded element.
      excludedDigest :: Digest alg,
      -- | A uni-directional inclusion proof from the left of the immediate predecessor to the included element, if one exists.
      immediatePredecessor :: Maybe (Proof () 'Inclusion alg),
      -- | A uni-directional inclusion proof from the right of the immediate successor to the included element, if one exists.
      immediateSuccessor :: Maybe (Proof () 'Inclusion alg),
      -- | A list of sibling digests from the root to the first common sibling of the immediate predecessor and successors with the directions from their parents.
      commonRootPath :: [(Digest alg, d)]
    } ->
    Proof d 'Exclusion alg

deriving instance Show d => Show (Proof d alg p)

-- | A direction of a node from its parent.
data Direction
  = -- | A left node
    L
  | -- | A right node
    R
  deriving (Show, Eq)

deriving instance Show (MembershipProof alg)

-- | A type of proof
data ProofType
  = -- | A proof that an element is in a tree.
    Inclusion
  | -- | A proof that an element is not in a tree.
    Exclusion

-- | Is the element in the tree?
--
-- Average case Θ(log n), Worst case Θ(n) where n is the size of the tree.
member :: (ByteArrayAccess a, HashAlgorithm alg) => a -> CSMT i alg a -> Bool
member x = isInclusionProof . membershipProof x

-- | Is the element not in the tree?
--
-- Average case Θ(log n), Worst case Θ(n) where n is the size of the tree.
notMember :: (ByteArrayAccess a, HashAlgorithm alg) => a -> CSMT i alg a -> Bool
notMember x = not . member x

-- | Lookup the value with the digest in the map.
--
-- Average case Θ(log n), Worst case Θ(n) where n is the size of the tree.
lookup :: Digest alg -> CSMT i alg a -> Maybe a
lookup h = \case
  Nil {} -> Nothing
  Leaf {digest, value}
    | h == digest -> Just value
    | otherwise -> Nothing
  Parent {left, right} ->
    case compareSubTrees h left right of
      EQ -> Nothing
      LT -> lookup h left
      GT -> lookup h right

-- | Is this an inclusion proof?
--
-- Worst case Θ(1).
isInclusionProof :: MembershipProof alg -> Bool
isInclusionProof = \case
  MembershipProof (InclusionProof {}) -> True
  _ -> False

-- | Is this an exclusion proof?
--
-- Worst case Θ(1).
isExclusionProof :: MembershipProof alg -> Bool
isExclusionProof = not . isInclusionProof

-- | Construct a membership proof of inclusion if the given element is in the
-- tree, or a proof of exclusion if the element is not in the tree.
--
-- Average case Θ(log n), Worst case Θ(n) where n is the size of the tree.
-- The constructed membership proof has equivalent space complexity.
membershipProof :: (ByteArrayAccess a, HashAlgorithm alg) => a -> CSMT i alg a -> MembershipProof alg
membershipProof x = membershipProofDigest [] (hashLeaf x)

membershipProofDigest :: [(CSMT 'NonEmpty alg a, Direction)] -> Digest alg -> CSMT i alg a -> MembershipProof alg
membershipProofDigest path h = \case
  Nil {} ->
    MembershipProof $ trivialExclusionProof h
  leaf@Leaf {digest} -> case h `compare` digest of
    EQ ->
      MembershipProof (trivialInclusionProof digest) {rootPath = toRootPath path}
    __ -> nonMembershipProof path h leaf
  root@Parent {left, right} ->
    case compareSubTrees h left right of
      EQ -> case h `compare` maximumDigest root of
        LT -> nonMembershipProof ((right, R) : path) h left
        __ -> nonMembershipProof ((left, L) : path) h right
      LT -> membershipProofDigest ((right, R) : path) h left
      GT -> membershipProofDigest ((left, L) : path) h right

nonMembershipProof :: [(CSMT 'NonEmpty alg a, Direction)] -> Digest alg -> CSMT 'NonEmpty alg a -> MembershipProof alg
nonMembershipProof path h t =
  let exclusionProof = trivialExclusionProof h
   in case h `compare` maximumDigest t of
        LT ->
          case spanDirection R path of
            (successorPath, []) ->
              MembershipProof $
                exclusionProof
                  { immediateSuccessor = Just $ minimumDigestInclusionProof' successorPath t
                  }
            (successorPath, (sibling, _) : commonPath) ->
              MembershipProof $
                exclusionProof
                  { immediateSuccessor = Just $ minimumDigestInclusionProof' successorPath t,
                    immediatePredecessor = Just $ maximumDigestInclusionProof sibling,
                    commonRootPath = toRootPath commonPath
                  }
        __ ->
          case spanDirection L path of
            (predecessorPath, []) ->
              MembershipProof $
                exclusionProof
                  { immediatePredecessor = Just $ maximumDigestInclusionProof' predecessorPath t
                  }
            (predecessorPath, (sibling, _) : commonPath) ->
              MembershipProof $
                exclusionProof
                  { immediatePredecessor = Just $ maximumDigestInclusionProof' predecessorPath t,
                    immediateSuccessor = Just $ minimumDigestInclusionProof sibling,
                    commonRootPath = toRootPath commonPath
                  }

spanDirection :: Eq d => d -> [(CSMT 'NonEmpty alg a, d)] -> ([(Digest alg, ())], [(CSMT 'NonEmpty alg a, d)])
spanDirection d = first toUniRootPath . span ((d ==) . snd)

toUniRootPath :: [(CSMT 'NonEmpty alg a, d)] -> [(Digest alg, ())]
toUniRootPath = fmap void . toRootPath

toRootPath :: [(CSMT 'NonEmpty alg a, d)] -> [(Digest alg, d)]
toRootPath = fmap (first digest)

trivialInclusionProof :: Digest alg -> Proof d 'Inclusion alg
trivialInclusionProof h =
  InclusionProof
    { includedDigest = h,
      rootPath = mempty
    }

trivialExclusionProof :: Digest alg -> Proof d 'Exclusion alg
trivialExclusionProof h =
  ExclusionProof
    { excludedDigest = h,
      commonRootPath = [],
      immediatePredecessor = Nothing,
      immediateSuccessor = Nothing
    }

maximumDigestInclusionProof :: CSMT 'NonEmpty alg a -> Proof () 'Inclusion alg
maximumDigestInclusionProof = maximumDigestInclusionProof' []

maximumDigestInclusionProof' :: [(Digest alg, ())] -> CSMT 'NonEmpty alg a -> Proof () 'Inclusion alg
maximumDigestInclusionProof' path = \case
  Leaf {digest} -> (trivialInclusionProof digest) {rootPath = path}
  Parent {left, right} -> maximumDigestInclusionProof' ((digest left, ()) : path) right

minimumDigestInclusionProof :: CSMT 'NonEmpty alg a -> Proof () 'Inclusion alg
minimumDigestInclusionProof = minimumDigestInclusionProof' []

minimumDigestInclusionProof' :: [(Digest alg, ())] -> CSMT 'NonEmpty alg a -> Proof () 'Inclusion alg
minimumDigestInclusionProof' path = \case
  Leaf {digest} -> (trivialInclusionProof digest) {rootPath = path}
  Parent {left, right} -> minimumDigestInclusionProof' ((digest right, ()) : path) left

--------------------------------------------------------------------------------

-- | A merkle root of a tree.
data MerkleRoot alg
  = -- | A merkle root of an empty tree.
    EmptyMerkleRoot
  | -- | A merkle root of a non-empty tree.
    MerkleRoot (Digest alg)
  deriving (Show, Eq)

-- | The merkle root of a tree.
--
-- Worst case Θ(1).
merkleRoot :: CSMT i alg a -> MerkleRoot alg
merkleRoot = \case
  Nil {} -> EmptyMerkleRoot
  Leaf {digest} -> MerkleRoot digest
  Parent {digest} -> MerkleRoot digest

-- | Validate a membership proof against a merkle root.
--
-- Worst case Θ(d) where d is the number of hash digests in the membership proof.
validProof :: HashAlgorithm alg => MerkleRoot alg -> MembershipProof alg -> Bool
validProof root = \case
  MembershipProof proof@InclusionProof {} -> validInclusionProof root proof
  MembershipProof proof@ExclusionProof {} -> validExclusionProof root proof

-- | Validate an inclusion proof against a merkle root.
--
-- Worst case Θ(d) where d is the number of hash digests in the inclusion proof.
validInclusionProof :: HashAlgorithm alg => MerkleRoot alg -> Proof Direction 'Inclusion alg -> Bool
validInclusionProof EmptyMerkleRoot _ = False
validInclusionProof (MerkleRoot root) proof = root == inclusionProofMerkleRoot proof

inclusionProofMerkleRoot :: HashAlgorithm alg => Proof Direction 'Inclusion alg -> Digest alg
inclusionProofMerkleRoot InclusionProof {includedDigest, rootPath} =
  foldl'
    ( \result (siblingDigest, direction) -> uncurry hashParent $
        case direction of
          L -> (siblingDigest, result)
          R -> (result, siblingDigest)
    )
    includedDigest
    rootPath

-- | Validate an exclusion proof against a merkle root.
--
-- Worst case Θ(d) where d is the number of hash digests in the exclusion proof.
validExclusionProof :: HashAlgorithm alg => MerkleRoot alg -> Proof Direction 'Exclusion alg -> Bool
validExclusionProof root = \case
  ExclusionProof {immediatePredecessor = Nothing, immediateSuccessor = Nothing} ->
    root == EmptyMerkleRoot
  ExclusionProof {immediatePredecessor = Just p, excludedDigest, immediateSuccessor = Nothing}
    | includedDigest p < excludedDigest ->
      validInclusionProof root $ mapProofDirection (const L) p
  ExclusionProof {immediatePredecessor = Nothing, excludedDigest, immediateSuccessor = Just q}
    | excludedDigest < includedDigest q ->
      validInclusionProof root $ mapProofDirection (const R) q
  ExclusionProof {immediatePredecessor = Just p, commonRootPath, excludedDigest, immediateSuccessor = Just q}
    | includedDigest p < excludedDigest,
      excludedDigest < includedDigest q ->
      let leftMerkleRoot = inclusionProofMerkleRoot $ mapProofDirection (const L) p
          rightMerkleRoot = inclusionProofMerkleRoot $ mapProofDirection (const R) q
          includedDigest = hashParent leftMerkleRoot rightMerkleRoot
       in validInclusionProof root $
            InclusionProof
              { includedDigest,
                rootPath = commonRootPath
              }
  _ -> False

mapProofDirection :: (d -> d') -> Proof d 'Inclusion alg -> Proof d' 'Inclusion alg
mapProofDirection f proof@InclusionProof {rootPath} = proof {rootPath = fmap (fmap f) rootPath}

-- | Validate a tree against the properties of a compact sparse merkle tree. Namely that:
--
-- * the maximum leaf digests for all subtrees are valid
-- * the leaf hash digests are valid
-- * and all leafs lie on its /minimum distance path/ from the root.
--
-- All exported functions maintain these properties.
--
-- Average case Θ(n*log n), Worst case Θ(n²) where n is the size of the tree.
valid :: (ByteArrayAccess a, HashAlgorithm alg) => CSMT i alg a -> Bool
valid = valid' (const True)
  where
    valid' :: (ByteArrayAccess a, HashAlgorithm alg) => (Digest alg -> Bool) -> CSMT i alg a -> Bool
    valid' validPath = \case
      Nil {} -> True
      Leaf {digest, value} -> hashLeaf value == digest && validPath digest
      Parent {left, digest = parentDigest, maxDigest, right} ->
        maximumDigest left <= maxDigest
          && maximumDigest right <= maxDigest
          && parentDigest == hashParent (digest left) (digest right)
          && valid' (\h -> compareSubTrees h left right == LT && validPath h) left
          && valid' (\h -> compareSubTrees h left right == GT && validPath h) right

-- | Create a tree from a list of elements.
--
-- Average case Θ(n*log n), Worst case Θ(n²) where n is the size of the tree.
fromList :: (ByteArrayAccess a, HashAlgorithm alg) => NonEmpty a -> CSMT 'NonEmpty alg a
fromList = \case
  (x :| []) -> singleton x
  (x :| y : ys) -> insert x $ fromList (y :| ys)

--------------------------------------------------------------------------------

-- | The depth of a tree.
--
-- Average case Θ(n), Worst case Θ(n) where n is the size of the tree.
depth :: (Num n, Ord n) => CSMT i alg a -> n
depth = \case
  Nil -> 0
  Leaf {} -> 1
  Parent {left, right} -> 1 + max (depth left) (depth right)

-- | Convert a tree to a rose tree with non-recursive nodes as elements.
-- Used for debugging purposes.
--
-- Average case Θ(n), Worst case Θ(n) where n is the size of the tree.
toTree :: CSMT i alg a -> Maybe (Tree (DataNode alg a))
toTree = \case
  Nil -> Nothing
  Leaf {digest, value} ->
    Just $
      Tree.Node
        ( DN.ExternalNode
            { digest,
              value
            }
        )
        []
  Parent {left, digest, maxDigest, right} ->
    Just $
      Tree.Node
        ( DN.InternalNode
            { digest,
              maxDigest
            }
        )
        $ mapMaybe toTree [left, right]

-- | 2-dimensional ASCII drawing of the tree.
-- Used for debugging purposes.
--
-- Average case Θ(n²), Worst case Θ(n²) where n is the size of the tree.
drawTree :: Show a => CSMT i alg a -> String
drawTree = maybe "" (Tree.drawTree . fmap show) . toTree
