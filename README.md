# sparse-merkle-trees

[![CI/CD](https://github.com/tochicool/sparse-merkle-trees/actions/workflows/cicd.yaml/badge.svg)](https://github.com/tochicool/sparse-merkle-trees/actions/workflows/cicd.yaml)
[![Hackage](https://img.shields.io/hackage/v/sparse-merkle-trees)](https://hackage.haskell.org/package/sparse-merkle-trees)
[![BSD3](https://img.shields.io/github/license/tochicool/sparse-merkle-trees)](https://github.com/tochicool/sparse-merkle-trees/blob/master/LICENSE)

A Haskell library implementing sparse Merkle trees, an authenticated data 
structure with support for zero-knowledge proofs of *inclusion and exclusion*, 
parametrised over cryptographic hash algorithms at the type level.


> **Note**: This library is currently experimental and is subject to change.

## Introduction

A [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) is an authenticated 
data structure which supports efficient zero-knowledge proofs of element 
inclusion from a Merkle root.

A sparse Merkle tree (SMT) is Merkle Tree where all possible keys (digests) are 
at the leaves of the tree. This gives us the additional properties over a Merkle 
tree:

* support for proofs of *exclusion* of elements from a Merkle root
* *history independence* of the merkle root from element insertion order

A naive construction would mean that a N-bit key would yield a SMT of size 
2^N. However, because the tree is *sparse*, there are efficient constructions
that grow in size O(n) where n is the size of the tree.

### Use cases

SMTs expand on the existing use cases of Merkle trees including:

* Asset universes
* Certificate revocation
* Secure file systems
* Secure messaging

## Examples

### Compact Sparse Merkle Trees

The compact sparse Merkle tree is based on the description given in this 
[report](https://eprint.iacr.org/2018/955.pdf) by 
[Faraz Haider](https://github.com/farazhaider). The module exposes an similar 
API to [`Data.Set`](https://hackage.haskell.org/package/containers-0.6.5.1/docs/Data-Set.html) but this is subject to change.

```haskell
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

import Crypto.Hash (SHA256) -- from cryptonite package
import Crypto.Hash.CompactSparseMerkleTree (CSMT, MembershipProof, MerkleRoot, Size (NonEmpty))
import qualified Crypto.Hash.CompactSparseMerkleTree as CSMT
import Data.ByteString (ByteString) -- from bytestring package

type MailingList = CSMT 'NonEmpty SHA256 ByteString

cypherPunks :: MailingList
cypherPunks =
  CSMT.insert "hal@finney.org" $
    CSMT.insert "satoshi@vistomail.com" $
      CSMT.insert "aba@dcs.ex.ac.uk" $
        CSMT.insert "szabo@techbook.com" $
          CSMT.insert "weidai@eskimo.com" $
            CSMT.empty

summary :: MerkleRoot SHA256
summary = CSMT.merkleRoot cypherPunks

-- >>> summary
-- MerkleRoot b7061997fc49294bfb5c8893a684eea53d20f11d152530fbb95b3fc5ca902d2a

nakamotoProof :: MembershipProof SHA256
nakamotoProof = CSMT.membershipProof "satoshi@vistomail.com" cypherPunks

-- >>> nakamotoProof
-- MembershipProof (InclusionProof {includedDigest = 4a2220676a74d2be6d0c00d939513a3b5599bd01c65cf3d1ce2d517f070a1c11, rootPath = [(5554c052244897a83ef61362e6a3141c034284b54f4977163070d634749a714c,R),(6c98a4128b8a86d5f646707d860a869244938b95177298c6746da5e1e981426e,R),(e1a4e69d03cd197af06688aafb33d50db1d7c407be747b4b9d46c877f2e97fa1,R)]})

szaboTechbookProof :: MembershipProof SHA256
szaboTechbookProof = CSMT.membershipProof "szabo@techbook.com" cypherPunks

-- >>> szaboTechbookProof
-- MembershipProof (InclusionProof {includedDigest = 5554c052244897a83ef61362e6a3141c034284b54f4977163070d634749a714c, rootPath = [(4a2220676a74d2be6d0c00d939513a3b5599bd01c65cf3d1ce2d517f070a1c11,L),(6c98a4128b8a86d5f646707d860a869244938b95177298c6746da5e1e981426e,R),(e1a4e69d03cd197af06688aafb33d50db1d7c407be747b4b9d46c877f2e97fa1,R)]})

szaboNetcomProof :: MembershipProof SHA256
szaboNetcomProof = CSMT.membershipProof "szabo@netcom.com" cypherPunks

-- >>> szaboNetcomProof
-- MembershipProof (ExclusionProof {excludedDigest = 8f3af01ec764fa90a9bb98b1547656e362640fc336cf31c80b7dfacb50f2d256, immediatePredecessor = Just (InclusionProof {includedDigest = 6c98a4128b8a86d5f646707d860a869244938b95177298c6746da5e1e981426e, rootPath = [(0fa34cea30d143cb5bbfd6937e3848c8faf4d0737b88b55fbcb0f2afac94e6b3,())]}), immediateSuccessor = Just (InclusionProof {includedDigest = 949802fb7f855457ede853818031b82bc5f446c7369f7abe6fa9e564dde18e96, rootPath = [(dc2baa959e086c741627d36a0804a302590b11e44590936621e81acd4a528de4,())]}), commonRootPath = []})

cypherPunks' :: MailingList
cypherPunks' = CSMT.delete "szabo@techbook.com" (CSMT.insert "szabo@netcom.com" cypherPunks) $ \case
  t@CSMT.Parent {} -> t
  _ -> error "impossible"

summary' :: MerkleRoot SHA256
summary' = CSMT.merkleRoot cypherPunks'

-- >>> summary'
-- MerkleRoot 7dc6b4dfcd54f9c6ac67a330b35539407c2e9559d7e589e6064f1c8a46256aa7

szaboTechbookProof' :: MembershipProof SHA256
szaboTechbookProof' = CSMT.membershipProof "szabo@techbook.com" cypherPunks'

-- >>> szaboTechbookProof'
-- MembershipProof (ExclusionProof {excludedDigest = 5554c052244897a83ef61362e6a3141c034284b54f4977163070d634749a714c, immediatePredecessor = Just (InclusionProof {includedDigest = 4a2220676a74d2be6d0c00d939513a3b5599bd01c65cf3d1ce2d517f070a1c11, rootPath = []}), immediateSuccessor = Just (InclusionProof {includedDigest = 6c98a4128b8a86d5f646707d860a869244938b95177298c6746da5e1e981426e, rootPath = []}), commonRootPath = [(b8804f3bbe10963f35ee72dbd55a8aa33b64260ab0c63bff59acc13ea8088e56,R)]})

szaboNetcomProof' :: MembershipProof SHA256
szaboNetcomProof' = CSMT.membershipProof "szabo@netcom.com" cypherPunks'

-- >>> szaboNetcomProof
-- MembershipProof (ExclusionProof {excludedDigest = 8f3af01ec764fa90a9bb98b1547656e362640fc336cf31c80b7dfacb50f2d256, immediatePredecessor = Just (InclusionProof {includedDigest = 6c98a4128b8a86d5f646707d860a869244938b95177298c6746da5e1e981426e, rootPath = [(0fa34cea30d143cb5bbfd6937e3848c8faf4d0737b88b55fbcb0f2afac94e6b3,())]}), immediateSuccessor = Just (InclusionProof {includedDigest = 949802fb7f855457ede853818031b82bc5f446c7369f7abe6fa9e564dde18e96, rootPath = [(dc2baa959e086c741627d36a0804a302590b11e44590936621e81acd4a528de4,())]}), commonRootPath = []})

-- >>> all (CSMT.validProof summary) [nakamotoProof, szaboTechbookProof, szaboNetcomProof]
-- True
-- >>> all (CSMT.validProof summary') [szaboTechbookProof', szaboNetcomProof']
-- True
-- >>> CSMT.validProof summary' nakamotoProof
-- False
```
See the more complete haddock documentation on [Hackage](https://hackage.haskell.org/package/sparse-merkle-trees).

## Related libraries

* [cryptonite](https://hackage.haskell.org/package/cryptonite) for cryptographic primitives
* [merkle-tree](https://hackage.haskell.org/package/merkle-tree) for an implementation of a merkle tree
