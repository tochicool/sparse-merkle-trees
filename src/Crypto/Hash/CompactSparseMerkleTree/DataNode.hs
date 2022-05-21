module Crypto.Hash.CompactSparseMerkleTree.DataNode where
import Crypto.Hash (Digest)

data DataNode alg a
  = ExternalNode
      { digest :: Digest alg,
        value :: a
      }
  | InternalNode
      { digest :: Digest alg,
        maxDigest :: Digest alg
      }
  deriving (Show)
