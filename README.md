# Inugami 🩸

## BloodOath (Deposit)
User sends Diesel tokens along with a message and specified amount as an oath payment for including the message in the coinbase transaction scriptSig. The contract checks incoming transfers, holds the specified amount of Diesel for this message, updates the total accumulated value in storage (by a key generated from the message) and returns confirmation. This is like placing a "bounty" or reward for a message.

## SigilTrove (Balance Query)
Returns the current accumulated amount of Diesel for a given message.

## BindSigil (Claim)
To retrieve accumulated tokens, you need to specify offset and length in protostone that will tell the contract where the message begins and how many characters it occupies in the coinbase scriptSig of the current block. The contract extracts message bytes from coinbase, checks if there are accumulated tokens for it, and if so - transfers them to the caller, clearing the storage. This incentivizes miners to include specific messages in coinbase so that the miner themselves can "claim" them in the same block.