# Vcash Pool Merged Mining Protocol Documentation

This document describes the current Merged Mining protocol implemented in Vcash.

## Table of Contents

1. [WHAT DO YOU NEED TO DO](#what-do-you-need-to-do)
2. [POOL API](#pool-api)
    1. [GET Mining Job Info](#get-mining-job-info)
    1. [POST Mining Block](#post-mining-block)

## WHAT DO YOU NEED TO DO

In order to proof work has been achieved on bitcoin blockchain, you should put vcash header hash in bitcoin's coinbase as a commitment, the complete steps are as follow:
1. Get Vcash job info from vcash node. Job info includes vcash header hash, bits for bitcoin and some other information, for detail: [GET Mining Job Info](#get-mining-job-info). 
2. Put vcash header hash in bitcoin coinbase transaction when you construct a new bitcoin block, the format are as follow:

    OP_RETURN(0x6a) + Length(0x24) + MagicNum(0xb9e11b6d) + Vcash Header Hash

    here is a example for a vcash header hash "c2415983cf8f63e705e8368f295590e0b88d69b33a17e0c0149f4d4458f1cd5c":
    "6a24b9e11b6dc2415983cf8f63e705e8368f295590e0b88d69b33a17e0c0149f4d4458f1cd5c"
    
3. Mining a bitcoin block until its work is enough for the bits in Vcash job info.
4. Submit the bitcoin block info to Vcash node, see the [POST Mining Block](#post-mining-block).

## POOL API

### GET Mining Job Info

Get mining job info for current height

* **URL**

  /v1/pool/getauxblock

* **Method:**

  `GET`
  
* **URL Params**

  None

* **Data Params**

  None

* **Success Response:**

  * **Code:** 200
  * **Content:**

    | Field            | Type     | Description                         |
    |:-----------------|:---------|:------------------------------------|
    | height           | number   | vcash height           |
    | cur_hash         | string   | vcash header hash      |
    | prev_hash        | string   | vcash prev header hash |
    | bits             | number   | bits for bitcoin       |
    | base_rewards     | number   | vcash coinbase subsidy |
    | transactions_fee | number   | vcash transaction fee  |
    

* **Error Response:**

  * **Code:** 400


### POST Mining Block

Submit a bitcoin solution for vcash

* **URL**

  /v1/pool/submitauxblock

* **Method:**

  `POST`
  
* **URL Params**

  None

* **Data Params**

    | Field                 | Type     | Description            |
    |:----------------------|:---------|:-----------------------|
    | header_hash           | string   | vcash header hash      |
    | btc_header            | string   | bitcoin header hash    |
    | btc_coinbase          | string   | bitcoin coinbase       |
    | btc_merkle_branch     | string   | bitcoin merkle branch  |


* **Success Response:**

  * **Code:** 200

* **Error Response:**

  * **Code:** 400
