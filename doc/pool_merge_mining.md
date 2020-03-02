# VCash Pool Merged Mining Protocol Documentation

This document describes the current Merged Mining protocol implemented in VCash.

## Table of Contents

1. [WHAT DO YOU NEED TO DO](#what-do-you-need-to-do)
2. [POOL API](#pool-api)
    1. [GET Mining Job Info](#get-mining-job-info)
    1. [GET Masked Mining Job Info](#get-masked-mining-job-info)
    1. [POST Mining Block](#post-mining-block)

## WHAT DO YOU NEED TO DO

### Version 1 Job Info
In order to proof work has been achieved on Bitcoin block chain, you should put VCash header hash in Bitcoin's coinbase as a commitment, the complete steps are as follow:
1. Get VCash job info from VCash node. Job info includes VCash header hash, bits for Bitcoin and some other information, for detail: [GET Mining Job Info](#get-mining-job-info). 
2. Put VCash header hash in Bitcoin coinbase transaction when you construct a new Bitcoin block, the format are as follow:

    OP_RETURN(0x6a) + Length(0x24) + MagicNum(0xb9e11b6d) + VCash Header Hash

    here is a example for a VCash header hash "c2415983cf8f63e705e8368f295590e0b88d69b33a17e0c0149f4d4458f1cd5c":
    ```
        "6a24b9e11b6dc2415983cf8f63e705e8368f295590e0b88d69b33a17e0c0149f4d4458f1cd5c"
    ```
    
3. When accept a valid share from Miner, check whether the following condition is satisfied. If so, means it's a valid solution.

    ```
        DSHA256(bitcoin_header) <= bitsToHash(vcash_network_bits)
    ```
    
4. Submit the Bitcoin block info to VCash node, see the [POST Mining Block](#post-mining-block).

### Version 2 Job Info
To support Solve Block Withholding Attack feature(for detail:[Solve Block Withholding Attack](solve_block_withholding_attack/solve_block_withholding_attack.md)), 
we got new version API for merge mining, ie:[GET Masked Mining Job Info](#get-masked-mining-job-info). If you want to open this new feature, steps are as follow:
1. Get new version VCash job info from VCash node. New version job info now includes miner_base_bits and mask_hash pair, 
also some other necessary information. for detail:[GET Masked Mining Job Info](#get-masked-mining-job-info). 

2. Put VCash header hash in Bitcoin coinbase transaction when you construct a new Bitcoin block, the format are as follow:

    OP_RETURN(0x6a) + Length(0x24) + MagicNum(0xb9e11b6d) + VCash Header Hash

    here is a example for a VCash header hash "c2415983cf8f63e705e8368f295590e0b88d69b33a17e0c0149f4d4458f1cd5c":
    ```
        "6a24b9e11b6dc2415983cf8f63e705e8368f295590e0b88d69b33a17e0c0149f4d4458f1cd5c"
    ```
    
3. When accept a valid share from Miner, find corresponding mask_hash for the share, and then check whether the following condition is satisfied.

    ```
        DSHA256(bitcoin_header) ^ mask_hash <= bitsToHash(vcash_network_bits)
    ```
    
4. Submit the Bitcoin block info to VCash node, see the [POST Mining Block](#post-mining-block).

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
    | height           | number   | VCash height           |
    | cur_hash         | string   | VCash header hash      |
    | prev_hash        | string   | VCash prev header hash |
    | bits             | number   | bits for Bitcoin       |
    | base_rewards     | number   | VCash coinbase subsidy |
    | transactions_fee | number   | VCash transaction fee  |
    

* **Error Response:**

  * **Code:** 400

* **Sample Call:**

  ```javascript
    $.ajax({
      url: "/v1/pool/getauxblock",
      dataType: "json",
      type : "GET",
      success : function(r) {
        console.log(r);
      }
    });
  ```
  
  * **Sample Result:**
  ```
    {
        "height": 1,
        "cur_hash": "baa60c424d2471c45a01a7b1fb9f399105415172818eb7ee938a3e74f8a459ba",
        "prev_hash": "569ed9e4a5463896190447e6ffe37c394c4d77ce470aa29ad762e0286b896832",
        "bits": 553713663,
        "base_rewards": 50000000000,
        "transactions_fee": 0
    }
  ``` 

### GET Masked Mining Job Info

Get masked mining job info for current height, masked mining job info can solve block withholding attack. `minerbits` is bits for Bitcoin miner share difficulty.

* **URL**

  * /v1/pool/getauxblockv2?minerbits==x
  * /v1/pool/getauxblockv2?minerbits==x,y,z

* **Method:**

  `GET`
  
* **URL Params**

    **Required:**
    `minerbits=[string]`

* **Data Params**

  None

* **Success Response:**

  * **Code:** 200
  * **Content:**

    | Field            | Type     | Description                                |
    |:-----------------|:---------|:-------------------------------------------|
    | height           | number   | VCash height                               |
    | prev_hash        | string   | VCash prev header hash                     |
    | bits             | number   | bits for Bitcoin                           |
    | base_rewards     | number   | VCash coinbase subsidy                     |
    | transactions_fee | number   | VCash transaction fee                      |
    | miner_info       | object   | Miner Info for a giving Bitcoin miner bits |
    | miner_base_bits  | number   | bits for Bitcoin miner share difficulty    |
    | cur_hash         | string   | VCash header hash for miner_base_bits      |
    | mask             | string   | Random mask hash for miner_base_bits       |
    

* **Error Response:**

  * **Code:** 400

* **Sample Call:**

  ```javascript
    $.ajax({
      url: "/v1/pool/getauxblockv2?minerbits=457179072&minerbits=437256176&minerbits=419692540&minerbits=436591499",
      dataType: "json",
      type : "GET",
      success : function(r) {
        console.log(r);
      }
    });
  ```
  
  * **Sample Result:**
  ```
  {
    "height": 219,
    "prev_hash": "eb0f58ee20ee88b9a74b41086aa0a4619f45cd5046a5e62b3c41fe83e75b9aef",
    "bits": 553713663,
    "base_rewards": 50000000000,
    "transactions_fee": 0,
    "miner_info": [
      {
        "cur_hash": "6c0d3ac003f6c470204c3568c4dd36eacd1ae5246b8a0091b3ef2110b20f8463",
        "miner_base_bits": 457179072,
        "mask": "da478173dc4328761885ebe92d836b2980abbbad031062ff42aa000000000000"
      },
      {
        "cur_hash": "a90ba31960808affb0281d7124c789cfede8a2d22d2e257a7818dcecbbe5ff0b",
        "miner_base_bits": 437256176,
        "mask": "8d82a5ea7a82deb218a0121f89f04627965223eb7e1f8fb95f00000000000000"
      },
      {
        "cur_hash": "4bb63cec226c09b425e77ef2bbd2f863ee203cc82ff334adbee9a644a6515ccf",
        "miner_base_bits": 419692540,
        "mask": "c91174f6efaca813dad45ee296810fa634fb1c4a854d82090000000000000000"
      },
      {
        "cur_hash": "65eb80d6de3e9acf9977355cb1c48d20d8639c700b9b52ebcf2290e7d4e04fd8",
        "miner_base_bits": 436591499,
        "mask": "58470a06ff5fd49fab9b463ee57e24a00ae58bc4f72333c3e500000000000000"
      }
    ]
  }
  ``` 

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
