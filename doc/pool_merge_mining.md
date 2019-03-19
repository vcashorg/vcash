# Vcash Pool Merge Mining API Documentation

This document describes the current Merge Mining API Documentation implemented in Vcash.

## Table of Contents

1. [POOL API](#pool-api)
    1. [GET Mining Job Info](#get-mining-job-info)
    1. [POST Mining Block](#post-mining-block)

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
    | prev_hash        | string   | vcash header hash      |
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
